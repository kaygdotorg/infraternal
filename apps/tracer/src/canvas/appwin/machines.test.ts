/** The machine list asks only for windows; icons are fetched once per hash, and an arriving icon repaints the list (#146). */
import { expect, test } from "bun:test";
import type { HostEntry } from "../sessions/adapter";
import type { StreamConnection } from "./adapter";
import { Machines } from "./machines";

/** The online Mac fixture shared by the inventory refresh scenarios. */
const host = { id: "mac", name: "Mac", os: "apple", online: true } as HostEntry;
/** One tiny real PNG and its content hash. */
const PNG_B64 = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+/0xAAAAAASUVORK5CYII=";

test("polls carry only the host; an icon hash is fetched once and its arrival notifies the list", async () => {
  const png = Uint8Array.from(atob(PNG_B64), (c) => c.charCodeAt(0));
  const hash = Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256", png)), (b) => b.toString(16).padStart(2, "0")).join("");
  const row = { window_id: 7, owner_pid: 42, app_name: "Editor", title: "main.ts", bundle_id: "org.example.editor", app_version: "1.0", layer: 0, frame: [0, 0, 800, 600], on_screen: true, icon: hash };
  const calls: Array<{ action: string; body: Record<string, unknown> }> = [];
  const connection = {
    isWelcomed: true,
    call(action: string, body: Record<string, unknown>) {
      calls.push({ action, body });
      return Promise.resolve(action === "desktop.icon" ? { png: PNG_B64 } : { windows: [row] });
    },
    /** The inventory test starts after the connection has already welcomed the browser. */
    onWelcome() { return () => undefined; },
  } as unknown as StreamConnection;
  const priorWindow = Object.getOwnPropertyDescriptor(globalThis, "window");
  Object.defineProperty(globalThis, "window", { value: globalThis, configurable: true });
  try {
    const machines = new Machines(connection, () => [host]);
    let changes = 0;
    machines.onChange(() => { changes++; });
    await machines.refresh(host);
    await machines.refresh(host);
    expect(calls.map((call) => call.body)).toEqual([{ host_id: "mac" }, { host_id: "mac" }]);
    expect(machines.state("mac")?.inventory?.windows[0]?.iconHash).toBe(hash);
    const before = changes;
    await machines.icons.load("mac", hash);
    await machines.icons.load("mac", hash);
    expect(calls.filter((call) => call.action === "desktop.icon")).toEqual([{ action: "desktop.icon", body: { host_id: "mac", sha256: hash } }]);
    expect(changes).toBe(before + 1);
    machines.dispose();
  } finally {
    if (priorWindow) Object.defineProperty(globalThis, "window", priorWindow);
    else Reflect.deleteProperty(globalThis, "window");
  }
});
