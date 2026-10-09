/** Verifies live host-facts presentation and disabled-plugin lifecycle boundaries (D126/D198). */
import { expect, test } from "bun:test";
import { ActionRefused, type MuxConnection } from "../../connection";
import type { WinRec } from "../context";
import { createLiveDetails } from "./details-live.on-demand";

test("a refused host facts action stops its recurring timer", async () => {
  const originalWindow = Object.getOwnPropertyDescriptor(globalThis, "window");
  const timers = new Map<number, () => void>();
  let nextTimer = 1;
  Object.defineProperty(globalThis, "window", { configurable: true, value: {
    setTimeout(callback: () => void): number {
      const id = nextTimer++;
      timers.set(id, callback);
      return id;
    },
    clearTimeout(id: number): void { timers.delete(id); },
  } });
  let stop = (): void => {};
  let calls = 0;
  try {
    // Model the actual Result(ok=false) emitted for a disabled or build-removed plugin.
    const connection = {
      isWelcomed: true,
      call: async (): Promise<Record<string, unknown>> => {
        calls++;
        throw new ActionRefused(undefined, "action unavailable");
      },
    } as unknown as MuxConnection;
    const source = createLiveDetails({ host: { name: "local" }, connection, roundTrip: () => undefined });
    const rec = { model: { id: "window-1", kind: "terminal", host: "local" } } as unknown as WinRec;
    stop = source.open!(rec, () => {});
    // Flush the read's rejected call and finally block without advancing a real clock.
    await Promise.resolve();
    await Promise.resolve();
    expect(calls).toBe(1);
    expect(timers.size).toBe(0);
  } finally {
    stop();
    if (originalWindow) Object.defineProperty(globalThis, "window", originalWindow);
    else Reflect.deleteProperty(globalThis, "window");
  }
});

// A valid read must feed the existing operating-system mark, as well as the System row (D126).
test("a detected operating system supplies the live popover mark", async () => {
  const originalWindow = Object.getOwnPropertyDescriptor(globalThis, "window");
  const originalLocation = Object.getOwnPropertyDescriptor(globalThis, "location");
  Object.defineProperty(globalThis, "window", { configurable: true, value: {
    setTimeout: (): number => 1, clearTimeout: (): void => {},
  } });
  Object.defineProperty(globalThis, "location", { configurable: true, value: { hostname: "example.invalid", protocol: "https:" } });
  let stop = (): void => {};
  try {
    const connection = {
      isWelcomed: true, isOpen: true,
      call: async (): Promise<Record<string, unknown>> => ({
        os: "Debian GNU/Linux", version: "13", kernel: "6.12", architecture: "x86_64",
        logicalCpus: 8, executionUid: 1000, mode: "embedded", engines: [],
      }),
    } as unknown as MuxConnection;
    const source = createLiveDetails({ host: { name: "build-01" }, connection, roundTrip: () => undefined });
    const rec = { model: { id: "window-1", kind: "terminal", host: "build-01" } } as unknown as WinRec;
    stop = source.open!(rec, () => {});
    await Promise.resolve();
    await Promise.resolve();
    const facts = source.facts(rec)!;
    // Establish that the response decoded and became visible before checking its header metadata.
    expect(facts.sections[0]!.rows.find((row) => row.key === "System")?.value).toBe("Debian GNU/Linux 13");
    expect(facts.os).toBe("debian");
  } finally {
    stop();
    if (originalWindow) Object.defineProperty(globalThis, "window", originalWindow);
    else Reflect.deleteProperty(globalThis, "window");
    if (originalLocation) Object.defineProperty(globalThis, "location", originalLocation);
    else Reflect.deleteProperty(globalThis, "location");
  }
});
