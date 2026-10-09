/** Verifies that unavailable host-facts plugins leave no recurring browser work (D198). */
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
