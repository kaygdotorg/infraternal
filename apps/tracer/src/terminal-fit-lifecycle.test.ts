/** A queued fit must not read a renderer that a shared-layout update retired before the next frame (#243). */
import { expect, test } from "bun:test";
import { TerminalClient } from "./terminal";
for (const state of ["closed", "suspended", "frozen"] as const) test(`a queued fit stops when the terminal becomes ${state}`, () => {
  const originalFrame = globalThis.requestAnimationFrame, originalStyle = globalThis.getComputedStyle;
  let frame: FrameRequestCallback | undefined, reads = 0;
  globalThis.requestAnimationFrame = (callback) => { frame = callback; return 1; };
  globalThis.getComputedStyle = (() => ({ paddingLeft: "0", paddingRight: "0", paddingTop: "0", paddingBottom: "0" })) as unknown as typeof getComputedStyle;
  const terminal = Object.create(TerminalClient.prototype) as { scheduleFit(): void; fitQueued: boolean; closed: boolean; suspended: boolean; frozen: boolean; config: { host: { clientWidth: number; clientHeight: number } }; cellMetrics(): never };
  Object.assign(terminal, { fitQueued: false, closed: false, suspended: false, frozen: false, config: { host: { clientWidth: 800, clientHeight: 600 } }, cellMetrics() { reads++; throw Error("retired renderer was read"); } });
  try {
    terminal.scheduleFit(); terminal[state] = true;
    expect(frame).toBeDefined(); expect(() => frame?.(0)).not.toThrow(); expect(reads).toBe(0);
  } finally { if (originalFrame) globalThis.requestAnimationFrame = originalFrame; else Reflect.deleteProperty(globalThis, "requestAnimationFrame"); if (originalStyle) globalThis.getComputedStyle = originalStyle; else Reflect.deleteProperty(globalThis, "getComputedStyle"); }
});
