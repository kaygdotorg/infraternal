/**
 * The resume probe's sampling rules (#478): one forced drop is one sample. The report never shows the previous drop's
 * time while a resume is running, and a second drop cannot start until the first one's marker echo is painted.
 */
import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { PerformanceProbe } from "./perf-probe";
import type { TerminalClient } from "./terminal";

/** A stand-in for one panel control: just the fields the probe reads and writes, plus a way to click it. */
class FakeControl {
  disabled = false;
  textContent = "";
  value = "";
  private readonly clicks: Array<() => void> = [];
  /** Records a click listener; the probe registers nothing else on its controls. */
  addEventListener(type: string, listener: () => void): void { if (type === "click") this.clicks.push(listener); }
  /** Clicks like a person would: a disabled control ignores it. */
  click(): void { if (!this.disabled) for (const listener of this.clicks) listener(); }
}

/** The real globals, put back after each test. */
const realWindow = globalThis.window;
/** See `realWindow`. */
const realDocument = globalThis.document;
/** See `realWindow`. */
const realNow = globalThis.performance.now.bind(globalThis.performance);
/** The fake clock, in milliseconds; `performance.now()` returns it during a test. */
let now = 0;
/** Pending fake timers, run in time order by `advance`. */
let timers: Array<{ at: number; run: () => void; id: number }> = [];
/** The id the next fake timer gets. */
let nextTimer = 1;

/** Runs every timer due by `ms` from now, in order, advancing the fake clock. */
function advance(ms: number): void {
  const until = now + ms;
  for (;;) {
    timers.sort((left, right) => left.at - right.at);
    const due = timers[0];
    if (!due || due.at > until) break;
    timers.shift();
    now = due.at;
    due.run();
  }
  now = until;
}

beforeEach(() => {
  now = 0;
  timers = [];
  Object.assign(globalThis, {
    window: {
      setTimeout: (run: () => void, ms: number) => { const id = nextTimer++; timers.push({ at: now + ms, run, id }); return id; },
      clearTimeout: (id: number) => { timers = timers.filter((timer) => timer.id !== id); },
    },
    document: { addEventListener: () => undefined, removeEventListener: () => undefined },
  });
  globalThis.performance.now = () => now;
});

afterEach(() => {
  Object.assign(globalThis, { window: realWindow, document: realDocument });
  globalThis.performance.now = realNow;
});

/** A probe on a fake panel bound to a fake connected terminal that records the keys it is given and its drops. */
function setup() {
  const controls = new Map<string, FakeControl>();
  const panel = { querySelector: (selector: string) => controls.get(selector) ?? controls.set(selector, new FakeControl()).get(selector) };
  const probe = new PerformanceProbe(panel as unknown as HTMLElement, 20);
  const terminal = { isConnected: true, drops: 0, typed: [] as string[], forceDrop() { this.drops += 1; }, injectInput(key: string) { this.typed.push(key); } };
  probe.bind(terminal as unknown as TerminalClient);
  const hooks = probe.hooks();
  const drop = controls.get("#probe-drop")!;
  const results = controls.get("#probe-results")!;
  /** Resumes the link and paints the marker's echo `rtt` later, as one reconnect does. */
  const resume = (rtt: number) => {
    hooks.onAttached?.(true, terminal as unknown as TerminalClient);
    advance(rtt);
    hooks.onPaintedOutput?.(new TextEncoder().encode("~"), now, 0n);
  };
  const quiet = () => { hooks.onPaintedOutput?.(new Uint8Array(), now, 0n); advance(150); };
  return { terminal, hooks, drop, results, resume, quiet };
}

describe("PerformanceProbe forced drops", () => {
  test("a drop clears the shown time and locks the drop button until its own marker echo is painted", () => {
    const { terminal, hooks, drop, results, resume, quiet } = setup();
    quiet();
    drop.click();
    hooks.onDisconnected?.(true);
    advance(600);
    resume(300);
    expect(results.textContent).toBe("Time to resume: 900.00 ms");

    quiet();
    expect(drop.disabled).toBe(false);
    drop.click();
    expect(terminal.drops).toBe(2);
    // The previous number is gone at once: a reader polling for "Time to resume: <n> ms" now waits for this drop.
    expect(results.textContent).not.toContain("Time to resume");
    hooks.onDisconnected?.(true);
    advance(600);
    hooks.onAttached?.(true, terminal as unknown as TerminalClient);
    expect(terminal.typed).toEqual(["~", "~"]);
    // Linked and quiet, but the marker is still in flight: no second drop may land inside this sample.
    quiet();
    expect(drop.disabled).toBe(true);
    drop.click();
    expect(terminal.drops).toBe(2);
    advance(300);
    hooks.onPaintedOutput?.(new TextEncoder().encode("~"), now, 0n);
    expect(results.textContent).toBe("Time to resume: 1050.00 ms");
  });

  test("a marker the terminal refuses frees the button and cannot end a later sample", () => {
    const { terminal, hooks, drop, results, resume, quiet } = setup();
    terminal.injectInput = () => { throw new Error("not attached"); };
    quiet();
    drop.click();
    hooks.onDisconnected?.(true);
    advance(600);
    hooks.onAttached?.(true, terminal as unknown as TerminalClient);
    quiet();
    expect(drop.disabled).toBe(false);

    terminal.injectInput = (key: string) => { terminal.typed.push(key); };
    drop.click();
    hooks.onDisconnected?.(true);
    advance(500);
    resume(300);
    expect(results.textContent).toBe("Time to resume: 800.00 ms");
  });
});
