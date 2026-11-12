/**
 * The resume probe's sampling rules (#478): one forced drop is one sample. The report never shows the previous drop's
 * time while a resume is running, and a second drop cannot start until the first one's marker echo is painted.
 */
import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { PerformanceProbe } from "./perf-probe.on-demand";
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
const realKeyboardEvent = globalThis.KeyboardEvent;
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
  const keydownListeners: Array<(event: { key: string; preventDefault(): void }) => void> = [];
  Object.assign(globalThis, {
    window: {
      setTimeout: (run: () => void, ms: number) => { const id = nextTimer++; timers.push({ at: now + ms, run, id }); return id; },
      clearTimeout: (id: number) => { timers = timers.filter((timer) => timer.id !== id); },
    },
    document: {
      addEventListener: (type: string, listener: (event: { key: string; preventDefault(): void }) => void) => { if (type === "keydown") keydownListeners.push(listener); },
      removeEventListener: () => undefined,
      dispatchEvent: (event: { key: string; preventDefault(): void }) => { for (const listener of keydownListeners) listener(event); return true; },
    },
    KeyboardEvent: class {
      readonly key: string;
      constructor(_type: string, init: { key: string }) { this.key = init.key; }
      preventDefault(): void {}
    },
  });
  globalThis.performance.now = () => now;
});

afterEach(() => {
  Object.assign(globalThis, { window: realWindow, document: realDocument, KeyboardEvent: realKeyboardEvent });
  globalThis.performance.now = realNow;
});

/** A probe on a fake panel bound to a fake connected terminal that records the keys it is given and its drops. */
function setup(initialCount = 20) {
  const controls = new Map<string, FakeControl>();
  const panel = { querySelector: (selector: string) => controls.get(selector) ?? controls.set(selector, new FakeControl()).get(selector) };
  const probe = new PerformanceProbe(panel as unknown as HTMLElement, initialCount);
  const terminal = { isConnected: true, inputSequence: 0n, drops: 0, typed: [] as string[], forceDrop() { this.drops += 1; }, injectInput(key: string) { this.typed.push(key); } };
  probe.bind(terminal as unknown as TerminalClient);
  const hooks = probe.hooks();
  const drop = controls.get("#probe-drop")!;
  const results = controls.get("#probe-results")!;
  const message = controls.get("#probe-message")!;
  /** Resumes the link and paints the marker's echo `rtt` later, as one reconnect does. */
  const resume = (rtt: number) => {
    hooks.onAttached?.(true, terminal as unknown as TerminalClient);
    advance(rtt);
    hooks.onPaintedOutput?.(new TextEncoder().encode(terminal.typed.at(-1)!), now, 0n);
  };
  const quiet = () => { hooks.onPaintedOutput?.(new Uint8Array(), now, 0n); advance(150); };
  return { probe, terminal, hooks, drop, run: controls.get("#probe-run")!, results, message, resume, quiet };
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
    expect(terminal.typed).toHaveLength(2);
    // Linked and quiet, but the marker is still in flight: no second drop may land inside this sample.
    quiet();
    expect(drop.disabled).toBe(true);
    drop.click();
    expect(terminal.drops).toBe(2);
    advance(300);
    hooks.onPaintedOutput?.(new TextEncoder().encode(terminal.typed.at(-1)!), now, 0n);
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
    expect(results.textContent).toContain("FAIL");

    terminal.injectInput = (key: string) => { terminal.typed.push(key); };
    drop.click();
    hooks.onDisconnected?.(true);
    advance(500);
    resume(300);
    expect(results.textContent).toContain("Time to resume: 800.00 ms");
    expect(results.textContent).toContain("FAIL");
  });

  test("missing attachment records FAIL and releases the measurement lock", () => {
    const { terminal, hooks, drop, run, results, quiet } = setup();
    quiet();
    drop.click();
    terminal.isConnected = false;
    hooks.onDisconnected?.(true);
    advance(120_000);
    expect(results.textContent).toContain("FAIL");
    expect(results.textContent).toContain("attachment");
    terminal.isConnected = true;
    hooks.onAttached?.(true, terminal as unknown as TerminalClient);
    quiet();
    expect(run.disabled).toBe(false);
    expect(drop.disabled).toBe(false);
    expect(terminal.typed).toHaveLength(0);
    expect(timers).toHaveLength(0);
  });

  test("missing echo records FAIL, releases both controls and rejects an expired marker", () => {
    const { terminal, hooks, drop, run, results, quiet } = setup();
    quiet();
    drop.click();
    hooks.onDisconnected?.(true);
    advance(600);
    hooks.onAttached?.(true, terminal as unknown as TerminalClient);
    const expiredMarker = terminal.typed.at(-1)!;
    advance(119_400);
    expect(results.textContent).toContain("FAIL");
    expect(results.textContent).toContain("echo");
    expect(run.disabled).toBe(false);
    expect(drop.disabled).toBe(false);
    expect(timers).toHaveLength(0);
    drop.click();
    hooks.onDisconnected?.(true);
    advance(600);
    hooks.onAttached?.(true, terminal as unknown as TerminalClient);
    const currentMarker = terminal.typed.at(-1)!;
    hooks.onPaintedOutput?.(new TextEncoder().encode(expiredMarker), now, 0n);
    expect(results.textContent).not.toMatch(/Time to resume: [0-9.]+ ms/);
    advance(300);
    // A marker may span separate painted output callbacks.
    hooks.onPaintedOutput?.(new TextEncoder().encode(currentMarker.slice(0, 2)), now, 0n);
    hooks.onPaintedOutput?.(new TextEncoder().encode(currentMarker.slice(2)), now, 0n);
    expect(results.textContent).toContain("Time to resume: 900.00 ms");
    expect(results.textContent).toContain("FAIL");
    advance(120_000);
    expect(results.textContent).toContain("Resume samples: 1 FAIL");
  });

  test("a slow successful sample keeps its full duration and prevents a second reconnect", () => {
    const { terminal, hooks, drop, results, resume, quiet } = setup();
    quiet();
    drop.click();
    hooks.onDisconnected?.(true);
    advance(60_000);
    drop.click();
    expect(terminal.drops).toBe(1);
    resume(300);
    expect(results.textContent).toBe("Time to resume: 60300.00 ms");
    advance(120_000);
    expect(results.textContent).not.toContain("FAIL");
  });

  test("disposing a pending measurement cancels its deadline", () => {
    const { probe, drop, quiet } = setup();
    quiet();
    drop.click();
    probe.dispose();
    expect(timers).toHaveLength(0);
  });

});

describe("PerformanceProbe key samples", () => {
  test("cycles through adjacent probe keys that are absent from the yes flood", () => {
    const { probe, terminal, hooks, run, quiet } = setup(200);
    const encoder = new TextEncoder();
    const sent: string[] = [];
    quiet();
    run.click();

    for (let index = 0; index < 200; index += 1) {
      const key = terminal.typed.at(-1)!;
      expect("yes !").not.toContain(key);
      expect(key).not.toBe(sent.at(-1));
      sent.push(key);
      hooks.onPaintedOutput?.(encoder.encode(key), now, BigInt(index));
      advance(0);
    }
    expect(sent).toHaveLength(200);
    probe.dispose();
  });

  test("keeps a 200-key latency run open long enough for the 300 ms profile", () => {
    const { probe, run, results, quiet } = setup(200);
    quiet();
    run.click();
    advance(15_000);
    expect(results.textContent).toBe("Painted 0 / 200");
    probe.dispose();
  });

  test("keeps a slow 200-key paint profile alive for its full collection window", () => {
    const { probe, run, results, message, quiet } = setup(200);
    quiet();
    run.click();

    advance(140_001);
    expect(results.textContent).toBe("Painted 0 / 200");

    advance(579_998);
    expect(message.textContent).toBe("Sending synthetic keys. They are not followed by Enter.");
    advance(1);
    expect(message.textContent).toBe("Timed out after 0 of 200 painted echoes.");
    probe.dispose();
  });

  test("advances once per painted key while unrelated output keeps arriving", () => {
    const { probe, terminal, hooks, run, quiet } = setup(3);
    const encoder = new TextEncoder();
    quiet();
    run.click();
    expect(terminal.typed).toEqual(["a"]);

    hooks.onPaintedOutput?.(encoder.encode("a"), now, 1n);
    hooks.onPaintedOutput?.(encoder.encode("!"), now, 2n);
    advance(0);

    expect(terminal.typed).toEqual(["a", "b"]);
    probe.dispose();
  });

  test("does not count a flood's `yes` output as the pending key echo", () => {
    const { probe, terminal, hooks, run, results, quiet } = setup(25);
    const encoder = new TextEncoder();
    quiet();
    run.click();

    for (let index = 0; index < 24; index += 1) {
      hooks.onPaintedOutput?.(encoder.encode(terminal.typed.at(-1)!), now, BigInt(index));
      advance(0);
    }
    expect(terminal.typed.every((key) => !"yes !".includes(key))).toBe(true);

    hooks.onPaintedOutput?.(encoder.encode("yes !"), now, 0n);
    expect(results.textContent).toBe("Painted 24 / 25");
    probe.dispose();
  });

  test("does not count a key byte inside a terminal control string as a painted echo", () => {
    const { probe, terminal, hooks, run, results, quiet } = setup(2);
    const encoder = new TextEncoder();
    quiet();
    run.click();
    expect(terminal.typed.at(-1)).toBe("a");

    // A window-title update is not visible terminal text, even when it contains the pending key.
    hooks.onPaintedOutput?.(encoder.encode("\x1b]0;"), now, 0n);
    hooks.onPaintedOutput?.(encoder.encode("a"), now, 1n);
    hooks.onPaintedOutput?.(encoder.encode("\x07"), now, 2n);
    expect(results.textContent).toBe("Painted 0 / 2");

    // A real cell update still completes the sample after the control sequence ends.
    hooks.onPaintedOutput?.(encoder.encode("\x1b[1;1Ha"), now, 3n);
    expect(results.textContent).toBe("Painted 1 / 2");
    advance(0);
    expect(terminal.typed.at(-1)).toBe("b");
    hooks.onPaintedOutput?.(encoder.encode("\x1b]0;"), now, 4n, "output");
    hooks.onPaintedOutput?.(encoder.encode("\x1b[1;1Hb"), now, 5n, "snapshot");
    expect(results.textContent).toContain("Painted echoes: 2 / 2");
    probe.dispose();
  });
});
