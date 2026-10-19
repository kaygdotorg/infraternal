/** Exercises fragmented mode-2026 recognition and the bounded hold state. */
import { describe, expect, test } from "bun:test";
import { SynchronizedOutput, type SynchronizedOutputScheduler } from "./synchronized-output";

/** Runs timers and animation frames explicitly so release ordering is exact and repeatable. */
class FakeClockAndFrames implements SynchronizedOutputScheduler {
  private now = 0;
  private nextTimer = 1;
  private nextFrame = 1;
  private readonly timers = new Map<number, { at: number; callback: () => void }>();
  private readonly frames = new Map<number, () => void>();
  frameNumber = 0;

  setTimeout(callback: () => void, delayMs: number): number {
    const id = this.nextTimer++;
    this.timers.set(id, { at: this.now + delayMs, callback });
    return id;
  }

  clearTimeout(timer: unknown): void {
    if (typeof timer === "number") this.timers.delete(timer);
  }

  requestAnimationFrame(callback: () => void): number {
    const id = this.nextFrame++;
    this.frames.set(id, callback);
    return id;
  }

  cancelAnimationFrame(frame: number): void {
    this.frames.delete(frame);
  }

  advanceBy(milliseconds: number): void {
    const target = this.now + milliseconds;
    for (;;) {
      const next = [...this.timers.entries()].sort((left, right) => left[1].at - right[1].at)[0];
      if (!next || next[1].at > target) break;
      this.timers.delete(next[0]);
      this.now = next[1].at;
      next[1].callback();
    }
    this.now = target;
  }

  frame(): void {
    this.now += 1000 / 60;
    this.frameNumber += 1;
    const callbacks = [...this.frames.values()];
    this.frames.clear();
    for (const callback of callbacks) callback();
  }
}

describe("synchronized terminal output", () => {
  test("recognizes a private mode split across byte and string writes", () => {
    const scheduler = new FakeClockAndFrames();
    const output = new SynchronizedOutput(() => undefined, () => undefined, 150, scheduler);
    output.feed("before\u001b[?20");
    expect(output.holdsPaint).toBe(false);
    output.feed(new TextEncoder().encode("26;25hbody"));
    expect(output.holdsPaint).toBe(true);
    expect(output.requiresAtomicPaint).toBe(true);
    output.feed("\u001b[?25l");
    expect(output.holdsPaint).toBe(true);
    output.feed("\u001b[?25;2026l");
    expect(output.holdsPaint).toBe(false);
    expect(output.requiresAtomicPaint).toBe(true);
    output.finishAtomicPaint();
    expect(output.requiresAtomicPaint).toBe(false);
    scheduler.frame();
    output.dispose();
  });

  test("preserves mode transitions for every pair of input chunk boundaries", () => {
    const enable = "\u001b[?2026h";
    const body = "frame";
    const reset = "\u001b[?2026l";
    const sample = `${enable}${body}${reset}`;
    const enabledThrough = enable.length + body.length;

    for (let firstBoundary = 0; firstBoundary <= sample.length; firstBoundary += 1) {
      for (let secondBoundary = firstBoundary; secondBoundary <= sample.length; secondBoundary += 1) {
        const scheduler = new FakeClockAndFrames();
        const output = new SynchronizedOutput(() => undefined, () => undefined, 10_000, scheduler);
        let offset = 0;
        for (const chunk of [sample.slice(0, firstBoundary), sample.slice(firstBoundary, secondBoundary), sample.slice(secondBoundary)]) {
          output.feed(chunk);
          offset += chunk.length;
          expect(output.holdsPaint).toBe(offset >= enable.length && offset < enabledThrough + reset.length);
        }
        expect(output.requiresAtomicPaint).toBe(true);
        output.finishAtomicPaint();
        expect(output.requiresAtomicPaint).toBe(false);
        output.dispose();
      }
    }
  });

  test("ignores CSI-looking bytes inside control strings and other mode numbers", () => {
    const output = new SynchronizedOutput(() => undefined, () => undefined, 150, new FakeClockAndFrames());
    output.feed("\u001b]title \u001b[?2026h\u0007");
    output.feed("\u001bPdata\u001b[?2026h\u001b\\");
    output.feed("\u001b[?2025h\u001b[2026h");
    expect(output.holdsPaint).toBe(false);
    output.dispose();
  });

  test("RIS clears an active mode", () => {
    const scheduler = new FakeClockAndFrames();
    const output = new SynchronizedOutput(() => undefined, () => undefined, 150, scheduler);
    output.feed("\u001b[?2026h");
    expect(output.holdsPaint).toBe(true);
    output.feed("\u001bc");
    expect(output.holdsPaint).toBe(false);
    scheduler.frame();
    output.dispose();
  });

  test("bounds an unfinished control sequence", () => {
    const output = new SynchronizedOutput(() => undefined, () => undefined, 150, new FakeClockAndFrames());
    output.feed(`\u001b[?2026${"0".repeat(4100)}h`);
    expect(output.holdsPaint).toBe(false);
    output.dispose();
  });

  test("paints queued output on the first frame after reset and timeout release", () => {
    for (const release of ["reset", "timeout"] as const) {
      const scheduler = new FakeClockAndFrames();
      let queued = "";
      let applied = "";
      let painted: { frame: number; text: string } | undefined;
      const output = new SynchronizedOutput(
        () => { applied += queued; queued = ""; },
        () => { painted = { frame: scheduler.frameNumber, text: applied }; },
        150,
        scheduler,
      );
      const frame = "\u001b[?2026hframe-body";
      queued += frame;
      output.feed(frame);
      expect(output.holdsPaint).toBe(true);
      expect(applied).toBe("");

      if (release === "reset") {
        queued += "\u001b[?2026l";
        output.feed("\u001b[?2026l");
        // acceptOutput drains after the scanner has examined the entire message.
        applied += queued;
        queued = "";
      } else {
        scheduler.advanceBy(149);
        expect(output.holdsPaint).toBe(true);
        expect(applied).toBe("");
        scheduler.advanceBy(1);
      }

      expect(output.holdsPaint).toBe(false);
      expect(applied).toContain("frame-body");
      expect(painted).toBeUndefined();
      expect(scheduler.frameNumber).toBe(0);
      scheduler.frame();
      expect(painted).toEqual({ frame: 1, text: applied });
      expect(scheduler.frameNumber).toBe(1);
      output.dispose();
    }
  });
});
