/** Exercises fragmented mode-2026 recognition and the bounded hold state. */
import { describe, expect, test } from "bun:test";
import { SynchronizedOutput } from "./synchronized-output";

describe("synchronized terminal output", () => {
  test("recognizes a private mode split across byte and string writes", () => {
    const output = new SynchronizedOutput(() => undefined);
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
    output.dispose();
  });

  test("ignores CSI-looking bytes inside control strings and other mode numbers", () => {
    const output = new SynchronizedOutput(() => undefined);
    output.feed("\u001b]title \u001b[?2026h\u0007");
    output.feed("\u001bPdata\u001b[?2026h\u001b\\");
    output.feed("\u001b[?2025h\u001b[2026h");
    expect(output.holdsPaint).toBe(false);
    output.dispose();
  });

  test("RIS clears an active mode", () => {
    const output = new SynchronizedOutput(() => undefined);
    output.feed("\u001b[?2026h");
    expect(output.holdsPaint).toBe(true);
    output.feed("\u001bc");
    expect(output.holdsPaint).toBe(false);
    output.dispose();
  });

  test("bounds an unfinished control sequence", () => {
    const output = new SynchronizedOutput(() => undefined);
    output.feed(`\u001b[?2026${"0".repeat(4100)}h`);
    expect(output.holdsPaint).toBe(false);
    output.dispose();
  });

  test("releases an unmatched mode after its configured timeout", async () => {
    let released = 0;
    const output = new SynchronizedOutput(() => { released += 1; }, 10);
    output.feed("\u001b[?2026hpartial");
    expect(output.holdsPaint).toBe(true);
    await new Promise((resolve) => setTimeout(resolve, 30));
    expect(output.holdsPaint).toBe(false);
    expect(output.requiresAtomicPaint).toBe(true);
    expect(released).toBe(1);
    output.feed("\u001b[?2026l");
    expect(output.holdsPaint).toBe(false);
    output.dispose();
  });
});
