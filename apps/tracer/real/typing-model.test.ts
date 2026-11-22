/** Rules of the realistic-typing model (#569, D375): the traces, the human rhythm and how a line is scored. */
import { describe, expect, test } from "bun:test";
import { humanGaps, paintAfterMessage, percentile, scoreRepetition, TRACES } from "./typing-model";

describe("typing traces", () => {
  test("are J1079's four lines: plain and one Backspace correction, in each shell", () => {
    expect(TRACES.map((trace) => trace.name)).toEqual(["bash-plain", "bash-backspace", "zsh-plain", "zsh-backspace"]);
    expect(TRACES[0]?.keys.join("")).toBe("echo hello world");
    expect(TRACES[1]?.keys.filter((key) => key === "Backspace")).toHaveLength(1);
  });
});

describe("humanGaps", () => {
  test("repeat for the same seed, differ between seeds, and keep keys overlapping at a 300 ms round trip", () => {
    const first = humanGaps(16, 7);
    expect(humanGaps(16, 7)).toEqual(first);
    expect(humanGaps(16, 8)).not.toEqual(first);
    expect(first[0]).toBe(0);
    expect(Math.min(...first.slice(1))).toBeGreaterThanOrEqual(45);
    const mean = first.slice(1).reduce((sum, gap) => sum + gap, 0) / 15;
    // Overlap: on average more than one key is sent per round trip.
    expect(300 / mean).toBeGreaterThan(1.5);
  });
});

describe("scoreRepetition", () => {
  const key = (letter: string, keydownAt: number, echoPaintedAt?: number) => ({ key: letter, keydownAt, predictedAt: undefined, echoPaintedAt });

  test("a correctly predicted key is felt at the frame that showed it, ahead of its echo", () => {
    const scored = scoreRepetition(
      [key("e", 0, 300), key("c", 100, 400)],
      [{ at: 8, glyphs: [{ text: "e", column: 2 }] }, { at: 110, glyphs: [{ text: "e", column: 2 }, { text: "c", column: 3 }] }],
      2,
    );
    expect(scored.felt).toEqual([8, 10]);
    expect(scored.predictedFirst).toEqual([true, true]);
    expect(scored.wrongCells).toBe(0);
  });

  test("a letter drawn one cell short is counted wrong and is not felt until the host's echo", () => {
    const scored = scoreRepetition(
      [key("e", 0, 300), key("c", 100, 400)],
      // zsh redraws the second key as "\bec": the predicted `c` landed in column 2 instead of 3.
      [{ at: 8, glyphs: [{ text: "e", column: 2 }] }, { at: 110, glyphs: [{ text: "e", column: 2 }, { text: "c", column: 2 }] }],
      2,
    );
    expect(scored.wrongCells).toBe(1);
    expect(scored.felt[1]).toBe(300);
    expect(scored.predictedFirst).toEqual([true, false]);
  });

  test("a key that never showed is NaN", () => {
    expect(scoreRepetition([key("x", 0)], [], 0).felt[0]).toBeNaN();
  });
});

describe("helpers", () => {
  test("percentile is nearest rank and ignores NaN", () => {
    expect(percentile([5, 1, Number.NaN, 3, 2, 4], 0.5)).toBe(3);
    expect(percentile([], 0.99)).toBeNaN();
  });

  test("paintAfterMessage skips regions whose arrival was not seen", () => {
    expect(paintAfterMessage([{ wsMessageAt: 10, paintedAt: 14 }, { wsMessageAt: undefined, paintedAt: 20 }])).toEqual([4]);
  });
});
