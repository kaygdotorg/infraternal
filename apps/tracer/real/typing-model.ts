/**
 * The pure parts of the realistic-typing rows (#569 finding 2, D375, #447): the key sequences a person types, how
 * quickly, and how a recorded run is turned into numbers. No browser and no server here, so the rules are unit
 * tested (`typing-model.test.ts`) and the spec only drives and records.
 *
 * Why this exists: the original D375 key rows type one key at a time and wait for its echo, against a test double
 * that echoes every byte verbatim. A person at 80 words a minute sends a new key every ~150 ms; on a 300 ms round
 * trip two or three keys are in flight at once, and real shells do not echo verbatim (zsh redraws the second key of
 * a line as `\bec`, bash answers Backspace with `\b` plus erase-to-end). Those are the cases where prediction goes
 * wrong, and the one-key rows cannot see them.
 */

/**
 * One typing trace: a name, the shell it is typed into, and the keys. The key lists are the ones J1079 recorded
 * through real PTYs (`research/feels-local-audit/capture-traces.sh` on branch `j1079-audit-feels-local`, #569):
 * plain typing, and the same line with one typo fixed by Backspace. `Backspace` stands for the DEL key.
 */
export interface TypingTrace {
  name: string;
  shell: "bash" | "zsh";
  keys: string[];
}

/** The characters of a line as single-key entries. */
function chars(text: string): string[] {
  return [...text];
}

/** J1079's four shell traces: plain and with a Backspace correction, in bash and in zsh. */
export const TRACES: readonly TypingTrace[] = [
  { name: "bash-plain", shell: "bash", keys: chars("echo hello world") },
  { name: "bash-backspace", shell: "bash", keys: [...chars("echo helo"), "Backspace", ...chars("lo world")] },
  { name: "zsh-plain", shell: "zsh", keys: chars("echo hello world") },
  { name: "zsh-backspace", shell: "zsh", keys: [...chars("echo helo"), "Backspace", ...chars("lo world")] },
];

/**
 * A small deterministic random generator (mulberry32), so a run's typing rhythm is the same every time and two
 * builds are compared on the same keystrokes.
 */
export function seededRandom(seed: number): () => number {
  let state = seed >>> 0;
  return () => {
    state = (state + 0x6d2b79f5) >>> 0;
    let mixed = Math.imul(state ^ (state >>> 15), 1 | state);
    mixed = (mixed + Math.imul(mixed ^ (mixed >>> 7), 61 | mixed)) ^ mixed;
    return ((mixed ^ (mixed >>> 14)) >>> 0) / 4294967296;
  };
}

/** The mean gap between keys of a fast typist, in milliseconds: about 85 words a minute. */
export const MEAN_GAP_MS = 140;

/**
 * The gaps before each key of a trace, in milliseconds: a person's rhythm, not a metronome. Each gap is the mean
 * plus or minus up to 60 % (never below 45 ms, the speed of a double tap), and about one key in eight is followed by
 * a hesitation of an extra 150 to 300 ms. The first gap is 0. With the same `seed` the gaps are the same.
 */
export function humanGaps(count: number, seed: number, meanMs = MEAN_GAP_MS): number[] {
  const random = seededRandom(seed);
  const gaps: number[] = [];
  for (let index = 0; index < count; index += 1) {
    if (index === 0) { gaps.push(0); continue; }
    let gap = meanMs * (0.4 + 1.2 * random());
    if (random() < 0.125) gap += 150 + 150 * random();
    gaps.push(Math.max(45, gap));
  }
  return gaps;
}

/** Nearest-rank percentile of `values` (fraction 0..1) ignoring non-finite entries; NaN when none. */
export function percentile(values: number[], fraction: number): number {
  const sorted = values.filter(Number.isFinite).sort((left, right) => left - right);
  if (sorted.length === 0) return Number.NaN;
  return sorted[Math.min(sorted.length - 1, Math.max(0, Math.ceil(sorted.length * fraction) - 1))]!;
}

/** The recorder's key, as the spec reads it (see `HumanKeyRecord` in the probe). */
export interface RecordedKey {
  key: string;
  keydownAt: number;
  predictedAt: number | undefined;
  echoPaintedAt: number | undefined;
}

/** One change of the prediction overlay (see `HumanOverlayFrame`). */
export interface RecordedOverlay {
  at: number;
  glyphs: Array<{ text: string; column: number }>;
}

/** How a plain-typing repetition went, per key and for the line. */
export interface Repetition {
  /** Per key: milliseconds from keydown to the letter first being shown in its own cell; NaN when it never was. */
  felt: number[];
  /** Per key: whether a correct prediction showed before the host's echo painted. */
  predictedFirst: boolean[];
  /** Distinct (letter, column) pairs the overlay drew that are not the cell of any key of this line. */
  wrongCells: number;
}

/**
 * Scores one repetition of a plain line (no Backspace), where key `index` belongs in column `startColumn + index`.
 *
 * A key is felt when its letter is first on screen in its own cell: the earlier of a predicted glyph in that cell
 * and the host's echo painting. A predicted glyph in any other cell is wrong, however briefly it showed; counting
 * it is what the old one-key rows could not do (zsh at 300 ms drew 9 of 16 keys one cell short, #569). `keys` and
 * `overlay` are the recorder's for this repetition only.
 */
export function scoreRepetition(keys: RecordedKey[], overlay: RecordedOverlay[], startColumn: number): Repetition {
  const expected = new Set(keys.map((key, index) => `${key.key}@${startColumn + index}`));
  const felt: number[] = [];
  const predictedFirst: boolean[] = [];
  keys.forEach((key, index) => {
    const cell = startColumn + index;
    const shown = overlay.find((frame) => frame.at >= key.keydownAt
      && frame.glyphs.some((glyph) => glyph.text === key.key && glyph.column === cell));
    const times = [shown?.at, key.echoPaintedAt].filter((time): time is number => time !== undefined);
    felt.push(times.length === 0 ? Number.NaN : Math.min(...times) - key.keydownAt);
    predictedFirst.push(shown !== undefined && (key.echoPaintedAt === undefined || shown.at <= key.echoPaintedAt));
  });
  const wrong = new Set<string>();
  for (const frame of overlay) {
    for (const glyph of frame.glyphs) {
      const id = `${glyph.text}@${glyph.column}`;
      if (!expected.has(id)) wrong.add(id);
    }
  }
  return { felt, predictedFirst, wrongCells: wrong.size };
}

/** One painted output region as the recorder saw it. */
export interface RecordedOutput {
  wsMessageAt: number | undefined;
  paintedAt: number;
}

/** Milliseconds from the socket message to the paint of each region whose arrival was seen. */
export function paintAfterMessage(outputs: RecordedOutput[]): number[] {
  return outputs.flatMap((output) => output.wsMessageAt === undefined ? [] : [Math.max(0, output.paintedAt - output.wsMessageAt)]);
}
