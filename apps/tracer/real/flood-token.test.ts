/** The flood spec reads a key's token from raw output and from a per-cell repaint alike (#477, D381). */
import { expect, test } from "bun:test";
import { scanTokens } from "./flood-token";

/** One positioned, reset cell as the infraternal agent's repaint serialises it. */
const cell = (row: number, col: number, char: string) => `\x1b[${row};${col}H\x1b[0m${char}`;
/** The head of a real repaint captured under a flood (J575): reset, modes, palette resets, then every cell placed alone. */
const REPAINT_HEAD = "\x1bc\x1b[?7l\x1b[?6l\x1b[?2027l\x1b(B\x0f\x1b]104\x1b\\\x1b]110\x1b\\\x1b]111\x1b\\\x1b]112\x1b\\";

test("a token drawn by the program in raw output is read", () => {
  expect(scanTokens("y\r\ny\x1b7\x1b[1;1H<K000022>\x1b8y\r\n", 21).newest).toBe(22);
});

test("a token that arrives only in a per-cell repaint is read", () => {
  const row1 = [..."<K000023>"].map((char, index) => cell(1, index + 1, char)).join("");
  const flood = Array.from({ length: 35 }, (_, index) => cell(index + 2, 150, "y")).join("");
  const repaint = REPAINT_HEAD + row1 + flood + "\x1b[0m\x1b[?7h\x1b[?25h\x1b[37;150H";
  expect(scanTokens(repaint, 22).newest).toBe(23);
});

test("a raw token split across two frames is read once the second frame arrives", () => {
  const first = scanTokens("y\r\n".repeat(40) + "\x1b7\x1b[1;1H<K0000", 23);
  expect(first.newest).toBe(23);
  expect(scanTokens(first.tail + "24>\x1b8y\r\n", first.newest).newest).toBe(24);
});

test("flood lines and an older token never move the newest token backwards or invent one", () => {
  const repaint = REPAINT_HEAD + [..."yK000021>"].map((char, index) => cell(1, index + 1, char)).join("") + cell(2, 1, "y");
  expect(scanTokens(repaint, 22).newest).toBe(22);
  expect(scanTokens("y\r\n".repeat(500), 22).newest).toBe(22);
});
