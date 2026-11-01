import { expect, test } from "bun:test";
import { keysIn } from "./input-keys";

test("text is one key per character, whole characters, not code units", () => {
  expect(keysIn("a")).toBe(1);
  expect(keysIn("ls -la")).toBe(6);
  expect(keysIn("é")).toBe(1);
  expect(keysIn("😀😀")).toBe(2);
});

test("a control sequence is one key, however long", () => {
  expect(keysIn("\u001b[A")).toBe(1);
  expect(keysIn("\u001b[200~pasted text\u001b[201~")).toBe(1);
  expect(keysIn("\u001b")).toBe(1);
});

test("an empty chunk still counts as one, so a kept chunk is never zero keys", () => {
  expect(keysIn("")).toBe(1);
});
