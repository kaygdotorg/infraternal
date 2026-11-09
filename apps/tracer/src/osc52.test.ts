/** Verifies the OSC 52 scanner: split chunks, both terminators, refusals and the size cap (#440). */
import { test, expect } from "bun:test";
import { MAX_BASE64, Osc52Scanner } from "./osc52";

/** Turns test strings into the bytes the scanner reads. */
const encoder = new TextEncoder();
/** The base64 text of a string, as a program sends it. */
const b64 = (text: string): string => Buffer.from(text, "utf8").toString("base64");
/** Feeds the chunks to one scanner in order and returns every text it reports. */
const scanAll = (...chunks: string[]): string[] => {
  const scanner = new Osc52Scanner(); const copies: string[] = [];
  for (const chunk of chunks) scanner.scan(encoder.encode(chunk), (text) => copies.push(text));
  return copies;
};

test("a copy ends on BEL or on ESC backslash, and decodes UTF-8", () => {
  expect(scanAll(`\u001b]52;c;${b64("naïve ✓")}\u0007`)).toEqual(["naïve ✓"]);
  expect(scanAll(`x\u001b]52;c;${b64("a\nb")}\u001b\\y`)).toEqual(["a\nb"]);
});

test("a copy split at every byte boundary gives the same text", () => {
  const whole = `\u001b[1mhi\u001b]52;c;${b64("split me")}\u001b\\\u001b]52;p;${b64("two")}\u0007`;
  for (let cut = 1; cut < whole.length; cut++) expect(scanAll(whole.slice(0, cut), whole.slice(cut))).toEqual(["split me", "two"]);
});

test("reads, empty writes, bad base64 and cut buffers copy nothing", () => {
  expect(scanAll("\u001b]52;c;?\u0007\u001b]52;c;\u0007\u001b]52;c;@@\u0007\u001b]52;0;" + b64("cut") + "\u0007")).toEqual([]);
  expect(scanAll(`\u001b]52;c;${Buffer.from([0xff, 0xfe]).toString("base64")}\u0007`)).toEqual([]);
});

test("an empty target list and the primary selection are writes", () => {
  expect(scanAll(`\u001b]52;;${b64("default")}\u0007\u001b]52;s;${b64("primary")}\u0007`)).toEqual(["default", "primary"]);
});

test("other sequences, a cancelled copy and an ESC inside a copy do not leak or hide the next copy", () => {
  expect(scanAll(`\u001b]0;title\u0007\u001b]52;c;${b64("lost")}\u0018ok\u001b]52;c;${b64("kept")}\u0007`)).toEqual(["kept"]);
  expect(scanAll(`\u001b]52;c;${b64("never")}\u001b[31m\u001b]52;c;${b64("next")}\u0007`)).toEqual(["next"]);
});

test("a copy over the cap is ignored whole and the next one still works", () => {
  const huge = "A".repeat(MAX_BASE64 + 4);
  expect(scanAll(`\u001b]52;c;${huge}\u0007`, `\u001b]52;c;${b64("after")}\u0007`)).toEqual(["after"]);
});

test("a copy over the cap is reported once, and a replayed one is not", () => {
  const scanner = new Osc52Scanner(); let reported = 0; const copies: string[] = [];
  const huge = encoder.encode(`\u001b]52;c;${"A".repeat(MAX_BASE64 + 4)}\u0007`);
  scanner.scan(huge.subarray(0, 600_000), (text) => copies.push(text), () => reported++);
  scanner.scan(huge.subarray(600_000), (text) => copies.push(text), () => reported++);
  expect([reported, copies.length]).toEqual([1, 0]);
  scanner.scan(huge, undefined, () => reported++);
  expect(reported).toBe(1);
});

test("replayed bytes keep the scanner in step without copying", () => {
  const scanner = new Osc52Scanner(); const copies: string[] = [];
  scanner.scan(encoder.encode(`\u001b]52;c;${b64("old").slice(0, 2)}`), undefined);
  scanner.scan(encoder.encode(`${b64("old").slice(2)}\u0007\u001b]52;c;${b64("live")}\u0007`), (text) => copies.push(text));
  expect(copies).toEqual(["live"]);
});
