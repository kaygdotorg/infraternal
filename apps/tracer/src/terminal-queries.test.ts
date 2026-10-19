/** Verifies byte identities through fragments and control strings without retaining output [307]. */
import { test, expect } from "bun:test";
import { TerminalQueries } from "./terminal-queries";
const encoder = new TextEncoder();
test("query identity survives split writes and ignores control-string content", () => {
  const scanner = new TerminalQueries(); const found: bigint[] = [];
  scanner.scan(encoder.encode("abc\u001b[6"), 100n, (_, seq) => found.push(seq));
  scanner.scan(encoder.encode("n\u001b]0;title\u001b[6n\u0007\u001b[c"), 106n, (_, seq) => found.push(seq));
  expect(found).toEqual([103n, 121n]);
});
test("all requested query families have identities", () => {
  const queries = ["\u001b[c", "\u001b[>c", "\u001b[6n", "\u001b]11;?\u0007", "\u001b]4;3;?\u001b\\", "\u001b[?2004$p", "\u001b[>q", "\u001b[?u"];
  const found: bigint[] = []; new TerminalQueries().scan(encoder.encode(queries.join("")), 0n, (_, seq) => found.push(seq));
  expect(found.length).toBe(queries.length);
});
test("every split preserves one identity and oversized strings cannot introduce queries", () => {
  const queries = ["\u001b[c", "\u001b[6n", "\u001b]10;?;?\u0007", "\u001b]4;1;?;2;rgb:f/0/0\u001b\\", "\u001b[?2004$p", "\u001b[>q", "\u001b[?u"];
  for (const query of queries) {
    const bytes = encoder.encode(query);
    for (let split = 0; split <= bytes.length; split++) {
      const scanner = new TerminalQueries(); const found: bigint[] = [];
      scanner.scan(bytes.subarray(0, split), 10n, (_, seq) => found.push(seq));
      scanner.scan(bytes.subarray(split), 10n + BigInt(split), (_, seq) => found.push(seq));
      expect(found).toEqual([10n]);
    }
  }
  const found: bigint[] = [];
  const bytes = encoder.encode("\u001bP$q" + "x".repeat(10_000) + "\u001b[6n\u001b\\\u001b[c");
  new TerminalQueries().scan(bytes, 0n, (_, seq) => found.push(seq));
  expect(found).toEqual([BigInt(bytes.length - 3)]);
});

test("oversized OSC retains BEL termination before a later query", () => {
  const bytes = encoder.encode("\u001b]0;" + "a".repeat(260) + "\u0007\u001b[6n");
  const found: bigint[] = []; new TerminalQueries().scan(bytes, 0n, (_, seq) => found.push(seq));
  expect(found).toEqual([BigInt(bytes.length-4)]);
});
