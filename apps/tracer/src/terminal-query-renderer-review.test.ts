/** Checks query identities against actual responses from the shipping VT engine [307]. */
import { expect, test } from "bun:test";
import { Ghostty } from "../vendor/ghostty-web";
import { TerminalQueries } from "./terminal-queries";
import { QueryReplies } from "../test/query-replies-double";

const engine = await Ghostty.load(new URL("../vendor/ghostty-web/dist/ghostty-vt.wasm", import.meta.url).pathname);

for (const [name, request] of [
  ["DECID", "\u001bZ"],
  ["zero-padded CPR", "\u001b[06n"],
  ["CPR with an ignored NUL", "\u001b[\u00006n"],
] as const) {
  test(`review: ${name} gives every real renderer response an identity`, () => {
    const terminal = engine.createTerminal(80, 24);
    try {
      terminal.write(request);
      expect(terminal.readResponse()).not.toBeNull();
      const identities: bigint[] = [];
      new TerminalQueries().scan(new TextEncoder().encode(request), 100n,
        (_end, sequence) => identities.push(sequence));
      expect(identities).toEqual([100n]);
    } finally { terminal.free(); }
  });
}

test("review: three adjacent requests keep distinct identities across different viewer chunking", () => {
  const bytes = new TextEncoder().encode("text\u001b[6n\u001bZ\u001b[5n");
  for (let split = 0; split <= bytes.length; split++) {
    const registry = new QueryReplies();
    registry.output(100n, bytes);
    const accepted: bigint[] = [];
    for (const ends of [[bytes.length], [split, bytes.length], Array.from({ length: bytes.length }, (_, index) => index + 1)]) {
      const terminal = engine.createTerminal(80, 24);
      const scanner = new TerminalQueries();
      let offset = 0;
      try {
        for (const end of ends) {
          if (end <= offset) continue;
          const part = bytes.subarray(offset, end);
          terminal.writeSlices(part, (write) => {
            let written = 0;
            const flush = (boundary: number, identity: bigint): void => {
              write(boundary);
              let answer = "";
              for (let next = terminal.readResponse(); next !== null; next = terminal.readResponse()) answer += next;
              if (answer && registry.accept(identity, new TextEncoder().encode(answer))) accepted.push(identity);
              written = boundary;
            };
            scanner.scan(part, 100n + BigInt(offset), flush);
            if (written < part.length) flush(part.length, 100n + BigInt(offset + written));
          });
          offset = end;
        }
      } finally { terminal.free(); }
    }
    expect(accepted).toEqual([104n, 108n, 110n]);
    expect(registry.attempts).toBe(9);
    expect(registry.dropped).toBe(6);
  }
});
