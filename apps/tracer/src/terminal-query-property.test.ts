/** Checks every corpus form answered by the shipping VT across splits and three independent viewers [307]. */
import { expect, test } from "bun:test";
import { Ghostty } from "../vendor/ghostty-web";
import { terminalQueryCorpus } from "../test/terminal-query-corpus";
import { QueryReplies } from "../test/query-replies-double";
import { TerminalQueries } from "./terminal-queries";

const engine = await Ghostty.load(new URL("../vendor/ghostty-web/dist/ghostty-vt.wasm", import.meta.url).pathname);
const encoder = new TextEncoder();
test("every renderer-answered form produces exactly one admitted reply for every split with three viewers", () => {
  let answered = 0; let splits = 0;
  for (const request of terminalQueryCorpus) {
    const reference = engine.createTerminal(80, 24);
    reference.write(request);
    const response = reference.readResponse();
    reference.free();
    if (response === null) continue;
    answered++;
    const bytes = encoder.encode(request);
    for (let split = 0; split <= bytes.length; split++) {
      splits++;
      const registry = new QueryReplies();
      registry.output(100n, bytes.subarray(0, split));
      registry.output(100n + BigInt(split), bytes.subarray(split));
      const accepted: string[] = [];
      for (let viewer = 0; viewer < 3; viewer++) {
        const terminal = engine.createTerminal(80, 24);
        const boundaries = new TerminalQueries();
        try {
          for (const [offset, part] of [[0, bytes.subarray(0, split)], [split, bytes.subarray(split)]] as const) {
            terminal.writeSlices(part, (writeSlice) => {
              let start = 0;
              const write = (end: number, identity: bigint): void => {
                writeSlice(end);
                let replies = "";
                for (let next = terminal.readResponse(); next !== null; next = terminal.readResponse()) replies += next;
                if (replies && registry.accept(identity, encoder.encode(replies))) accepted.push(replies);
                start = end;
              };
              boundaries.scan(part, 100n + BigInt(offset), (end, identity) => write(end, identity));
              if (start < part.length) write(part.length, 100n + BigInt(offset + start));
            });
          }
        } finally { terminal.free(); }
      }
      expect(accepted, JSON.stringify({ request, split })).toEqual([response]);
      expect(registry.attempts).toBe(3);
      expect(registry.dropped).toBe(2);
    }
  }
  expect(answered).toBeGreaterThanOrEqual(30);
  console.log(`QUERY_PROPERTY forms=${answered} splits=${splits} viewers=3 accepted=1 duplicates=2`);
});
