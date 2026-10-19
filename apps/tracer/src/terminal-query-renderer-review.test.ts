/** Checks query identities against actual responses from the shipping VT engine [307]. */
import { expect, test } from "bun:test";
import { Ghostty } from "../vendor/ghostty-web";
import { TerminalQueries } from "./terminal-queries";

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
