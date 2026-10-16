/** Deterministic fuzz target for malformed terminal text and OSC 8 cell runs. */
import { expect, test } from "bun:test";
import { detectTerminalLinks, isOpenableTarget, type TerminalLinkRow } from "./terminal-links.on-demand";

const ALPHABET = "httphttpsfilemailtojavascriptdata://example.test:8443/path?q=1&x=(a)[b]{c},.;!?<>\"'`\\\u0000";

function random(seed: number): () => number {
  let state = seed >>> 0;
  return () => {
    state ^= state << 13;
    state ^= state >>> 17;
    state ^= state << 5;
    return state >>> 0;
  };
}

test("fuzzes malformed text and OSC 8 targets without producing invalid ranges", () => {
  const next = random(0x2140_2026);
  const rows: TerminalLinkRow[] = [];
  let absoluteY = 0;
  for (let sample = 0; sample < 750; sample += 1) {
    const rowCount = 1 + (next() % 4);
    for (let rowIndex = 0; rowIndex < rowCount; rowIndex += 1) {
      const width = 1 + (next() % 72);
      const cells = Array.from({ length: width }, () => {
        const character = ALPHABET[next() % ALPHABET.length]!;
        if (next() % 5 !== 0) return { text: character };
        const target = [
          "https://valid.example.test/path",
          "mailto:person@example.test",
          "javascript:alert(1)",
          "data:text/html,unsafe",
          "custom:target",
        ][next() % 5]!;
        return { text: character, target };
      });
      const wrapped = rowIndex > 0 && next() % 2 === 0;
      rows.push({ y: absoluteY + rowIndex, wrapped, cells });
    }
    absoluteY += rowCount + 1;
  }

  const found = detectTerminalLinks(rows);
  const byY = new Map(rows.map((row) => [row.y, row]));
  for (const link of found) {
    expect(link.range.end.y).toBeGreaterThanOrEqual(link.range.start.y);
    expect(byY.get(link.range.start.y)?.cells[link.range.start.x]).toBeDefined();
    expect(byY.get(link.range.end.y)?.cells[link.range.end.x]).toBeDefined();
    expect(link.openable).toBe(isOpenableTarget(link.target));
    if (link.openable) expect(["http:", "https:", "mailto:"]).toContain(new URL(link.target).protocol);
  }
});
