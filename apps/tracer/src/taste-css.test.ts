// SPDX-License-Identifier: AGPL-3.0-only
/**
 * Guards the shared CSS invariants fixed by the 2026-11-27 TASTE audit (#598):
 * - No bare `:focus-visible` rule draws an outline without `[data-focus-ring="on"]` (TASTE §1).
 * - `.ui-window-session` shrinks far faster than `.ui-window-title` so hostnames stay whole while session text yields (TASTE §4).
 * - `.ui-kv-hint` wraps instead of using `white-space: nowrap`, so long hints never cause horizontal overflow in Settings panes (TASTE §4).
 */
import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

/** Reads a repository stylesheet relative to the repo root. */
function readSheet(relativePath: string): string {
  return readFileSync(resolve(import.meta.dir, "../../..", relativePath), "utf8");
}

describe("shared TASTE CSS invariants (#598)", () => {
  test("no bare :focus-visible rule in packages/ui/styles.css sets a visible outline", () => {
    const css = readSheet("packages/ui/styles.css");
    const offenders: string[] = [];
    for (const line of css.split("\n")) {
      if (!line.includes(":focus-visible")) continue;
      if (line.includes('data-focus-ring="on"')) continue;
      if (/outline\s*:(?!\s*none\b)/.test(line)) offenders.push(line.trim());
    }
    expect(offenders).toEqual([]);
  });

  test(".ui-window-session shrinks far faster than .ui-window-title so hostnames stay whole", () => {
    const css = readSheet("packages/ui/styles.css");
    const match = css.match(/\.ui-window-session\s*\{[^}]*flex:\s*0\s+(\d+)\s+auto/);
    expect(match).not.toBeNull();
    expect(Number(match![1])).toBeGreaterThanOrEqual(10000);
  });

  test(".ui-kv-hint wraps instead of forcing nowrap horizontal overflow", () => {
    const css = readSheet("packages/ui/styles.css");
    const match = css.match(/\.ui-kv-hint\s*\{([^}]*)\}/);
    expect(match).not.toBeNull();
    expect(match![1]).not.toMatch(/white-space\s*:\s*nowrap/);
  });
});
