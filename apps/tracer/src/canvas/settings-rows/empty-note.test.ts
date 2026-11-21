// SPDX-License-Identifier: AGPL-3.0-only
/** The empty-window line says what is coming and never claims a date (#568: "Not available yet." named nothing). */
import { expect, test } from "bun:test";
import { emptyGroupNote } from "./empty-note";

test("a window with no settings says there is nothing to set yet, with no invented detail", () => {
  expect(emptyGroupNote([])).toBe("Nothing to set here yet.");
});

test("one setting is named, with 'it'", () => {
  expect(emptyGroupNote(["Lines Kept"])).toBe("Nothing to set here yet. Lines Kept will appear here once the server can save it.");
});

test("two settings are joined with 'and', with 'them'", () => {
  expect(emptyGroupNote(["Join Code Lasts", "Name Suffix"])).toBe(
    "Nothing to set here yet. Join Code Lasts and Name Suffix will appear here once the server can save them.",
  );
});

test("three or more settings are listed in order, comma-separated, with the last joined by 'and'", () => {
  expect(emptyGroupNote(["Add Link Lasts", "Join Code Lasts", "Install Mode"])).toBe(
    "Nothing to set here yet. Add Link Lasts, Join Code Lasts and Install Mode will appear here once the server can save them.",
  );
});

test("the line never says 'Not available' and never gives a date", () => {
  for (const titles of [[], ["Lines Kept"], ["A", "B", "C"]]) {
    const line = emptyGroupNote(titles);
    expect(line).not.toContain("Not available");
    expect(line).not.toMatch(/\d{4}-\d{2}-\d{2}|\bdays?\b|\bweeks?\b/);
  }
});
