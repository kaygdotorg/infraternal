// SPDX-License-Identifier: AGPL-3.0-only
/** The rules that refuse a bad setting value, and the words they use. */
import { expect, test } from "bun:test";
import { captionFor, defaultValue, formatValue, parseValue, type ChoiceSpec, type DurationSpec, type NumberSpec, type SwitchSpec, type TextSpec } from "./setting-value";

const browser: DurationSpec = { kind: "duration", unit: "d", default: 30, min: 1, max: 90 };
const cert: DurationSpec = { kind: "duration", unit: "h", default: 24, min: 1, max: 24 };
const suffix: TextSpec = { kind: "text", default: ".internal", pattern: /^\.[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$/, rule: "Start with a dot, then lowercase letters, digits and hyphens." };

test("a bare number uses the setting's own unit", () => {
  expect(parseValue(browser, "45", 43200)).toEqual({ ok: true, value: 45 * 1440 });
  expect(parseValue(cert, " 12 ", 1440)).toEqual({ ok: true, value: 720 });
});

test("another unit is converted and checked against the same range", () => {
  expect(parseValue(browser, "36 h", 43200)).toEqual({ ok: true, value: 2160 });
  expect(parseValue(cert, "1d", 60)).toEqual({ ok: true, value: 1440 });
  expect(parseValue(browser, "2 days", 43200)).toEqual({ ok: true, value: 2880 });
});

test("the limits themselves are allowed and one step past them is refused", () => {
  expect(parseValue(browser, "1", 43200).ok).toBe(true);
  expect(parseValue(browser, "90", 43200).ok).toBe(true);
  expect(parseValue(browser, "0", 43200).ok).toBe(false);
  expect(parseValue(browser, "91", 43200).ok).toBe(false);
  expect(parseValue(cert, "25", 1440).ok).toBe(false);
  expect(parseValue(cert, "2d", 1440).ok).toBe(false);
});

test("a refusal names the range and says the old value stays", () => {
  expect(parseValue(browser, "400", 43200)).toEqual({ ok: false, message: "Pick 1 to 90 days. Still using 30 d." });
  expect(parseValue(cert, "30", 1440)).toEqual({ ok: false, message: "Pick 1 to 24 hours. Still using 24 h." });
});

test("things that are not a number of time are refused in plain words", () => {
  expect(parseValue(browser, "", 43200)).toEqual({ ok: false, message: "Type a whole number of days, like 30. Still using 30 d." });
  expect(parseValue(browser, "abc", 43200).ok).toBe(false);
  expect(parseValue(browser, "1.5", 43200).ok).toBe(false);
  expect(parseValue(browser, "-3", 43200).ok).toBe(false);
  expect(parseValue(browser, "5 weeks", 43200)).toEqual({ ok: false, message: "Use min, h or d after the number. Still using 30 d." });
  expect(parseValue(browser, "99999999999999999999", 43200).ok).toBe(false);
});

test("a value is written in the setting's unit when it divides evenly, else in the largest unit that does", () => {
  expect(formatValue(browser, 43200)).toBe("30 d");
  expect(formatValue(cert, 1440)).toBe("24 h");
  expect(formatValue(browser, 2160)).toBe("36 h");
  expect(formatValue({ kind: "duration", unit: "min", default: 15, min: 1, max: 60 }, 15)).toBe("15 min");
});

test("the caption gives the default and the allowed range", () => {
  expect(captionFor(browser)).toBe("Default 30 d · allowed 1 to 90 days");
  expect(captionFor(cert)).toBe("Default 24 h · allowed 1 to 24 hours");
  expect(defaultValue(browser)).toBe(43200);
});

test("a text value must match its pattern", () => {
  expect(parseValue(suffix, ".mesh.internal", ".internal")).toEqual({ ok: true, value: ".mesh.internal" });
  expect(parseValue(suffix, ".Internal", ".internal")).toEqual({ ok: true, value: ".internal" });
  expect(parseValue(suffix, "internal", ".internal")).toEqual({ ok: false, message: "Start with a dot, then lowercase letters, digits and hyphens. Still using .internal." });
  expect(parseValue(suffix, ".bad name", ".internal").ok).toBe(false);
});

const lines: NumberSpec = { kind: "number", unit: "lines", default: 10000, min: 1000, max: 100000 };
const mode: ChoiceSpec = { kind: "choice", options: [{ id: "system", label: "System" }, { id: "user", label: "User" }], default: "system" };
const auto: SwitchSpec = { kind: "switch", default: true };

test("a count is a whole number within its range, with or without its unit", () => {
  expect(parseValue(lines, "5000", 10000)).toEqual({ ok: true, value: 5000 });
  expect(parseValue(lines, "5000 lines", 10000)).toEqual({ ok: true, value: 5000 });
  expect(parseValue(lines, "999", 10000)).toEqual({ ok: false, message: "Pick 1000 to 100000 lines. Still using 10000." });
  expect(parseValue(lines, "100001", 10000).ok).toBe(false);
  expect(parseValue(lines, "5000 days", 10000).ok).toBe(false);
  expect(parseValue(lines, "1.5", 10000)).toEqual({ ok: false, message: "Type a whole number of lines, like 10000. Still using 10000." });
  expect(captionFor(lines)).toBe("Default 10000 · allowed 1000 to 100000 lines");
});

test("a choice and a switch are picked, so they show their default and have nothing to refuse", () => {
  expect(captionFor(mode)).toBe("Default System");
  expect(formatValue(mode, "user")).toBe("User");
  expect(defaultValue(mode)).toBe("system");
  expect(parseValue(mode, "user", "system")).toEqual({ ok: true, value: "user" });
  expect(parseValue(mode, "root", "system").ok).toBe(false);
  expect(captionFor(auto)).toBe("Default On");
  expect(formatValue(auto, false)).toBe("Off");
  expect(defaultValue(auto)).toBe(true);
});
