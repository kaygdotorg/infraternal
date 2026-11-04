// SPDX-License-Identifier: AGPL-3.0-only
/**
 * The values a setting can hold and the rules that refuse a bad one (pure, no DOM, so the rules are tested alone).
 *
 * Five kinds exist. A **duration** is a whole number of minutes, hours or days with an allowed range; it is written in the
 * unit the setting is described in (`30 d`), but a person may type another unit (`36 h`, `2 days`) and it is converted and
 * checked against the same range. A **number** is a whole count with a range (lines of scrollback). A **text** value must
 * match a pattern (a name suffix). A **choice** is one of a few named options, and a **switch** is on or off: both are picked,
 * never typed, so they have nothing to refuse.
 *
 * A refusal is a plain sentence that names the allowed range and says the old value stays ("Pick 1 to 90 days. Still using
 * 30 d."): the message is the whole explanation, so the row never needs a second line of help (TASTE: messages say what
 * happens, in plain words). Technical terms never appear in a refusal.
 *
 * Durations are held in minutes so one comparison covers every unit; `formatValue` writes them back in the setting's own
 * unit when they divide evenly, else in the largest unit that does (36 h for a setting in days).
 */

/** The units a duration is written in. */
export type DurationUnit = "min" | "h" | "d";

/** Minutes in one of each unit. */
export const UNIT_MINUTES: Readonly<Record<DurationUnit, number>> = { min: 1, h: 60, d: 1440 };

/** A duration setting. `default`, `min` and `max` are numbers of `unit`. */
export interface DurationSpec { kind: "duration"; unit: DurationUnit; default: number; min: number; max: number }
/** A count: `unit` is the plural noun ("lines"). */
export interface NumberSpec { kind: "number"; unit: string; default: number; min: number; max: number }
/** A text setting. `rule` is the sentence a refusal shows ("Use lowercase letters, digits and hyphens."). */
export interface TextSpec { kind: "text"; default: string; pattern: RegExp; rule: string }
/** One of a few named options; `default` is an option's id. */
export interface ChoiceSpec { kind: "choice"; options: ReadonlyArray<{ id: string; label: string }>; default: string }
/** An on-or-off setting. */
export interface SwitchSpec { kind: "switch"; default: boolean }
/** Every kind of value a setting can hold, with the rules for it. */
export type ValueSpec = DurationSpec | NumberSpec | TextSpec | ChoiceSpec | SwitchSpec;
/** The kinds a person types into a field (and so can get wrong). */
export type TypedSpec = DurationSpec | NumberSpec | TextSpec;
/** True for the kinds a person types (a duration, a count, a text), which can be wrong. */
export const isTyped = (spec: ValueSpec): spec is TypedSpec => spec.kind === "duration" || spec.kind === "number" || spec.kind === "text";

/** What a setting holds: minutes for a duration, the count for a number, the text, an option's id, on or off. */
export type SettingValue = number | string | boolean;
/** The outcome of reading typed text: the value, or the sentence that says why not. */
export type Parsed = { ok: true; value: SettingValue } | { ok: false; message: string };

/** The singular and plural word for each duration unit. */
const WORD: Record<DurationUnit, [one: string, many: string]> = { min: ["minute", "minutes"], h: ["hour", "hours"], d: ["day", "days"] };

/** "1 day", "30 days". */
export const unitWord = (unit: DurationUnit, n: number): string => WORD[unit][n === 1 ? 0 : 1];

/** The unit a typed word means, or undefined. Accepts the short and the long forms, singular or plural. */
function unitOf(word: string): DurationUnit | undefined {
  if (["m", "min", "mins", "minute", "minutes"].includes(word)) return "min";
  if (["h", "hr", "hrs", "hour", "hours"].includes(word)) return "h";
  if (["d", "day", "days"].includes(word)) return "d";
  return undefined;
}

/** The default as a value (minutes for a duration). */
export const defaultValue = (spec: ValueSpec): SettingValue => spec.kind === "duration" ? spec.default * UNIT_MINUTES[spec.unit] : spec.default;

/** "1 to 90 days", "1000 to 100000 lines". For text, the rule. */
export function rangeText(spec: ValueSpec): string {
  if (spec.kind === "duration") return `${spec.min} to ${spec.max} ${unitWord(spec.unit, spec.max)}`;
  if (spec.kind === "number") return `${spec.min} to ${spec.max} ${spec.unit}`;
  return spec.kind === "text" ? spec.rule : "";
}

/** A value written for display: `30 d`, `24 h`, `15 min`, `10000`, an option's label, `On`, or the text itself. */
export function formatValue(spec: ValueSpec, value: SettingValue): string {
  if (spec.kind === "text") return String(value);
  if (spec.kind === "number") return String(value);
  if (spec.kind === "choice") return spec.options.find((o) => o.id === value)?.label ?? String(value);
  if (spec.kind === "switch") return value ? "On" : "Off";
  const minutes = Number(value);
  for (const unit of [spec.unit, "d", "h", "min"] as const) {
    if (minutes % UNIT_MINUTES[unit] === 0) return `${minutes / UNIT_MINUTES[unit]} ${unit}`;
  }
  return `${minutes} min`;
}

/** The caption under a row: what the default is and what is allowed. `Default 30 d · allowed 1 to 90 days`. */
export function captionFor(spec: ValueSpec): string {
  const shown = formatValue(spec, defaultValue(spec));
  if (spec.kind === "duration" || spec.kind === "number") return `Default ${shown} · allowed ${rangeText(spec)}`;
  if (spec.kind === "text") return `Default ${spec.default} · ${spec.rule}`;
  return `Default ${shown}`;
}

/** Reads what a person typed. A refusal never changes anything: the caller keeps the saved value. */
export function parseValue(spec: ValueSpec, text: string, current: SettingValue): Parsed {
  const typed = text.trim().toLowerCase();
  const still = `Still using ${formatValue(spec, current)}.`;
  if (spec.kind === "choice") return spec.options.some((o) => o.id === typed) ? { ok: true, value: typed } : { ok: false, message: `Pick one of the choices. ${still}` };
  if (spec.kind === "switch") return { ok: true, value: typed === "on" || typed === "true" };
  if (spec.kind === "text") {
    return spec.pattern.test(typed) ? { ok: true, value: typed } : { ok: false, message: `${spec.rule} ${still}` };
  }
  if (spec.kind === "number") {
    const match = /^(\d+)\s*([a-z]*)$/.exec(typed);
    if (!match || (match[2] && match[2] !== spec.unit)) return { ok: false, message: `Type a whole number of ${spec.unit}, like ${spec.default}. ${still}` };
    const n = Number(match[1]);
    return Number.isSafeInteger(n) && n >= spec.min && n <= spec.max ? { ok: true, value: n } : { ok: false, message: `Pick ${rangeText(spec)}. ${still}` };
  }
  const match = /^(\d+)\s*([a-z]*)$/.exec(typed);
  if (!match) return { ok: false, message: `Type a whole number of ${WORD[spec.unit][1]}, like ${spec.default}. ${still}` };
  const unit = match[2] ? unitOf(match[2]) : spec.unit;
  if (!unit) return { ok: false, message: `Use min, h or d after the number. ${still}` };
  const minutes = Number(match[1]) * UNIT_MINUTES[unit];
  const low = spec.min * UNIT_MINUTES[spec.unit], high = spec.max * UNIT_MINUTES[spec.unit];
  if (!Number.isSafeInteger(minutes) || minutes < low || minutes > high) return { ok: false, message: `Pick ${rangeText(spec)}. ${still}` };
  return { ok: true, value: minutes };
}
