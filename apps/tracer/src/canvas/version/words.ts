/**
 * Everything the version pill and its panel say, as pure functions of the facts and the update state (#216), so the wording
 * can be tested and read in one place. Plain, short, calm. No prices, ever. "Infraternal agent" always means the host
 * daemon. A value never repeats its key, and the heading says the version once.
 */
import type { VersionPillState } from "../../../../../packages/ui/src/version-pill.on-demand";
import type { KeyValueRow } from "../../../../../packages/ui/src/kv-list";
import type { Fleet } from "./updates";
import type { Licence, Target, Tier, VersionFacts } from "./source";

const DAY = 86_400_000;
/** A licence that ends within this many days tints the edition and says so in the panel. */
export const SOON_DAYS = 14;

export const TIER_NAME: Record<Tier, string> = { community: "Community", homelab: "Homelab", team: "Team", enterprise: "Enterprise" };

/** "22 Oct 2026", always with the month spelled out. */
export const dayName = (days: number, now = Date.now()): string =>
  new Date(now + days * DAY).toLocaleDateString("en-GB", { day: "numeric", month: "short", year: "numeric" });

export const plural = (n: number, one: string, many: string): string => `${n} ${n === 1 ? one : many}`;

/** The tier whose features run now: an ended licence is Community again. */
export const effectiveTier = (licence: Licence): Tier => (licence.days !== undefined && licence.days < 0 ? "community" : licence.tier);

/** CE for Community, EE for any paid licence (the code under `ee/`, D31). */
export const editionTag = (licence: Licence): "CE" | "EE" => (effectiveTier(licence) === "community" ? "CE" : "EE");

export const attention = (licence: Licence): "soon" | "ended" | undefined => {
  if (licence.days === undefined) return undefined;
  if (licence.days < 0) return "ended";
  return licence.days <= SOON_DAYS ? "soon" : undefined;
};

/** When the licence ends, in a few words: "in 7 days", "tomorrow", "today". */
export const endsIn = (days: number): string => (days === 0 ? "today" : days === 1 ? "tomorrow" : `in ${days} days`);

export const editionName = (licence: Licence): string => TIER_NAME[effectiveTier(licence)];

/** The panel's heading: the product and its version, said once. */
export const panelTitle = (facts: Pick<VersionFacts, "version">): string => `infraternal ${facts.version}`;

/** The title of the licence section is the edition itself, with who it is licensed to when it is a paid one. */
export function licenceLabel(licence: Licence): string {
  const tier = effectiveTier(licence);
  return tier === "community" ? "Community edition" : `${TIER_NAME[tier]} edition${licence.holder ? ` · ${licence.holder}` : ""}`;
}

/** The people row: "3 of 10". */
export const peopleLine = (people: { used: number; max: number }): string => `${people.used.toLocaleString("en")} of ${people.max.toLocaleString("en")}`;

/** True when the seats are nearly all used: the meter says so with a warning mark. */
export const seatsNearlyFull = (people: { used: number; max: number }): boolean => people.used / people.max >= 0.9;

/** What a licence says about its end: "Renews 3 Jan 2027", "Never ends", "Ends 22 Oct 2026 · in 7 days", "Ended 8 Oct 2026". */
export function endLine(licence: Licence, now = Date.now()): { key: string; value: string } {
  const days = licence.days;
  if (days === undefined) return { key: "Valid", value: "Never ends" };
  if (days < 0) return { key: "Licence", value: `${TIER_NAME[licence.endedTier ?? licence.tier]} ended ${dayName(days, now)}` };
  if (days <= SOON_DAYS) return { key: "Ends", value: `${dayName(days, now)} · ${endsIn(days)}` };
  return { key: "Renews", value: dayName(days, now) };
}

/** The sentence under the list when the licence needs a word (only then). */
export function licenceNote(licence: Licence, now = Date.now()): string | undefined {
  const days = licence.days;
  if (days === undefined) return undefined;
  if (days < 0) return "Everything in Community keeps working, and nothing has been turned off.";
  if (days <= SOON_DAYS) return `Your licence ends on ${dayName(days, now)}. Renew it to keep it. Community features keep working either way.`;
  return undefined;
}

// ---- the Updates row ---------------------------------------------------------------------------------------------------

/** "1 update available", "3 updates available". */
export const updatesAvailable = (count: number): string => `${plural(count, "update", "updates")} available`;

/** Which things the targets are, for the tip: "this server, build-01 and nas". */
export function targetNames(targets: Target[]): string {
  const names = targets.map((t) => (t.server ? "this server" : t.name));
  return names.length <= 1 ? (names[0] ?? "") : `${names.slice(0, -1).join(", ")} and ${names[names.length - 1]}`;
}

export interface UpdatesLine { value: string; mark: NonNullable<KeyValueRow["mark"]> | undefined; tip: string }

/** What the Updates row's value says for a state, and its warm tooltip (which names the action a press will do). */
export function updatesLine(fleet: Fleet): UpdatesLine {
  switch (fleet.kind) {
    case "unknown": return { value: "Check for updates", mark: undefined, tip: "Check this server and every host for updates" };
    case "current": return { value: "Up to date", mark: "ok", tip: "Up to date. Press to check again" };
    case "available": return { value: `${updatesAvailable(fleet.targets.length)} — proceed?`, mark: "warn", tip: `Update ${targetNames(fleet.targets)} now` };
    case "failed": return { value: "Couldn't check — try again", mark: "off", tip: `${fleet.reason} Press to try again` };
    case "checking": return { value: "Checking for updates…", mark: "busy", tip: "Checking this server and every host" };
    case "updating": return { value: `Updating ${fleet.targets.length}…`, mark: "busy", tip: `Updating ${targetNames(fleet.targets)}` };
  }
}

/** The pill's state: the settled answer (a check in progress does not change it), the edition and the spoken name. */
export function pillState(facts: VersionFacts, settled: Fleet): VersionPillState {
  const { licence } = facts;
  const status = settled.kind === "current" ? "current" : settled.kind === "available" ? "available" : settled.kind === "failed" ? "offline" : "unknown";
  const line = status === "current" ? "Up to date"
    : status === "available" && settled.kind === "available" ? updatesAvailable(settled.targets.length)
      : status === "offline" ? "Couldn't check for updates" : `Version ${facts.version}`;
  const note = attention(licence);
  const licenceWord = note === "soon" ? `, licence ends ${endsIn(licence.days!)}` : note === "ended" ? ", licence ended" : "";
  return {
    version: facts.version,
    status,
    edition: editionTag(licence),
    ...(note ? { attention: note } : {}),
    tip: `${line} · ${editionName(licence)}${licenceWord}`,
    label: `Version ${facts.version}. ${line}. ${editionName(licence)} edition${licenceWord}. Opens version and updates`,
  };
}
