/**
 * Everything the person's card says, as pure functions of the person (D283), so the wording can be tested and read in
 * one place. Plain, short, calm. The grammar follows the version panel: the heading is the person, a section's title is
 * never repeated by its rows, and a value never repeats its key.
 *
 * The rule for a value (TASTE, owner 2026-11-01): the value says the state plainly, and says a concern itself. There is
 * no second line that reports when something was last looked at ("checked 6 days ago"): when everything is fine the
 * value is calm ("Set up", "2"); when something needs the person, the value says so and what to do ("Not verified since
 * 3 Mar, verify now"), with the amber mark. A recovery key that was verified recently is just "Set up".
 */
import type { Login, LoginHost, Person, Recovery } from "./model";

const count = new Intl.NumberFormat("en");
/** A number with its separators: "1,284". */
export const num = (n: number): string => count.format(n);
const plural = (n: number, one: string, many: string): string => `${num(n)} ${n === 1 ? one : many}`;

/** What the card and the pill call the person: the name, or the username when the data has no name. */
export const shownName = (person: Pick<Person, "name" | "username">): string => person.name.trim() || person.username;

// ---- logs in as ----------------------------------------------------------------------------------------------------------

/** How many accounts are listed in the row before "+N" takes the rest. */
export const CHIPS_SHOWN = 3;

/** The row's value: a chip per account with its host count ("ravi 9"), the first few by host count, then "+N". */
export function loginChips(logins: Login[]): Array<{ text: string; note?: string }> {
  const ordered = [...logins].sort((a, b) => b.hosts.length - a.hosts.length);
  const shown = ordered.slice(0, CHIPS_SHOWN).map((login) => ({ text: login.account, note: num(login.hosts.length) }));
  return ordered.length > CHIPS_SHOWN ? [...shown, { text: `+${num(ordered.length - CHIPS_SHOWN)}` }] : shown;
}

/** The same run as plain text, for the spoken name and for copying. */
export const loginChipsText = (logins: Login[]): string => loginChips(logins).map((c) => (c.note ? `${c.text} ${c.note}` : c.text)).join(", ");

/** The answer when the person can log in nowhere yet; the row is then not a link. */
export const NO_LOGINS = "No hosts yet";

/** Text beside an account's name in the breakdown: how many hosts. */
export const accountHosts = (login: Login): string => plural(login.hosts.length, "host", "hosts");

/** Tag cards drawn per account; the rest is one quiet "+N more tags". */
export const TAG_CARDS_SHOWN = 6;
/** Hosts drawn in one tag card; the rest is one quiet "+N more". */
export const HOSTS_PER_TAG = 24;

export interface TagGroup {
  /** `null` = the machines that carry no tag. */
  tag: string | null;
  hosts: LoginHost[];
}

/**
 * An account's machines, one group for each tag (TASTE: named things are chips; the owner asked for a card for each tag).
 * A machine with several tags is in each of its tags' groups, as a tag filter would list it, and its own chip carries all
 * of its tags' colours. The biggest groups come first, then by name; the untagged machines come last.
 */
export function tagGroups(login: Login): TagGroup[] {
  const byTag = new Map<string, LoginHost[]>();
  const untagged: LoginHost[] = [];
  for (const host of login.hosts) {
    if (!host.tags.length) { untagged.push(host); continue; }
    for (const tag of new Set(host.tags)) (byTag.get(tag) ?? byTag.set(tag, []).get(tag)!).push(host);
  }
  const groups: TagGroup[] = [...byTag].map(([tag, hosts]) => ({ tag, hosts })).sort((a, b) => b.hosts.length - a.hosts.length || a.tag!.localeCompare(b.tag!));
  return untagged.length ? [...groups, { tag: null, hosts: untagged }] : groups;
}

// ---- sign-in health ----------------------------------------------------------------------------------------------------------

/** A recovery key that was last verified longer ago than this is a concern. A product call; the owner can change it. */
export const RECOVERY_STALE_DAYS = 90;
const DAY = 86_400_000;

/** "3 Mar", or "3 Mar 2025" when it was not this year. */
export function shortDate(at: number, now: number): string {
  const sameYear = new Date(at).getFullYear() === new Date(now).getFullYear();
  return new Intl.DateTimeFormat("en-GB", { day: "numeric", month: "short", ...(sameYear ? {} : { year: "numeric" }) }).format(at);
}

export interface Reading {
  /** What the value field says. */
  value: string;
  /** `warn` when the value is a concern; `ok` when it is a calm fact. */
  mark: "ok" | "warn";
  /** The row's warm tooltip: what to do, or where it leads. */
  tip: string;
}

/** The recovery key, in one value: calm when set up and recently verified, otherwise the concern and the way out. */
export function recoveryReading(recovery: Recovery, now: number): Reading {
  if (!recovery.setUp) return { value: "Not set up", mark: "warn", tip: "You have no recovery key. Set one up in Settings" };
  if (recovery.verifiedAt === null) return { value: "Never verified, verify now", mark: "warn", tip: "You have not checked that you hold it. Verify it in Settings" };
  if (now - recovery.verifiedAt > RECOVERY_STALE_DAYS * DAY) return { value: `Not verified since ${shortDate(recovery.verifiedAt, now)}, verify now`, mark: "warn", tip: "Check that you still hold it. Verify it in Settings" };
  return { value: "Set up", mark: "ok", tip: "Recovery key, in Settings" };
}

/** Passkeys: the number when there are two or more; the concern when there are fewer. */
export function passkeyReading(passkeys: number): Reading {
  if (passkeys === 0) return { value: "None, add one", mark: "warn", tip: "You have none. Add one in Settings" };
  if (passkeys === 1) return { value: "Only one, add a second", mark: "warn", tip: "You have only one. Add another on a second device, in Settings" };
  return { value: num(passkeys), mark: "ok", tip: "Passkeys, in Settings" };
}

export interface HealthRow extends Reading {
  id: "passkeys" | "recovery" | "devices";
  key: string;
}

/**
 * The sign-in rows the model knows. Each is state only and jumps to Settings, Account (Q2: one home per thing). A row whose
 * fact the server cannot say yet is left out, not drawn empty.
 */
export function healthRows(person: Person, now: number = Date.now()): HealthRow[] {
  const rows: HealthRow[] = [];
  if (person.passkeys !== undefined) rows.push({ id: "passkeys", key: "Passkeys", ...passkeyReading(person.passkeys) });
  if (person.recovery) rows.push({ id: "recovery", key: "Recovery key", ...recoveryReading(person.recovery, now) });
  if (person.devices !== undefined) rows.push({ id: "devices", key: "Devices", value: person.devices > 0 ? num(person.devices) : "None", mark: "ok", tip: "Devices, in Settings" });
  return rows;
}

export interface Attention { why: "recovery" | "passkey"; /** The pill's tooltip, in one line. */ tip: string }

/** The one reason the pill carries its amber mark (Q6); the recovery key comes first when both apply. */
export function attention(person: Person, now: number = Date.now()): Attention | undefined {
  const rows = healthRows(person, now);
  const recovery = rows.find((r) => r.id === "recovery");
  if (recovery?.mark === "warn") return { why: "recovery", tip: recovery.value.startsWith("Not set up") ? "You have no recovery key" : `Recovery key: ${recovery.value.charAt(0).toLowerCase()}${recovery.value.slice(1)}` };
  const passkeys = rows.find((r) => r.id === "passkeys");
  if (passkeys?.mark === "warn") return { why: "passkey", tip: person.passkeys === 0 ? "You have no passkey" : "You have only one passkey" };
  return undefined;
}

/** The email row's value when there is none: a plain statement, not an invitation (the row's tip invites). */
export const NO_EMAIL = "Not added";

/** The pill's spoken name. */
export const pillLabel = (person: Person, a: Attention | undefined): string =>
  `${shownName(person)}${person.name.trim() ? `, ${person.username}` : ""}. Account${a ? `. ${a.tip}` : ""}`;

/** A plain email check: one @, a dot in the domain, no spaces. */
export const looksLikeEmail = (text: string): boolean => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(text);
