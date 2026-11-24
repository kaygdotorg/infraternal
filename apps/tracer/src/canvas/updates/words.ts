// SPDX-License-Identifier: AGPL-3.0-only
/**
 * The plain words of the Updates controls (#211, S5), as pure functions so every state can be tested without a screen.
 *
 * TASTE: a message says what happens to the person, in one sentence, with no ids or enum names; a button is a verb; the
 * version is written once. Times read as "2 hours ago".
 */
import type { UpdateFacts, UpdateHistoryEntry, UpdateState } from "./source";

/** "just now", "5 minutes ago", "2 hours ago", "3 days ago". */
export function ago(at: number, now: number): string {
  const minutes = Math.max(0, Math.round((now - at) / 60_000));
  if (minutes < 1) return "just now";
  if (minutes < 60) return `${minutes} ${minutes === 1 ? "minute" : "minutes"} ago`;
  const hours = Math.round(minutes / 60);
  if (hours < 24) return `${hours} ${hours === 1 ? "hour" : "hours"} ago`;
  const days = Math.round(hours / 24);
  return `${days} ${days === 1 ? "day" : "days"} ago`;
}

/** The status row: its value, the mark before it (`ok` a tick, `warn` a waiting item, `off` something that did not work, `busy` work now), and an optional meter. */
export interface StatusLine { value: string; mark?: "ok" | "off" | "warn" | "busy"; meter?: number; detail?: string }

/** What the Status row says for a state. `quietMinutes` is only used by the waiting state. */
export function statusLine(state: UpdateState, quietMinutes: number): StatusLine {
  switch (state.kind) {
    case "off": return { value: "Automatic updates are off", mark: "off", detail: state.reason };
    case "never": return { value: "Not checked yet" };
    case "current": return { value: "Up to date", mark: "ok" };
    case "checking": return { value: "Checking for updates…", mark: "busy" };
    case "downloading": return { value: `Downloading ${state.version}`, mark: "busy", meter: state.percent, detail: `${Math.round(state.percent)}%` };
    case "ready": return { value: `${state.version} is ready`, mark: "warn", detail: `It installs when nobody has typed for ${quietMinutes} min, or now if you choose.` };
    case "applying": return { value: state.phase === "switching" ? `Installing ${state.version}…` : `Checking ${state.version}…`, mark: "busy",
      detail: state.phase === "switching" ? "Your sessions stay open." : "If it does not start well within 2 minutes, the previous version comes back." };
    case "rolled-back": return { value: `${state.version} was undone`, mark: "warn", detail: state.reason };
    case "failed": return { value: "The update did not finish", mark: "off", detail: `${state.reason} Nothing was changed.` };
    case "offline": return { value: "Couldn't reach the release server", mark: "off", detail: state.reason };
  }
}

/** One line of history: "0.5.0 · installed · 2 hours ago", plus why for an undone or failed one. */
export function historyLine(entry: UpdateHistoryEntry, now: number): { title: string; sub: string } {
  const what = entry.outcome === "applied" ? "installed" : entry.outcome === "rolled-back" ? "undone" : "did not finish";
  const when = ago(entry.at, now);
  const base = `from ${entry.from} · ${when}`;
  return { title: `${entry.version} ${what}`, sub: entry.reason ? `${base}\n${entry.reason}` : base };
}

/** The confirmation before Roll back: what comes back, and what is lost (D295). */
export function rollbackConfirm(to: string, lost: string): { title: string; effect: string; confirmLabel: string; cancelLabel: string } {
  return { title: `Go back to ${to}?`, effect: lost, confirmLabel: "Roll back", cancelLabel: "Keep this version" };
}

/** The Inbox item's title (D155 U5 and the plan: "Update ready · <version>"). */
export const inboxTitle = (version: string): string => `Update ready · ${version}`;

/** The Inbox item's body: why it waits and what Update now does. */
export function inboxBody(version: string, quietMinutes: number): string {
  return `${version} is downloaded and checked. It installs by itself once nobody has typed for ${quietMinutes} min. Installing restarts the server, keeps your sessions open and reloads this page when you are idle.`;
}

/** The toast after an update (D155 U5). */
export const updatedToast = (version: string): string => `Updated to ${version}. This page reloads when you stop typing.`;

/** The toast when the update was undone. */
export const undoneToast = (version: string): string => `${version} was undone. The previous version is running again.`;

/** Which buttons the window offers now: the verb for each, and whether it can be pressed. */
export function buttons(facts: Pick<UpdateFacts, "state" | "rollback">): { check: boolean; apply: boolean; rollback: boolean } {
  const { kind } = facts.state;
  const busy = kind === "checking" || kind === "downloading" || kind === "applying";
  return { check: !busy && kind !== "off", apply: kind === "ready", rollback: !busy && kind !== "off" && facts.rollback.available };
}
