// SPDX-License-Identifier: AGPL-3.0-only
/**
 * What a revoked person left behind (D356, D398): an Inbox item per report, for the owner only.
 *
 * Revoking a person while their host stays makes the host scan that person's access files (SSH keys, scheduled jobs,
 * user services, shell startup files) and report what is new since access was granted. The server keeps the report and
 * lists it here, with its words already written (D360, D364, D367: "No changes found in the N places we watch ...
 * Access outside these checks isn't covered."), so this module only draws them: one generic Inbox line per report, its
 * sentence as the body, the files and lines as the detail list, and Dismiss. A host removal makes no report: it
 * deletes infraternal and its state and nothing else.
 *
 * A report that arrives while the page is open is also said once in a toast; when the toast is gone the item stays in
 * the Inbox until it is dismissed. The page asks again when the host list changes, when the tab comes back and once a
 * minute while it is visible. A refusal (not the owner, no session) withdraws everything and stops asking.
 */
import { ICON_ALERT, ICON_CIRCLE_CHECK } from "../../../../packages/ui/src/icons";
import type { InboxItem } from "../../../../packages/ui/src/inbox";
import type { CoreScreen } from "../core-screen";
import { existingInbox, inboxFor } from "./inbox-host";

/** One waiting report, as the server words it. Nothing here is reworded in the page. */
export interface AccessReportEntry {
  host_id: string;
  /** The host's name for the owner. */
  host: string;
  person_id: string;
  /** Who was revoked; null when they are no longer on this server. */
  person_name: string | null;
  /** When the revocation was confirmed (Unix seconds). */
  recorded_at: number;
  outcome: "changed" | "unchanged" | "not_checked";
  /** The one sentence that heads the report. */
  headline: string;
  /** The files and lines, ready to show in order. */
  lines: string[];
}

/** The two calls the Inbox needs; the product talks to the server, the test double to a list in memory. */
export interface AccessReportService {
  /** The waiting reports, newest first. Rejects with `status` 403 or 401 when this person may not read them. */
  list(): Promise<{ reports: AccessReportEntry[]; more: number }>;
  /** Dismiss one report. */
  dismiss(hostId: string, personId: string): Promise<void>;
}

/** A refusal with the response status, so a 403 can end the asking while a failed fetch just tries again later. */
export class AccessReportError extends Error {
  /** The message is safe to show; `status` is the HTTP status (0 when the request never got an answer). */
  constructor(message: string, readonly status: number) { super(message); }
}

/** The product's service: same-origin POSTs with the browser session, like the other host routes. */
export function serverAccessReports(): AccessReportService {
  const post = async <T>(path: string, body: unknown): Promise<T> => {
    const response = await fetch(`/remote/hosts/${path}`, { method: "POST", credentials: "same-origin", cache: "no-store", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
    if (!response.ok) throw new AccessReportError("Couldn't load the access report.", response.status);
    return await response.json() as T;
  };
  return {
    list: () => post("access-reports", {}),
    dismiss: async (hostId, personId) => { await post("access-reports/dismiss", { host_id: hostId, person_id: personId }); },
  };
}

/** How often a visible page asks again. A revoke is rare; the host list change and the tab coming back cover most of it. */
const POLL_MS = 60_000;
/** The first ask waits for the first screen to paint. */
const FIRST_MS = 1500;
/** How long the "it is in your Inbox" toast stays. */
const TOAST_MS = 9000;

/** The title of the collapsed line: short, host first, so several lines stay told apart. */
export function accessReportTitle(entry: AccessReportEntry): string {
  switch (entry.outcome) {
    case "changed": return `${entry.host}: access left behind`;
    case "unchanged": return `${entry.host}: no changes found`;
    default: return `${entry.host}: not fully checked`;
  }
}

/** The line a toast says when a report arrives. */
function arrivalMessage(entries: readonly AccessReportEntry[]): string {
  const entry = entries[0];
  if (entry === undefined) return "";
  if (entries.length > 1) return `${entries.length} revoked people have reports in your Inbox.`;
  const who = entry.person_name ?? "A revoked person";
  return entry.outcome === "changed" ? `${who} left access behind on ${entry.host}. See the list in your Inbox.` : `${who} was revoked on ${entry.host}. The check result is in your Inbox.`;
}

/** The Inbox item of one report: the sentence, then the files and lines, then Dismiss. */
export function accessReportItem(entry: AccessReportEntry, dismiss: (entry: AccessReportEntry) => void): InboxItem {
  const who = entry.person_name ?? "A revoked person";
  return {
    id: `access-left:${entry.host_id}:${entry.person_id}`,
    icon: entry.outcome === "unchanged" ? ICON_CIRCLE_CHECK : ICON_ALERT,
    title: accessReportTitle(entry),
    body: `${who} was revoked here and the host stayed. ${entry.headline}`,
    details: entry.lines,
    actions: [{ label: "Dismiss", primary: true, run: () => dismiss(entry) }],
  };
}

/** The running Inbox source: ask now, or stop. */
export interface AccessReportInbox {
  /** Asks the server now and republishes. */
  refresh(): Promise<void>;
  dispose(): void;
}

/** Start the Inbox source: the first ask after the first paint, then on host changes, tab returns and a slow timer. */
export function createAccessReportInbox(core: CoreScreen, service: AccessReportService, onHostsChange?: (listener: () => void) => () => void): AccessReportInbox {
  let entries: AccessReportEntry[] = [];
  let known = new Set<string>();
  let loaded = false;
  let stopped = false;
  let disposed = false;
  let running: Promise<void> | undefined;
  const keyOf = (entry: AccessReportEntry): string => `${entry.host_id}:${entry.person_id}`;
  const publish = (): void => {
    const items = entries.map((entry) => accessReportItem(entry, dismiss));
    const inbox = items.length ? inboxFor(core) : existingInbox(core);
    inbox?.set("access-left", items);
  };
  const dismiss = (entry: AccessReportEntry): void => {
    // Gone at once; a failed call brings it back on the next ask, so a dismissal never looks done when it is not.
    entries = entries.filter((other) => keyOf(other) !== keyOf(entry));
    publish();
    void service.dismiss(entry.host_id, entry.person_id).catch(() => { core.toast.show({ message: "Couldn't dismiss this report. Check your connection and try again.", tone: "error", duration: 6000 }); void refresh(); });
  };
  const refresh = (): Promise<void> => running ??= (async () => {
    if (stopped || disposed) return;
    try {
      const answer = await service.list();
      if (disposed) return;
      entries = answer.reports;
      // The first answer says nothing aloud when the person already knew (no toast for what waited before this page);
      // later answers say what is new.
      const fresh = loaded ? entries.filter((entry) => !known.has(keyOf(entry))) : [];
      known = new Set(entries.map(keyOf));
      loaded = true;
      publish();
      if (fresh.length) core.toast.show({ message: arrivalMessage(fresh), duration: TOAST_MS, dismissible: true, icon: fresh.some((entry) => entry.outcome !== "unchanged") ? ICON_ALERT : ICON_CIRCLE_CHECK });
    } catch (error) {
      // Not the owner or no session: nothing here is theirs, and asking again cannot change that. Anything else is a
      // network or server hiccup: keep what is shown and ask again later.
      if (error instanceof AccessReportError && (error.status === 403 || error.status === 401)) { stopped = true; entries = []; publish(); }
    }
  })().finally(() => { running = undefined; });
  const onVisible = (): void => { if (document.visibilityState === "visible") void refresh(); };
  document.addEventListener("visibilitychange", onVisible);
  const offHosts = onHostsChange?.(() => { void refresh(); });
  const first = window.setTimeout(() => { void refresh(); }, FIRST_MS);
  const poll = window.setInterval(() => { if (document.visibilityState === "visible") void refresh(); }, POLL_MS);
  return {
    refresh,
    dispose() {
      disposed = true; offHosts?.(); window.clearTimeout(first); window.clearInterval(poll);
      document.removeEventListener("visibilitychange", onVisible);
      existingInbox(core)?.set("access-left", []);
    },
  };
}
