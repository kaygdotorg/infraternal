// SPDX-License-Identifier: AGPL-3.0-only
/**
 * Where the owner's Updates controls get their facts (#211, S5): the state of this server's own automatic update, the two
 * settings that steer it (channel, quiet window), the history of past updates, and the four things the owner can ask for
 * (check now, update now, roll back, pick a channel).
 *
 * The Settings window (`panel.on-demand.ts`) and the Inbox item (`notices.ts`; no toasts, owner 2026-11-22) read only this interface, so the
 * test double (canvas/mock/updates/double.ts) and the live source (the `release.update.*` RPCs) differ in where the facts come
 * from and never in how they are told. Until the owner approves the mockup (D162) the product registers no source, and the
 * Updates window keeps its "Not available yet" line.
 *
 * "Update" here is the server's own binary. Updating the infraternal agents on hosts follows later (S7) and is not shown.
 */

/** The two release channels (D185): stable by default, edge opt-in and labelled "may break". */
export type Channel = "stable" | "edge";

/**
 * Where an update is now. The server decides; the window only tells it.
 * - `off`: automatic updates cannot run on this server at all (not root, a source build, macOS); `reason` says why in a sentence.
 * - `never`: nothing was checked yet.
 * - `current`: the last check found nothing newer.
 * - `checking` / `downloading`: work in progress (`percent` is 0 to 100).
 * - `ready`: downloaded, verified and staged; it applies at the next quiet moment (or when the owner says "Update now").
 * - `applying`: switching, then the two-minute health check of the new version (D295).
 * - `rolled-back`: the new version failed its check or the owner rolled back; the old one runs again. `lost` says which data went with it.
 * - `failed`: a check, download or verification did not finish; nothing changed.
 * - `offline`: the release server cannot be reached, or the channel has no release yet.
 */
export type UpdateState =
  | { kind: "off"; reason: string }
  | { kind: "never" }
  | { kind: "current" }
  | { kind: "checking" }
  | { kind: "downloading"; version: string; percent: number }
  | { kind: "ready"; version: string }
  | { kind: "applying"; version: string; phase: "switching" | "checking" }
  | { kind: "rolled-back"; version: string; reason: string }
  | { kind: "failed"; reason: string }
  | { kind: "offline"; reason: string };

/** One line of the history: an update that was applied, undone or never finished. */
export interface UpdateHistoryEntry {
  /** The version it moved to (or tried to). */
  version: string;
  /** The version it came from; unknown when the server's record does not say. */
  from: string | undefined;
  outcome: "applied" | "rolled-back" | "failed";
  /** Why, in a sentence, for an outcome that is not `applied`. */
  reason?: string;
  /** Milliseconds since the epoch. */
  at: number;
}

/** How long after an install the owner may roll back (owner, 2026-11-22). After a day the loss is too large for one button. */
export const ROLLBACK_HOURS = 24;

/** What the owner sees: the state, the running version and the settings. */
export interface UpdateFacts {
  state: UpdateState;
  /** The version this server runs now. */
  running: string;
  channel: Channel;
  /** Minutes without typing or attaching before an update may apply (D295 quiet window). */
  quietMinutes: number;
  /** When the last check finished, milliseconds since the epoch; undefined before the first. */
  checkedAt: number | undefined;
  /** Newest first. */
  history: readonly UpdateHistoryEntry[];
  /**
   * What "Roll back" would do: a previous version is kept next to the running one. `lost` says what a roll back costs (D295:
   * what was written since the copy of the database was taken), in a sentence for the confirmation; `since` is when that copy
   * was taken (milliseconds since the epoch). The window offers the button only for `ROLLBACK_HOURS` after `since`.
   */
  rollback: { available: false } | { available: true; to: string; lost: string; since: number };
}

/** What the window asks of the server. Each call needs the owner and a fresh sign-in; a refusal rejects with a plain sentence. */
export interface UpdatesSource {
  facts(): UpdateFacts;
  /** Looks for a newer release now. Resolves when the check has started; the state follows through `onChange`. */
  check(): Promise<void>;
  /** Applies the staged version now instead of waiting for a quiet moment. */
  apply(): Promise<void>;
  /** Puts the previous version back, with the database copy taken before the update. */
  rollback(): Promise<void>;
  setChannel(channel: Channel): Promise<void>;
  setQuietMinutes(minutes: number): Promise<void>;
  /** Calls `run` when `facts()` would answer differently. Returns the remover. */
  onChange(run: () => void): () => void;
}

/** The source the Updates window and the notices use; the product registers the live one once its connection is up. */
let registered: UpdatesSource | undefined;
const listeners = new Set<() => void>();

/** Makes `source` the one the Updates window reads, or removes it (`undefined`). Windows already open repaint. */
export function setUpdatesSource(source: UpdatesSource | undefined): void {
  registered = source;
  for (const run of listeners) run();
}

/** The registered source, if any. */
export const updatesSource = (): UpdatesSource | undefined => registered;

/** Calls `run` when a source is registered or removed. Returns the remover. */
export function onUpdatesSource(run: () => void): () => void {
  listeners.add(run);
  return () => { listeners.delete(run); };
}
