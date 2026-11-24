// SPDX-License-Identifier: AGPL-3.0-only
/**
 * The live Updates source (#211, S5): the owner's Updates window and the Inbox item read this server's real update state through the
 * `release.update.*` actions (status, check, apply, rollback, history, settings) and the `release.channel.set` action, over the canvas
 * connection. It is the same `UpdatesSource` the test double plays, so nothing in the window knows which one it has.
 *
 * What the server says and what this file makes of it:
 *  - `status` (and the `release.update` topic, which streams the same state) gives the running version, channel, quiet window, what is
 *    staged, the last check and its error, how the last switch ended, and the roll back plan. It is read again after every reconnect:
 *    an update restarts the server, so the socket drops and events sent meanwhile are not replayed.
 *  - Work in progress (`checking`, `applying`) is this page's own: the server answers a check when it finishes (up to minutes) and an apply
 *    when the switch has started, so the page shows the work from its own flag and lets the next status end it.
 *  - Calls that change something need the owner with a passkey tap in the last 15 minutes. A refusal asks for the passkey once, reconnects so
 *    the socket carries it, and tries again; a second refusal is said in a sentence, and the window shows it (never a toast).
 *
 * The source is registered only once the first `status` was answered: a person who is not the owner is refused it, and then the window
 * keeps its "Not available yet" line.
 */
import { setUpdatesSource, ROLLBACK_HOURS, type Channel, type UpdateFacts, type UpdateHistoryEntry, type UpdateState, type UpdatesSource } from "./source";
import { lostSince } from "./words";

/** What the live source needs from the canvas: the action call, the topic subscription, and a fresh passkey sign-in. */
export interface UpdatesLink {
  call(actionId: string, input: Record<string, unknown>): Promise<Record<string, unknown>>;
  /** Subscribes to a topic of server events; `onOpen` runs after every (re)connect so the owner reads the state again. Returns the unsubscribe. */
  subscribe(filter: { topic: string }, onEvent: (event: Record<string, unknown>) => void, onOpen?: () => void): () => void;
  /** Signs in with a passkey (the server wants a recent one) and resolves once the connection carries it. */
  confirmAndReconnect(): Promise<void>;
}

/** What the server's `UpdateState` holds, as far as the window reads it (everything else is ignored). */
interface ServerState {
  current?: string; channel?: string; available?: string | null; staged?: string | null; last_check?: number | null; last_error?: string | null;
  applied?: { version?: string; outcome?: string; reason?: string | null; at?: number } | null;
  mode?: string; reason?: string | null; quiet_minutes?: number; rollback?: { to?: string; copy_taken_at?: number } | null;
}

/** The sentence for a refusal that carried none of its own. */
const SAID_NO = "Only the owner can do this, with a recent passkey sign-in.";

/** The text of a refusal: the server's own sentence when it sent one, else the plain fallback. */
function sentence(error: unknown): string {
  const reason = (error as { reason?: unknown } | undefined)?.reason;
  return typeof reason === "string" && reason ? reason : error instanceof Error && error.message ? error.message : SAID_NO;
}

/** Reads the server's state into what the window shows. `local` is this page's work in progress; Exported for the tests. */
export function stateOf(server: ServerState, local: "checking" | "applying" | undefined): UpdateState {
  if (server.mode === "off") return { kind: "off", reason: server.reason ?? "Automatic updates are not available on this server." };
  if (local === "checking") return { kind: "checking" };
  if (local === "applying") return { kind: "applying", version: server.staged ?? server.applied?.version ?? "", phase: "switching" };
  if (server.staged) return { kind: "ready", version: server.staged };
  const applied = server.applied;
  // The last switch was undone and no check has finished since: say so, with the server's reason.
  if (applied?.outcome === "undone" && applied.at !== undefined && applied.at >= (server.last_check ?? 0)) {
    return { kind: "rolled-back", version: applied.version ?? "", reason: `${applied.reason ?? "It did not pass its health check."} ${server.current ?? "The previous version"} is running again.` };
  }
  if (server.last_error) return { kind: "failed", reason: server.last_error };
  if (!server.last_check) return { kind: "never" };
  return { kind: "current" };
}

/** Reads the server's history into the window's lines: what was installed, undone or failed, newest first. Staged and removed entries are noise to the owner. */
export function historyOf(entries: unknown): UpdateHistoryEntry[] {
  if (!Array.isArray(entries)) return [];
  const out: UpdateHistoryEntry[] = [];
  for (const raw of entries) {
    const entry = raw as { at?: number; kind?: string; version?: string | null; detail?: string | null };
    const outcome = entry.kind === "applied" ? "applied" : entry.kind === "rolled_back" ? "rolled-back" : entry.kind === "failed" ? "failed" : undefined;
    if (!outcome || !entry.version || typeof entry.at !== "number") continue;
    out.push({ version: entry.version, from: undefined, outcome, at: entry.at * 1000, ...(entry.detail ? { reason: entry.detail } : {}) });
  }
  return out;
}

/** A live source over `link`, already holding the server's first answer. Rejects when that answer is refused (not the owner). */
export async function connectUpdates(link: UpdatesLink): Promise<UpdatesSource & { dispose(): void }> {
  let server: ServerState = await link.call("release.update.status", {}) as ServerState;
  let history: UpdateHistoryEntry[] = [];
  let local: "checking" | "applying" | undefined;
  let startedAt = 0;
  let runningAtStart = "";
  const listeners = new Set<() => void>();
  const emit = (): void => { for (const run of listeners) run(); };

  const take = (next: ServerState): void => {
    server = next;
    // An apply ends when the server answers with the new version running, or says the switch was undone or not applied.
    if (local === "applying" && ((next.applied?.at ?? 0) * 1000 >= startedAt || next.current !== runningAtStart)) local = undefined;
    emit();
  };
  const refresh = async (): Promise<void> => {
    const [status, past] = await Promise.all([link.call("release.update.status", {}), link.call("release.update.history", {}).catch(() => ({ entries: [] }))]);
    history = historyOf((past as { entries?: unknown }).entries);
    take(status as ServerState);
  };
  const stop = link.subscribe({ topic: "release.update" }, (event) => {
    if (typeof event.current === "string") take(event as ServerState); else void refresh().catch(() => undefined);
  }, () => { void refresh().catch(() => undefined); });
  history = historyOf(((await link.call("release.update.history", {}).catch(() => ({ entries: [] }))) as { entries?: unknown }).entries);

  /** Runs a call that changes something: on a refusal, asks for the passkey once and tries again; a second refusal is final. */
  const write = async (id: string, input: Record<string, unknown>): Promise<Record<string, unknown>> => {
    try { return await link.call(id, input); } catch { /* most often a sign-in older than 15 minutes: confirm once, below */ }
    try { await link.confirmAndReconnect(); return await link.call(id, input); } catch (error) { throw new Error(sentence(error)); }
  };

  return {
    facts(): UpdateFacts {
      const now = Date.now();
      const rb = server.rollback;
      const since = rb?.copy_taken_at !== undefined ? rb.copy_taken_at * 1000 : undefined;
      const running = server.current ?? "";
      return {
        state: stateOf(server, local),
        running,
        channel: server.channel === "edge" ? "edge" : "stable",
        quietMinutes: server.quiet_minutes ?? 5,
        checkedAt: server.last_check ? server.last_check * 1000 : undefined,
        history,
        // Past ROLLBACK_HOURS the plan is not offered at all, so the confirmation never has to word a loss of days.
        rollback: rb?.to && since !== undefined && now - since < ROLLBACK_HOURS * 3_600_000 ? { available: true, to: rb.to, lost: lostSince(running, since, now), since } : { available: false },
      };
    },
    async check() {
      local = "checking"; emit();
      try { await write("release.update.check", {}); } finally { local = undefined; }
      await refresh();
    },
    async apply() {
      startedAt = Date.now(); runningAtStart = server.current ?? ""; local = "applying"; emit();
      try { await write("release.update.apply", server.staged ? { version: server.staged } : {}); } catch (error) { local = undefined; emit(); throw error; }
      // The switch has started; the socket drops and returns, and the status read after that ends the work.
    },
    async rollback() {
      startedAt = Date.now(); runningAtStart = server.current ?? ""; local = "applying"; emit();
      try { await write("release.update.rollback", {}); } catch (error) { local = undefined; emit(); throw error; }
    },
    async setChannel(channel: Channel) { await write("release.channel.set", channel === "edge" ? { channel, confirmed: true } : { channel }); await refresh(); },
    async setQuietMinutes(minutes) { await write("release.update.settings", { quiet_minutes: Math.round(minutes) }); await refresh(); },
    onChange(run) { listeners.add(run); return () => { listeners.delete(run); }; },
    dispose() { stop(); listeners.clear(); setUpdatesSource(undefined); },
  };
}
