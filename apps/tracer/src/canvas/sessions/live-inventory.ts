/**
 * The product's session inventory from the server's reconciled live-shim set (#168).
 *
 * The server pushes its account-filtered intersection of persisted rows and the infraternal agent's live shim
 * snapshot. Local storage keeps names and frecency only until that first snapshot; it never establishes liveness.
 * A session is open while a window of this account shows it and detached when its window closed (D178: closing never ends a session). It is honest about what it
 * cannot do: it cannot end a session, read a session's output or exit code, or know which device typed last, so
 * `can` leaves those verbs out and the manager does not draw them. Renaming works: the name is the window's
 * name, saved in the canvas document, and a rename pins it.
 *
 * After a new local session has appeared in a census, a complete host census is final for missing shims: absent rows become exited and `gone`, and are removed from
 * local storage so a later load never offers them as running. Its bounded exit-status sidecar keeps a saved code
 * on any matching open window. An unavailable host only hides rows; it does not end them before a fresh census.
 *
 * The full snapshot is replayed after every socket welcome, so missed changes during a disconnect cannot revive a
 * stale row. Ended records stay available to their existing window but disappear from every session list.
 */
import { documentWindows, type CanvasDocument } from "../model/schema";
import { createAccountNotifications } from "../../account-storage";
import type { DeviceInfo, InventoryCapabilities, InventoryStatus, SessionInventory, SessionRecord } from "./inventory";


export interface LiveInventory extends SessionInventory {
  /** The server answered that the host no longer has this session (#158): it becomes exited and `gone`. */
  gone(host: string, id: string, status?: number): void;
  /** Hide cached host rows while the agent cannot provide an authoritative inventory. */
  unavailable(host: string): void;
  /** Replace one host's cached rows with its full authoritative live-shim set. */
  /** Replaces a host's liveness set and reports newly ended IDs to open terminal streams. */
  reconcile(host: string, ids: readonly string[], ended?: readonly { id: string; status: number }[]): Array<{ id: string; status?: number }>;
  /** Shared layout membership, independent of this device's terminal attachments. */
  setLayout(document: CanvasDocument): void;
  dispose(): void;
}

export function createLiveInventory(options: { accountId: string; host: string }): LiveInventory {
  const records = new Map<string, SessionRecord>();
  const owners = new Map<string, string>();
  // Only windows opened on this device need status after its sidecar is superseded.
  const opened = new Set<string>();
  // A Result can overtake a pre-open census; only a positive census makes absence conclusive.
  const awaitingCensus = new Set<string>();
  const verifiedHosts = new Set<string>();
  let top = 0;
  let shared: Set<string> | undefined;
  const cache = createAccountNotifications();
  const save = (): void => {};
  const emit = cache.notify;
  const blank = (id: string, name: string): SessionRecord => ({ id, name, pinned: false, state: "detached", lastOutput: "", age: "", viewers: 0, size: "", frecency: 0, screen: [] });

  const can: InventoryCapabilities = { rename: true, end: false, runAgain: false, dismiss: false };
  const only = (host: string, id: string): boolean => owners.get(id) === host;
  return {
    can,
    setLayout(document) {
      const targets = documentWindows(document).flatMap((window) => window.target.type === "session" ? [window.target] : []);
      shared = new Set(targets.map((t) => t.id));
      let changed = false;
      for (const s of records.values()) if (!s.gone) {
        const state = shared.has(s.id) ? "open" : "detached";
        if (s.state !== state) { s.state = state; changed = true; }
      }
      for (const target of targets) {
        const record = records.get(target.id);
        if (record && target.name && target.name !== record.name) { record.name = target.name; changed = true; }
      }
      if (changed) emit();
    },
    status: (): InventoryStatus => verifiedHosts.has(options.host) ? "ready" : "loading",
    reload: async () => undefined,
    hosts: () => [...new Set([options.host, ...[...records.values()].filter((record) => !record.gone).map((record) => owners.get(record.id)).filter((host): host is string => Boolean(host))])],
    list: (host) => host === options.host && !verifiedHosts.has(host) ? [] : [...records.values()].filter((record) => only(host, record.id) && !record.gone),
    get: (host, id) => (only(host, id) ? records.get(id) : undefined),
    attach(host, id, hint) {
      if (owners.has(id) && !only(host, id)) return;
      owners.set(id, host);
      opened.add(id);
      let s = records.get(id);
      // Selecting a remembered session is not proof that the host can attach it.
      // The final gone state survives another window's selection (#158).
      if (s?.gone) return;
      if (!s) { s = blank(id, hint?.name ?? "shell"); records.set(id, s); awaitingCensus.add(id); }
      else if (hint?.name && !s.pinned) s.name = hint.name;
      if (s.state === "open") { if (hint?.name && s.name !== hint.name && !s.pinned) emit(); return; }
      s.state = shared && !shared.has(id) ? "detached" : "open";
      s.frecency = ++top;
      save();
      emit();
    },
    detach(host, id) {
      const s = only(host, id) ? records.get(id) : undefined;
      if (!s || s.state !== "open" || shared?.has(id)) return;
      s.state = "detached";
      save();
      emit();
    },
    rename(host, id, name) {
      const s = only(host, id) ? records.get(id) : undefined;
      const next = name.trim();
      if (!s || !next || next === s.name) return;
      s.name = next;
      s.pinned = true;
      save();
      emit();
    },
    end() { /* not offered: the shim cannot be asked yet (#100) */ },
    runAgain() { /* not offered */ },
    dismiss() { /* not offered: an ended session is forgotten at the next load (it is not saved) */ },
    // A final host answer stays exited even when another window selects the session.
    gone(host, id, status) {
      const s = only(host, id) && records.get(id);
      if (s && (!s.gone || (status !== undefined && s.exit?.code !== status))) {
        awaitingCensus.delete(id);
        s.state = "exited";
        s.gone = true;
        if (status !== undefined) s.exit = { code: status };
        save();
        emit();
      }
    },
    unavailable(host) {
      if (verifiedHosts.delete(host)) emit();
    },
    reconcile(host, ids, ended = []) {
      const live = new Set(ids);
      const statuses = new Map(ended.map(({ id, status }) => [id, status]));
      const retired = new Map<string, { id: string; status?: number }>();
      for (const record of records.values()) {
        if (only(host, record.id) && record.gone && !opened.has(record.id) && !statuses.has(record.id)) {
          records.delete(record.id);
          owners.delete(record.id);
        }
      }
      verifiedHosts.add(host);
      for (const record of records.values()) {
        if (only(host, record.id) && !live.has(record.id) && !record.gone && (!awaitingCensus.has(record.id) || statuses.has(record.id))) {
          awaitingCensus.delete(record.id);
          record.state = "exited";
          record.gone = true;
          const status = statuses.get(record.id);
          if (status !== undefined) record.exit = { code: status };
          retired.set(record.id, { id: record.id, ...(status === undefined ? {} : { status }) });
        }
      }
      for (const { id, status } of ended) {
        if (live.has(id) || (owners.has(id) && !only(host, id))) continue;
        owners.set(id, host);
        let record = records.get(id);
        if (!record) { record = blank(id, "shell"); records.set(id, record); }
        if (!record.gone || record.exit?.code !== status) {
          awaitingCensus.delete(record.id);
          record.state = "exited";
          record.gone = true;
          record.exit = { code: status };
          retired.set(id, { id, status });
        }
      }
      for (const id of live) {
        if (owners.has(id) && !only(host, id)) continue;
        awaitingCensus.delete(id);
        owners.set(id, host);
        let record = records.get(id);
        // A final close is monotonic: an older in-flight snapshot cannot revive it.
        if (record?.gone) continue;
        if (!record) { record = blank(id, "shell"); records.set(id, record); }
        if (shared) record.state = shared.has(id) ? "open" : "detached";
      }
      save();
      emit();
      return [...retired.values()];
    },
    sizedFor: (): DeviceInfo | undefined => undefined,
    takeOver() { /* every window of this account is this device until #99 */ },
    onChange: cache.subscribe,
    dispose: cache.dispose,
  };
}
