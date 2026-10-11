/**
 * The product's session inventory, until the host's shim can list its sessions (#100).
 *
 * The server has no "list sessions" message yet, so this inventory is what this browser knows: every session a
 * window of this account has shown, remembered per account in local storage. A session is open while a window
 * shows it and detached when its window closed (D178: closing never ends a session). It is honest about what it
 * cannot do: it cannot end a session, read a session's output or exit code, or know which device typed last, so
 * `can` leaves those verbs out and the manager does not draw them. Renaming works: the name is the window's
 * name, saved in the canvas document, and a rename pins it.
 *
 * The one end it does learn is final: when the server says the host no longer has a session (#158), the session
 * becomes exited and `gone` here, and it is no longer remembered, so a later load never offers it as running.
 *
 * When #100 lands the host's own inventory replaces this one behind the same interface; the manager, the
 * sidebar and the palette do not change.
 */
import type { DeviceInfo, InventoryCapabilities, InventoryStatus, SessionInventory, SessionRecord } from "./inventory";

interface Stored { host?: string; id: string; name: string; pinned: boolean; frecency: number }

export interface LiveInventory extends SessionInventory {
  /** The server answered that the host no longer has this session (#158): it becomes exited and `gone`. */
  gone(host: string, id: string, status?: number): void;
  dispose(): void;
}

export function createLiveInventory(options: { accountId: string; host: string }): LiveInventory {
  const key = `tracer.sessions.${options.accountId}`;
  const records = new Map<string, SessionRecord>();
  const listeners = new Set<() => void>();
  const owners = new Map<string, string>();
  let top = 0;
  const emit = (): void => { for (const l of listeners) l(); };
  const save = (): void => {
    const rows: Stored[] = [...records.values()].filter((s) => !s.gone).map((s) => ({ host: owners.get(s.id) ?? options.host, id: s.id, name: s.name, pinned: s.pinned, frecency: s.frecency }));
    try { window.localStorage.setItem(key, JSON.stringify(rows)); } catch { /* private mode: the inventory then lasts for this page */ }
  };
  const blank = (id: string, name: string): SessionRecord => ({ id, name, pinned: false, state: "detached", lastOutput: "", age: "", viewers: 0, size: "", frecency: 0, screen: [] });
  try {
    const rows = JSON.parse(window.localStorage.getItem(key) ?? "[]") as Stored[];
    for (const r of rows) if (typeof r.id === "string" && typeof r.name === "string") { owners.set(r.id, typeof r.host === "string" && r.host.length <= 200 ? r.host : options.host); records.set(r.id, { ...blank(r.id, r.name), pinned: Boolean(r.pinned), frecency: Number(r.frecency) || 0 }); top = Math.max(top, Number(r.frecency) || 0); }
  } catch { /* unreadable: start empty */ }

  const can: InventoryCapabilities = { rename: true, end: false, runAgain: false, dismiss: false };
  const only = (host: string, id: string): boolean => owners.get(id) === host;
  return {
    can,
    status: (): InventoryStatus => "ready",
    reload: async () => undefined,
    hosts: () => [...new Set([options.host, ...owners.values()])],
    list: (host) => [...records.values()].filter((record) => only(host, record.id)),
    get: (host, id) => (only(host, id) ? records.get(id) : undefined),
    attach(host, id, hint) {
      if (owners.has(id) && !only(host, id)) return;
      owners.set(id, host);
      let s = records.get(id);
      // Selecting a remembered session is not proof that the host can attach it.
      // The final gone state survives another window's selection (#158).
      if (s?.gone) return;
      if (!s) { s = blank(id, hint?.name ?? "shell"); records.set(id, s); }
      else if (hint?.name && !s.pinned) s.name = hint.name;
      if (s.state === "open") { if (hint?.name && s.name !== hint.name && !s.pinned) emit(); return; }
      s.state = "open";
      s.frecency = ++top;
      save();
      emit();
    },
    detach(host, id) {
      const s = only(host, id) ? records.get(id) : undefined;
      if (!s || s.state !== "open") return;
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
      if (s) { s.state = "exited"; s.gone = true; if (status !== undefined) s.exit = { code: status }; save(); emit(); }
    },
    sizedFor: (): DeviceInfo | undefined => undefined,
    takeOver() { /* every window of this account is this device until #99 */ },
    onChange(listener) { listeners.add(listener); return () => { listeners.delete(listener); }; },
    dispose() { listeners.clear(); },
  };
}
