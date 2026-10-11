/**
 * Mockup session inventory: the sessions of every host as the test double serves them (`/__mock/proto/sessions`),
 * kept in memory. Product code uses the host's real inventory (#99, #100) behind the same interface.
 *
 * Beyond the interface it has the knobs the scenes use: forcing the loading or error status, putting activity on
 * a detached session, saying that another device typed last, and putting everything back as served.
 */
import type { DeviceInfo, InventoryStatus, SessionActivity, SessionInventory, SessionRecord } from "../sessions/inventory";
import type { MockWorld } from "./world";

const URL_ = "/__mock/proto/sessions";

/** The session each host's first window shows in the mock world, and its fixture name. */
export const DEFAULT_SESSION: Record<string, string> = { "build-01": "deploy", "edge-arm": "apt-watch", "nix-cache": "flake-dev", "studio-mac": "release-notes" };

export interface MockInventory extends SessionInventory {
  /** Back to the inventory as served, with every state as fixtured. */
  reset(): void;
  /** Holds the status (a scene's loading or error state) until `release`. */
  force(status: InventoryStatus | undefined): void;
  setActivity(host: string, id: string, activity: SessionActivity | undefined): void;
  /** Says another device typed last in this session. */
  typedElsewhere(host: string, id: string, device: DeviceInfo | undefined): void;
  /** The account's other devices. */
  devices(): DeviceInfo[];
  dispose(): void;
}

export async function createMockInventory(world: MockWorld): Promise<MockInventory> {
  let pristine: Array<{ id: string; sessions: SessionRecord[] }> = [];
  let hosts = new Map<string, SessionRecord[]>();
  let devices: DeviceInfo[] = [];
  let loaded: InventoryStatus = "loading";
  let forced: InventoryStatus | undefined;
  const elsewhere = new Map<string, DeviceInfo>();
  const listeners = new Set<() => void>();
  const timers = new Set<number>();
  let shells = 0;
  let top = 0;
  const key = (host: string, id: string): string => `${host}/${id}`;
  const emit = (): void => { for (const l of listeners) l(); };
  const find = (host: string, id: string): SessionRecord | undefined => hosts.get(host)?.find((s) => s.id === id);

  const fill = (): void => {
    // An open session's screen is the host's own preview (the window already shows it); detached and exited ones carry theirs.
    hosts = new Map();
    for (const h of pristine) {
      if (h.id === "live") continue;
      const copy = structuredClone(h.sessions);
      for (const s of copy) if (!s.screen.length) s.screen = world.screens.get(h.id)?.screen ?? [];
      hosts.set(h.id, copy);
    }
    top = Math.max(0, ...[...hosts.values()].flat().map((s) => s.frecency));
    // `?shells=N` piles N more detached shells onto the first host: the long list the sidebar must scroll (test double only).
    const extra = Number(new URLSearchParams(location.search).get("shells")) || 0;
    const first = [...hosts.keys()][0];
    for (let i = 0; first && i < extra; i++) {
      hosts.get(first)!.push({ id: `shell-x${i + 1}`, name: "shell", pinned: false, state: "detached", lastOutput: "", age: "1h", viewers: 0, size: "", frecency: ++top, screen: [`kayg@${first}:~$ `] });
    }
  };
  const load = async (url: string, seed: boolean): Promise<boolean> => {
    try {
      const response = await fetch(url, { credentials: "same-origin" });
      if (!response.ok) return false;
      const data = (await response.json()) as { hosts?: typeof pristine; devices?: DeviceInfo[] };
      if (seed && data.hosts) { pristine = data.hosts; devices = data.devices ?? []; fill(); }
      return true;
    } catch { return false; }
  };
  loaded = (await load(URL_, true)) ? "ready" : "error";

  const inv: MockInventory = {
    status: () => forced ?? loaded,
    async reload() {
      forced = undefined;
      loaded = "loading"; emit();
      loaded = (await load(`${URL_}?delay=700`, hosts.size === 0)) ? "ready" : "error";
      forced = undefined;
      emit();
    },
    hosts: () => [...hosts.keys()],
    list: (host) => hosts.get(host) ?? [],
    get: find,
    attach(host, id) {
      const s = find(host, id);
      if (!s || s.state !== "detached") return;
      s.state = "open";
      delete s.activity;
      s.frecency = ++top;
      s.age = "now";
      emit();
    },
    detach(host, id) {
      const s = find(host, id);
      if (!s || s.state !== "open") return;
      s.state = "detached";
      s.age = "now";
      emit();
    },
    create(host) {
      const user = world.screens.get(host)?.user ?? "kayg";
      const s: SessionRecord = { id: `shell-${++shells}`, name: "shell", pinned: false, state: "detached", lastOutput: "", age: "now", viewers: 1, size: "", frecency: ++top, screen: [`${user}@${host}:~$ `] };
      hosts.set(host, [...(hosts.get(host) ?? []), s]);
      // The name follows the folder the shell moves to, until someone renames it.
      const timer = window.setTimeout(() => {
        timers.delete(timer);
        if (s.pinned || !find(host, s.id)) return;
        s.name = "infraternal";
        s.screen = [`${user}@${host}:~/src/infraternal$ `];
        emit();
      }, 2200);
      timers.add(timer);
      emit();
      return s;
    },
    rename(host, id, name) {
      const s = find(host, id);
      const next = name.trim();
      if (!s || !next || next === s.name) return;
      s.name = next;
      s.pinned = true;
      emit();
    },
    end(host, id) { hosts.set(host, (hosts.get(host) ?? []).filter((s) => s.id !== id)); elsewhere.delete(key(host, id)); emit(); },
    runAgain(host, id) {
      const s = find(host, id);
      if (!s || s.state !== "exited") return;
      const prompt = s.screen.at(0)?.split(" ")[0] ?? "$";
      s.state = "open";
      delete s.exit;
      s.frecency = ++top;
      s.screen = [...s.screen.slice(0, 1), "", `${prompt} _`];
      emit();
    },
    dismiss(host, id) { inv.end(host, id); },
    sizedFor: (host, id) => elsewhere.get(key(host, id)),
    takeOver(host, id) { if (elsewhere.delete(key(host, id))) emit(); },
    onChange(listener) { listeners.add(listener); return () => { listeners.delete(listener); }; },

    reset() {
      for (const t of timers) window.clearTimeout(t);
      timers.clear();
      forced = undefined;
      elsewhere.clear();
      fill();
      emit();
    },
    force(status) { forced = status; emit(); },
    setActivity(host, id, activity) {
      const s = find(host, id);
      if (!s) return;
      if (activity) s.activity = activity; else delete s.activity;
      emit();
    },
    typedElsewhere(host, id, device) { if (device) elsewhere.set(key(host, id), device); else elsewhere.delete(key(host, id)); emit(); },
    devices: () => devices,
    dispose() { for (const t of timers) window.clearTimeout(t); listeners.clear(); },
  };
  return inv;
}
