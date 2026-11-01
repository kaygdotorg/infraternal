/** Reproduces stale remembered rows and pins host reconciliation behavior. */
import { expect, test } from "bun:test";
import { createLiveInventory } from "./live-inventory";
import type { CanvasDocument } from "../model/schema";

test("a shared manual name pins an existing record and survives later attach hints", () => {
  const inventory = createLiveInventory({ accountId: "rename-peer", host: "server" });
  inventory.reconcile("server", ["shared-session"]);
  const document: CanvasDocument = { format: "infraternal.canvas", version: 1, revision: 1, views: [{ id: "console", kind: "console", name: "Console", cell: { x: 0, y: 0 }, layout: { type: "tiled", columns: [{ id: "c", weight: 1, windows: [{ id: "w", target: { type: "session", host: "server", id: "shared-session", name: "manual name", pinned: true } }] }] } }] };
  inventory.setLayout(document);
  expect(inventory.get("server", "shared-session")?.pinned).toBe(true);
  inventory.attach("server", "shared-session", { name: "shell" });
  expect(inventory.get("server", "shared-session")?.name).toBe("manual name");
  inventory.dispose();
});

test("choosing the current automatic name still pins it", () => {
  const inventory = createLiveInventory({ accountId: "rename-current", host: "server" });
  inventory.reconcile("server", ["session"]);
  inventory.rename("server", "session", "shell");
  expect(inventory.get("server", "session")?.pinned).toBe(true);
  inventory.dispose();
});

test("a host snapshot replaces in-memory session rows without rewriting legacy storage", () => {
  const prior = Object.getOwnPropertyDescriptor(globalThis, "window");
  const staleIds = Array.from({ length: 40 }, (_, index) => `stale-${index}`);
  const liveIds = Array.from({ length: 16 }, (_, index) => `live-${index}`);
  let saved = JSON.stringify(staleIds.map((id, frecency) => ({ host: "server", id, name: `old-${frecency}`, pinned: false, frecency })));
  Object.defineProperty(globalThis, "window", { configurable: true, value: { localStorage: { getItem: () => saved, setItem: (_key: string, value: string) => { saved = value; } } } });
  try {
    const inventory = createLiveInventory({ accountId: "ended", host: "server" });
    expect(inventory.status()).toBe("loading");
    expect(inventory.list("server")).toEqual([]);
    inventory.reconcile("server", staleIds);
    expect(inventory.reconcile("server", liveIds).map((row) => row.id).sort()).toEqual(staleIds.sort());
    expect(inventory.status()).toBe("ready");
    expect(inventory.list("server").map((row) => row.id).sort()).toEqual([...liveIds].sort());
    expect(inventory.list("server").every((row) => row.state === "detached")).toBe(true);
    expect(inventory.get("server", staleIds[0]!)?.gone).toBe(true);
    expect(JSON.parse(saved).map((row: { id: string }) => row.id).sort()).toEqual([...staleIds].sort());
    inventory.gone("server", liveIds[0]!);
    expect(inventory.list("server").map((row) => row.id)).not.toContain(liveIds[0]);
    expect(JSON.parse(saved).map((row: { id: string }) => row.id)).not.toContain(liveIds[0]);
    const retired = inventory.reconcile("server", liveIds.slice(1), [{ id: liveIds[0]!, status: 7 }]);
    expect(retired).toEqual([{ id: liveIds[0]!, status: 7 }]);
    expect(inventory.get("server", liveIds[0]!)?.exit?.code).toBe(7);
    inventory.dispose();
  } finally {
    if (prior) Object.defineProperty(globalThis, "window", prior);
    else Reflect.deleteProperty(globalThis, "window");
  }
});

test("an unavailable agent hides remembered rows without ending them, then restores verified sessions", () => {
  const prior = Object.getOwnPropertyDescriptor(globalThis, "window");
  const liveId = "live-after-restart";
  let saved = JSON.stringify([{ host: "server", id: liveId, name: "kept name", pinned: true, frecency: 4 }]);
  Object.defineProperty(globalThis, "window", { configurable: true, value: { localStorage: { getItem: () => saved, setItem: (_key: string, value: string) => { saved = value; } } } });
  try {
    const inventory = createLiveInventory({ accountId: "restart", host: "server" });
    inventory.reconcile("server", [liveId]);
    inventory.rename("server", liveId, "kept name");
    inventory.unavailable("server");
    expect(inventory.status()).toBe("loading");
    expect(inventory.list("server")).toEqual([]);
    expect(inventory.get("server", liveId)?.gone).toBeUndefined();
    inventory.reconcile("server", [liveId]);
    expect(inventory.status()).toBe("ready");
    expect(inventory.list("server").map((row) => row.id)).toEqual([liveId]);
    expect(inventory.list("server")[0]?.name).toBe("kept name");
    expect(inventory.reconcile("server", [], [{ id: liveId, status: 0 }])).toEqual([{ id: liveId, status: 0 }]);
    expect(inventory.get("server", liveId)?.exit?.code).toBe(0);
    inventory.dispose();
  } finally {
    if (prior) Object.defineProperty(globalThis, "window", prior);
    else Reflect.deleteProperty(globalThis, "window");
  }
});

test("inventory keeps a remote session per tab and refuses a cross-host attach", () => {
  const prior = Object.getOwnPropertyDescriptor(globalThis, "window");
  let saved = JSON.stringify([
    { host: "server", id: "legacy", name: "old", pinned: false, frecency: 1 },
    { host: "worker", id: "remote", name: "remote shell", pinned: false, frecency: 2 },
  ]);
  Object.defineProperty(globalThis, "window", { configurable: true, value: { localStorage: { getItem: () => saved, setItem: (_key: string, value: string) => { saved = value; } } } });
  try {
    const inventory = createLiveInventory({ accountId: "fixture", host: "server" });
    expect(inventory.list("server")).toEqual([]);
    inventory.reconcile("server", ["legacy"]);
    expect(inventory.list("server").map((row) => row.id)).toEqual(["legacy"]);
    inventory.attach("worker", "remote");
    inventory.attach("server", "remote");
    expect(inventory.get("server", "remote")).toBeUndefined();
    inventory.detach("worker", "remote");
    const restored = createLiveInventory({ accountId: "fixture", host: "server" });
    expect(restored.list("worker")).toEqual([]);
    expect(restored.get("worker", "remote")).toBeUndefined();
    expect(inventory.get("worker", "remote")?.state).toBe("detached");
    inventory.dispose(); restored.dispose();
  } finally {
    if (prior) Object.defineProperty(globalThis, "window", prior);
    else Reflect.deleteProperty(globalThis, "window");
  }
});

test("superseded status snapshots release records for sessions this device never opened", () => {
  const inventory = createLiveInventory({ accountId: "status-cache-review", host: "server" });
  const statuses = (offset: number) => Array.from({ length: 128 }, (_, index) => ({
    id: `00000000-0000-4000-8000-${(offset + index + 1).toString(16).padStart(12, "0")}`,
    status: 7,
  }));
  const earlier = statuses(0), current = statuses(128);
  // Neither snapshot describes a window ever opened here. Replacing a bounded
  // sidecar must not accumulate inaccessible history in the device inventory.
  inventory.reconcile("server", [], earlier);
  inventory.reconcile("server", [], current);
  const retained = [...earlier, ...current].filter(({ id }) => inventory.get("server", id));
  expect(retained.length).toBeLessThanOrEqual(128);
  expect(inventory.get("server", current[0]!.id)?.exit?.code).toBe(7);
  inventory.dispose();
});


test("superseding a sidecar preserves status for a window opened on this device", () => {
  const inventory = createLiveInventory({ accountId: "opened-retention", host: "server" });
  inventory.attach("server", "opened");
  inventory.reconcile("server", [], [{ id: "opened", status: 7 }]);
  inventory.reconcile("server", [], [{ id: "unviewed", status: 9 }]);
  expect(inventory.get("server", "opened")?.exit?.code).toBe(7);
  expect(inventory.get("server", "opened")?.gone).toBe(true);
  inventory.dispose();
});

test("a census predating a new shell does not permanently retire its confirmed live ID", () => {
  const inventory = createLiveInventory({ accountId: "ordering-review", host: "server" });
  const id = "a23432f2-3875-4e12-867a-8943df233f1c";
  // Open Results have priority over census Events in the daemon writer. The
  // new shell can therefore be known before the pre-open census is consumed.
  inventory.attach("server", id);
  inventory.reconcile("server", []);
  inventory.reconcile("server", [id]);
  expect(inventory.get("server", id)?.gone).not.toBe(true);
  expect(inventory.list("server").map((row) => row.id)).toEqual([id]);
  inventory.dispose();
});

test("a final Close before the first positive census never revives a new ID", () => {
  const inventory = createLiveInventory({ accountId: "close-fence", host: "server" });
  inventory.attach("server", "new-id");
  inventory.gone("server", "new-id", 7);
  inventory.reconcile("server", ["new-id"]);
  expect(inventory.get("server", "new-id")?.gone).toBe(true);
  expect(inventory.get("server", "new-id")?.exit?.code).toBe(7);
  expect(inventory.list("server")).toEqual([]);
  inventory.dispose();
});

test("a later absence retires a new ID after its first positive census", () => {
  const inventory = createLiveInventory({ accountId: "confirmed-absence", host: "server" });
  inventory.attach("server", "new-id");
  expect(inventory.reconcile("server", [])).toEqual([]);
  inventory.reconcile("server", ["new-id"]);
  expect(inventory.reconcile("server", [])).toEqual([{ id: "new-id" }]);
  expect(inventory.get("server", "new-id")?.gone).toBe(true);
  inventory.dispose();
});

for (const event of ["census", "close"] as const) test(`another host's ${event} cannot clear a new shell's census fence`, () => {
  const inventory = createLiveInventory({ accountId: `host-fence-${event}`, host: "server" });
  inventory.attach("server", "new-id");
  if (event === "census") inventory.reconcile("worker", ["new-id"]);
  else inventory.gone("worker", "new-id");
  expect(inventory.reconcile("server", [])).toEqual([]);
  expect(inventory.get("server", "new-id")?.gone).not.toBe(true);
  inventory.dispose();
});

test("shared membership marks windows open without any local attachment", () => {
  const prior = Object.getOwnPropertyDescriptor(globalThis, "window");
  Object.defineProperty(globalThis, "window", { configurable: true, value: { localStorage: { getItem: () => "[]", setItem() {} } } });
  try {
    const inventory = createLiveInventory({ accountId: "shared", host: "server" });
    const document = { format: "infraternal.canvas" as const, version: 1 as const, revision: 10, views: [{ id: "console", kind: "console", name: "Console", cell: { x: 0, y: 0 }, layout: { type: "tiled" as const, columns: [{ id: "c", weight: 1, windows: [{ id: "w", target: { type: "session" as const, host: "server", id: "shared-session" } }] }] } }] };
    inventory.setLayout(document);
    inventory.reconcile("server", ["shared-session", "detached-session"]);
    expect(inventory.get("server", "shared-session")?.state).toBe("open");
    expect(inventory.get("server", "detached-session")?.state).toBe("detached");
    inventory.detach("server", "shared-session");
    expect(inventory.get("server", "shared-session")?.state).toBe("open");
    inventory.setLayout({ ...document, views: [] });
    expect(inventory.get("server", "shared-session")?.state).toBe("detached");
    inventory.dispose();
  } finally { if (prior) Object.defineProperty(globalThis, "window", prior); else Reflect.deleteProperty(globalThis, "window"); }
});
