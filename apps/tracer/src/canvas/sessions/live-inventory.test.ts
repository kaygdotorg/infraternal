/** Reproduces stale remembered rows and pins host reconciliation behavior. */
import { expect, test } from "bun:test";
import { createLiveInventory } from "./live-inventory";

test("a host snapshot replaces cached session rows and keeps only live shims", () => {
  const prior = Object.getOwnPropertyDescriptor(globalThis, "window");
  const staleIds = Array.from({ length: 40 }, (_, index) => `stale-${index}`);
  const liveIds = Array.from({ length: 16 }, (_, index) => `live-${index}`);
  let saved = JSON.stringify(staleIds.map((id, frecency) => ({ host: "server", id, name: `old-${frecency}`, pinned: false, frecency })));
  Object.defineProperty(globalThis, "window", { configurable: true, value: { localStorage: { getItem: () => saved, setItem: (_key: string, value: string) => { saved = value; } } } });
  try {
    const inventory = createLiveInventory({ accountId: "ended", host: "server" });
    expect(inventory.status()).toBe("loading");
    expect(inventory.list("server")).toEqual([]);
    expect(inventory.reconcile("server", liveIds).map((row) => row.id).sort()).toEqual(staleIds.sort());
    expect(inventory.status()).toBe("ready");
    expect(inventory.list("server").map((row) => row.id).sort()).toEqual([...liveIds].sort());
    expect(inventory.list("server").every((row) => row.state === "detached")).toBe(true);
    expect(inventory.get("server", staleIds[0]!)?.gone).toBe(true);
    expect(JSON.parse(saved).map((row: { id: string }) => row.id).sort()).toEqual([...liveIds].sort());
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

test("inventory remembers a remote session and refuses a cross-host attach", () => {
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
    expect(restored.list("worker").map((row) => row.id)).toEqual(["remote"]);
    expect(restored.get("worker", "remote")?.state).toBe("detached");
    inventory.dispose(); restored.dispose();
  } finally {
    if (prior) Object.defineProperty(globalThis, "window", prior);
    else Reflect.deleteProperty(globalThis, "window");
  }
});
