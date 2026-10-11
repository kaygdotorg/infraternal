/** Retained sessions stay with their host; legacy embedded records continue to load. */
import { expect, test } from "bun:test";
import { createLiveInventory } from "./live-inventory";

test("inventory remembers a remote session and refuses a cross-host attach", () => {
  const prior = Object.getOwnPropertyDescriptor(globalThis, "window");
  let saved = JSON.stringify([{ id: "legacy", name: "old", pinned: false, frecency: 1 }]);
  Object.defineProperty(globalThis, "window", { configurable: true, value: { localStorage: { getItem: () => saved, setItem: (_key: string, value: string) => { saved = value; } } } });
  try {
    const inventory = createLiveInventory({ accountId: "fixture", host: "server" });
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
