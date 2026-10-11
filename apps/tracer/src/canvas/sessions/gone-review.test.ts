/** Independent #158 review: a final session-gone record stays exited when another window selects it. */
import { expect, test } from "bun:test";
import { createLiveInventory } from "./live-inventory";

test("selecting a known gone session keeps its final exited state", () => {
  const prior = Object.getOwnPropertyDescriptor(globalThis, "window");
  let saved = "[]";
  Object.defineProperty(globalThis, "window", { configurable: true, value: { localStorage: {
    getItem: () => saved, setItem: (_key: string, value: string) => { saved = value; },
  } } });
  try {
    const inventory = createLiveInventory({ accountId: "gone-review", host: "server" });
    try {
      inventory.attach("server", "ended-session");
      inventory.gone("server", "ended-session");
      expect(inventory.get("server", "ended-session")?.state).toBe("exited");
      // Session manager/sidebar selection and restoring another window use attach.
      inventory.attach("server", "ended-session");
      expect(inventory.get("server", "ended-session")?.gone).toBe(true);
      expect(inventory.get("server", "ended-session")?.state).toBe("exited");
    } finally { inventory.dispose(); }
  } finally {
    if (prior) Object.defineProperty(globalThis, "window", prior);
    else Reflect.deleteProperty(globalThis, "window");
  }
});

test("a known retired status survives repeated selection and generic ended answers", () => {
  const prior = Object.getOwnPropertyDescriptor(globalThis, "window");
  Object.defineProperty(globalThis, "window", { configurable: true, value: { localStorage: { getItem: () => "[]", setItem: () => {} } } });
  const inventory = createLiveInventory({ accountId: "retired-status", host: "host" });
  inventory.attach("host", "retired");
  inventory.gone("host", "retired", 7);
  inventory.attach("host", "retired");
  inventory.gone("host", "retired");
  expect(inventory.get("host", "retired")?.exit?.code).toBe(7);
  expect(inventory.get("host", "retired")?.state).toBe("exited");
  inventory.dispose();
  if (prior) Object.defineProperty(globalThis, "window", prior);
  else Reflect.deleteProperty(globalThis, "window");
});
