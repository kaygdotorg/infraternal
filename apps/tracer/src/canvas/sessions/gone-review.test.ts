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
