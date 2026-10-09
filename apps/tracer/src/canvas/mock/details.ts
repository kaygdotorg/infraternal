/** Mockup details facts (#127): the fake hosts and the mock inventory, worded exactly like the product's. */
import type { DetailsSource } from "../windows/details-source";
import { detailsFacts } from "../windows/details-facts";
import type { SessionInventory } from "../sessions/inventory";
import type { MockWorld } from "./world";

const ADDRESS: Record<string, string> = { "build-01": "10.69.69.71", "edge-arm": "10.69.69.72", "nix-cache": "10.69.69.73", "studio-mac": "100.86.4.21" };
const REACH: Record<string, string> = { "edge-arm": "Through the relay fra-relay" };
const DELAY: Record<string, number> = { "build-01": 42, "edge-arm": 188, "nix-cache": 31, "studio-mac": 58 };

export function createMockDetails(world: MockWorld, inventory: SessionInventory): DetailsSource {
  return {
    facts(rec) {
      if (rec.model.kind !== "terminal") return undefined;
      const h = rec.model.host;
      const screen = world.screens.get(h);
      const record = rec.model.sessionId ? inventory.get(h, rec.model.sessionId) : undefined;
      const other = rec.model.sessionId ? inventory.sizedFor(h, rec.model.sessionId) : undefined;
      return detailsFacts({
        host: { name: h, user: rec.model.user ?? screen?.user ?? "kayg", os: rec.model.os ?? screen?.os ?? "unknown", address: ADDRESS[h] ?? "", reach: REACH[h] ?? "Directly" },
        connection: { state: "connected", delayMs: DELAY[h] ?? 40, encrypted: true },
        session: { name: rec.model.session ?? record?.name ?? "", started: "Today, 09:14", ...(record ? { lastUsed: record.age, size: record.size, sizedBy: other ? other.name : "This device" } : {}), ...(record?.running ? { lastCommand: record.running } : {}) },
      });
    },
  };
}
