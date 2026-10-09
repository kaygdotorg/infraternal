/** Reads the product's current host, connection and session facts when the details popover is requested [188]. */
import type { MuxConnection } from "../../connection";
import type { DetailsSource } from "../windows/details-source";
import { detailsFacts } from "../windows/details-facts.on-demand";
import type { SessionInventory } from "./inventory";

export interface LiveDetailsOptions {
  host: { name: string; user?: string };
  connection: MuxConnection;
  inventory?: SessionInventory;
}

export function createLiveDetailsSource(options: LiveDetailsOptions, delay: () => number | undefined): DetailsSource {
  const { host, connection, inventory } = options;
  return {
    facts(rec) {
      if (rec.model.kind !== "terminal") return undefined;
      const record = rec.model.sessionId ? inventory?.get(rec.model.host, rec.model.sessionId) : undefined;
      const other = rec.model.sessionId ? inventory?.sizedFor(rec.model.host, rec.model.sessionId) : undefined;
      const delayMs = delay();
      return detailsFacts({
        host: { name: rec.model.host, ...(host.user ? { user: host.user } : {}), address: location.hostname, reach: "Directly, over this connection" },
        connection: { state: connection.isWelcomed ? "connected" : connection.isOpen ? "connecting" : "offline", ...(delayMs === undefined ? {} : { delayMs }), encrypted: location.protocol === "https:" },
        session: {
          name: rec.model.session ?? record?.name ?? "",
          ...(record?.age ? { lastUsed: record.age } : {}),
          ...(record?.running ? { lastCommand: record.running } : {}),
          ...(record?.size ? { size: record.size } : {}),
          ...(record ? { sizedBy: other ? other.name : "This device" } : {}),
        },
      });
    },
  };
}
