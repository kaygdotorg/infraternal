/** The product's details source (#127): reads live host, connection and session data after the popover is requested. */
import type { MuxConnection } from "../../connection";
import type { DetailsSource } from "../windows/details-source";
import { detailsFacts } from "../windows/details-facts";
import type { SessionInventory } from "./inventory";

export function createLiveDetails(options: {
  host: { name: string; user?: string };
  connection: MuxConnection;
  inventory?: SessionInventory;
  roundTrip: () => number | undefined;
}): DetailsSource {
  const { host, connection, inventory, roundTrip } = options;
  return {
    facts(rec) {
      if (rec.model.kind !== "terminal") return undefined;
      const record = rec.model.sessionId ? inventory?.get(rec.model.host, rec.model.sessionId) : undefined;
      const other = rec.model.sessionId ? inventory?.sizedFor(rec.model.host, rec.model.sessionId) : undefined;
      const delay = roundTrip();
      return detailsFacts({
        host: { name: rec.model.host, ...(host.user ? { user: host.user } : {}), address: location.hostname, reach: "Directly, over this connection" },
        connection: { state: connection.isWelcomed ? "connected" : connection.isOpen ? "connecting" : "offline", ...(delay === undefined ? {} : { delayMs: delay }), encrypted: location.protocol === "https:" },
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
