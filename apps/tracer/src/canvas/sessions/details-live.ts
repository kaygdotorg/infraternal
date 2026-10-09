/** The product's details facts (#127): the host the person signed in to, this connection, and the window's session. */
import type { MuxConnection } from "../../connection";
import type { DetailsSource } from "../windows/details-source";
import { detailsFacts } from "../windows/details-facts";
import type { SessionInventory } from "./inventory";

export function createLiveDetails(options: { host: { name: string; user?: string }; connection: MuxConnection; inventory?: SessionInventory }): { source: DetailsSource; dispose(): void } {
  const { host, connection, inventory } = options;
  let delay: number | undefined;
  const off = connection.onRoundTrip((ms) => { delay = ms; });
  return {
    source: {
      facts(rec) {
        if (rec.model.kind !== "terminal") return undefined;
        const record = rec.model.sessionId ? inventory?.get(rec.model.host, rec.model.sessionId) : undefined;
        const other = rec.model.sessionId ? inventory?.sizedFor(rec.model.host, rec.model.sessionId) : undefined;
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
    },
    dispose: off,
  };
}
