/** Synchronizes admitted terminal hosts from bounded account-scoped mux pages; storage never supplies admission. */
import { ensureHostMarks, hostPlatformFromOs } from "../../../../../packages/ui/src/host-icons";
import { ActionRefused } from "../../connection";
import { isCanonicalUuid } from "../../identifiers";
import type { HostEntry } from "./adapter";

/** The part of the connection the host list uses: calls, subscriptions and the welcome event. */
interface Transport {
  readonly isWelcomed?: boolean;
  call(action: string, input: Record<string, unknown>): Promise<Record<string, unknown>>;
  onWelcome(listener: () => void): () => void;
  subscribe(filter: { topic: string }, listener: (event: Record<string, unknown>) => void, onOpen?: () => void): () => void;
}
/** A host admitted to the account, with whether the infraternal agent on it is connected. */
type AdmittedHost = HostEntry & { address?: string; online: boolean };
/**
 * Checks one page of the host list from the server. Returns `undefined` for anything malformed (a bad shape, more than 128 hosts, a bad
 * id or name, a field over 1,024 characters, or a bad cursor), so one bad page never half-fills the list.
 */
function page(value: Record<string, unknown>): { hosts: AdmittedHost[]; next: string | null } | undefined {
  if (!Array.isArray(value.hosts) || value.hosts.length > 128 || !(value.next === null || isCanonicalUuid(value.next))) return;
  const hosts: AdmittedHost[] = [];
  for (const row of value.hosts) {
    if (!row || typeof row !== "object") return;
    const r = row as Record<string, unknown>;
    if (!isCanonicalUuid(r.id) || typeof r.name !== "string" || !r.name || r.name.length > 1024 || typeof r.online !== "boolean") return;
    for (const key of ["user", "os", "address"]) if (r[key] !== undefined && r[key] !== null && (typeof r[key] !== "string" || r[key].length > 1024)) return;
    if (r.state !== undefined && r.state !== "pending" && r.state !== "retired-unreachable") return;
    hosts.push({ ...(r.state ? { state: r.state as "pending" | "retired-unreachable" } : {}), id: r.id, name: r.name, online: r.online, ...(typeof r.user === "string" ? { user: r.user } : {}), ...(typeof r.os === "string" ? { os: hostPlatformFromOs(r.os) } : {}), ...(typeof r.address === "string" ? { address: r.address } : {}) });
  }
  return { hosts, next: value.next };
}
/** One list at a time; invalidations and welcomes fence in-flight pages before replacing anything. */
export function syncAdmittedHosts(connection: Transport, sink: { replaceHosts(hosts: AdmittedHost[]): void }): () => void {
  let disposed = false, running = false, version = 0;
  let offEvents: (() => void) | undefined;
  const refresh = (): void => {
    version++;
    if (!running) void load();
  };
  const connected = (): boolean => connection.isWelcomed !== false;
  const load = async (): Promise<void> => {
    if (disposed || !connected()) return;
    running = true;
    const started = version;
    try {
      const hosts: AdmittedHost[] = [], ids = new Set<string>();
      let after: string | null = null;
      do {
        if (!connected()) throw new Error("Not connected");
        const result = page(await connection.call("remote.host.list", after ? { after } : {}));
        if (disposed || started !== version) return;
        if (!result) throw new Error("Invalid host inventory");
        // Pages bound each mux reply, not the number of offline admissions in the account ledger (D214).
        for (const host of result.hosts) { if (ids.has(host.id)) throw new Error("Invalid host inventory"); ids.add(host.id); hosts.push(host); }
        if (result.next && (result.next === after || !ids.has(result.next) || !result.hosts.length)) throw new Error("Invalid host cursor");
        after = result.next;
      } while (after);
      // The marks start loading with the list but never hold it back (hosts matter more than their logos): a mark drawn
      // before its artwork arrives is the machine glyph and takes the real path in place (host-icons.ts).
      void ensureHostMarks(hosts.map((host) => host.os));
      sink.replaceHosts(hosts);
      // Older servers refuse the read; subscribing only after success avoids closing their socket.
      if (!offEvents) offEvents = connection.subscribe({ topic: "remote.hosts" }, (event) => {
        if (event.type === "changed") refresh();
        else if (event.type === "error") { sink.replaceHosts([]); version++; }
      }, refresh);
    } catch (error: unknown) {
      // A refused action withdraws authority; a network failure keeps the last complete snapshot for reconnect.
      if (!disposed && started === version && error instanceof ActionRefused) sink.replaceHosts([]);
    }
    finally { running = false; if (!disposed && started !== version) void load(); }
  };
  const offWelcome = connection.onWelcome(refresh);
  return () => { disposed = true; version++; offWelcome(); offEvents?.(); };
}
