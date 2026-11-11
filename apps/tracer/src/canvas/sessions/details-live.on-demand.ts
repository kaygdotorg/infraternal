/** The product's details source (#127): reads live host, connection and session data after the popover is requested. */
import { ActionRefused, type MuxConnection } from "../../connection";
import { hostPlatformFromOs } from "../../../../../packages/ui/src/host-icons";
import type { DetailsSource, HostFactsSnapshot } from "../windows/details-source";
import { detailsFacts } from "../windows/details-facts";
import { readExtendedInfo } from "../windows/extended-info";
import type { WinRec } from "../context";
import type { SessionInventory } from "./inventory";

/**
 * Where a window's machine facts come from (#410): the server's own machine for a window on the server's host, the window's
 * own host (by its admitted id) for an added host, and nowhere for a window whose host cannot be read from here.
 */
function factsTarget(model: WinRec["model"], server: { name: string }): { kind: "server" } | { kind: "host"; hostId: string } | { kind: "none" } {
  if (model.hostId) return { kind: "host", hostId: model.hostId };
  return !model.noAccess && (model.host === server.name || model.host === "embedded") ? { kind: "server" } : { kind: "none" };
}

/** A cache/poll identity distinguishes the embedded host, each admitted UUID and unreadable hosts. */
function factsKey(target: ReturnType<typeof factsTarget>): string {
  return target.kind === "host" ? target.hostId : target.kind;
}

/**
 * Makes the details source for the popover: it reads the host's facts, the connection and the session when the popover is asked for, and keeps
 * the last snapshot of each window with its host identity. Retargeting invalidates old replies and restarts polling. Only terminal windows have facts.
 */
export function createLiveDetails(options: {
  host: { name: string; user?: string };
  connection: MuxConnection;
  inventory?: SessionInventory;
  roundTrip: () => number | undefined;
}): DetailsSource {
  const { host, connection, inventory, roundTrip } = options;
  const snapshots = new Map<string, HostFactsSnapshot>();
  // Snapshot, offline and throttle keys pair each window with the host identity that answered.
  const offline = new Set<string>();
  // Hosts whose facts the server refused for good: their rows stop waiting ("Reading…") and are simply left out.
  const refusedKeys = new Set<string>();
  const retarget = new Map<string, () => void>();
  const lastReadAt = new Map<string, number>();
  return {
    facts(rec) {
      if (rec.model.kind !== "terminal") return undefined;
      const record = rec.model.sessionId ? inventory?.get(rec.model.host, rec.model.sessionId) : undefined;
      const other = rec.model.sessionId ? inventory?.sizedFor(rec.model.host, rec.model.sessionId) : undefined;
      const delay = roundTrip();
      retarget.get(rec.model.id)?.();
      const target = factsTarget(rec.model, host);
      const cacheKey = `${rec.model.id}:${factsKey(target)}`;
      const facts = snapshots.get(cacheKey);
      const server = target.kind === "server";
      const gone = target.kind === "host" && !facts && offline.has(cacheKey);
      return detailsFacts({
        extended: readExtendedInfo(),
        // A readable host whose facts have not come back yet (and is not known to be offline) holds its rows' places.
        ...(target.kind !== "none" && !facts && !gone && !refusedKeys.has(cacheKey) ? { loading: true } : {}),
        host: {
          name: rec.model.host,
          // The server's login only describes the server's own windows; an added host names its own.
          ...(server ? (host.user ? { user: host.user } : {}) : rec.model.user ? { user: rec.model.user } : {}),
          ...(facts ? { os: hostPlatformFromOs(facts.os) } : !server && rec.model.os ? { os: rec.model.os } : {}),
          // The page's own hostname is the server's address; an added host is reached by the address it was added with.
          ...(server ? { address: location.hostname, reach: "Directly, over this connection" } : { ...(rec.model.address ? { address: rec.model.address } : {}), reach: "Through this server" }),
          ...(facts ? { facts } : server ? {} : { unavailable: gone ? "offline" as const : "pending" as const }),
        },
        connection: { state: gone ? "offline" : connection.isWelcomed ? "connected" : connection.isOpen ? "connecting" : "offline", ...(delay === undefined ? {} : { delayMs: delay }), encrypted: location.protocol === "https:" },
        session: {
          name: rec.model.session ?? record?.name ?? "",
          ...(record?.age ? { lastUsed: record.age } : {}),
          ...(record?.running ? { lastCommand: record.running } : {}),
          ...(record?.size ? { size: record.size } : {}),
          ...(record ? { sizedBy: other ? other.name : "This device" } : {}),
        },
      });
    },
    open(rec, refresh) {
      const id = rec.model.id;
      let key = factsKey(factsTarget(rec.model, host));
      let active = true;
      let inFlight = false;
      let refused = false;
      let generation = 0;
      let timer = 0;
      /** Polls the current host independently of an older host's outstanding reply. */
      const read = async (): Promise<void> => {
        if (!active) return;
        const target = factsTarget(rec.model, host);
        const next = factsKey(target);
        if (next !== key) {
          snapshots.delete(`${id}:${key}`);
          offline.delete(`${id}:${key}`);
          refusedKeys.delete(`${id}:${key}`);
          key = next;
          generation++;
          inFlight = false;
          refused = false;
          window.clearTimeout(timer);
          refresh();
        }
        if (target.kind === "none" || refused) return;
        // Schedule the next observation before awaiting: retargeting must not wait for the old host.
        window.clearTimeout(timer);
        timer = window.setTimeout(() => { void read(); }, 1_000);
        if (inFlight || !connection.isWelcomed) return;
        const readKey = `${id}:${key}`;
        const last = lastReadAt.get(readKey);
        const now = performance.now();
        if (last !== undefined && now - last < 1_000) return;
        for (const [identity, at] of lastReadAt) {
          if (now - at >= 1_000) lastReadAt.delete(identity);
        }
        if (lastReadAt.size >= 32 && !lastReadAt.has(readKey)) {
          const oldest = lastReadAt.keys().next().value;
          if (oldest !== undefined) lastReadAt.delete(oldest);
        }
        lastReadAt.set(readKey, now);
        inFlight = true;
        const started = generation;
        /** Late replies may affect only the same still-open host generation. */
        const current = (): boolean => active && started === generation && key === factsKey(factsTarget(rec.model, host));
        try {
          const result = target.kind === "host"
            ? await connection.call("remote.host.facts", { host_id: target.hostId })
            : await connection.call("host.facts.read", { includeLive: true });
          const snapshot = decodeHostFacts(result);
          if (snapshot && current()) {
            snapshots.set(readKey, snapshot);
            offline.delete(readKey);
            refresh();
          }
        } catch (error) {
          if (!current()) return;
          if (target.kind === "host" && error instanceof ActionRefused && error.reason === "host offline") {
            snapshots.delete(readKey);
            if (!offline.has(readKey)) { offline.add(readKey); refresh(); }
          } else if (error instanceof ActionRefused && error.reason !== "host busy") {
            // A permanent refusal stops this host's poll; retargeting can still start another host.
            refused = true;
            refusedKeys.add(readKey);
            window.clearTimeout(timer);
            refresh();
          }
          // Transport failures and admission backpressure retry on the next bounded poll.
        } finally {
          if (current()) inFlight = false;
        }
      };
      /** A render observes shared-layout retargets immediately, including after a permanent refusal. */
      const checkTarget = (): void => {
        if (key !== factsKey(factsTarget(rec.model, host))) void read();
      };
      retarget.set(id, checkTarget);
      void read();
      return () => {
        active = false;
        window.clearTimeout(timer);
        retarget.delete(id);
        snapshots.delete(`${id}:${key}`);
        offline.delete(`${id}:${key}`);
        refusedKeys.delete(`${id}:${key}`);
      };
    },
  };
}

/** Returns `value` if it is a non-empty string of at most 256 characters without control characters, else `undefined`. */
function shortText(value: unknown): string | undefined {
  return typeof value === "string"
    && value.length > 0
    && value.length <= 256
    && !/[\u0000-\u001f\u007f]/u.test(value)
    ? value
    : undefined;
}

/** Returns `value` if it is a finite number from 0 to `max`, else `undefined`. */
function boundedNumber(value: unknown, max = Number.MAX_SAFE_INTEGER): number | undefined {
  return typeof value === "number"
    && Number.isFinite(value)
    && value >= 0
    && value <= max
    ? value
    : undefined;
}

/** Reads a used/total pair of bytes. Returns `undefined` unless the total is above zero and the used amount is not larger than it. */
function capacity(value: unknown): HostFactsSnapshot["memory"] {
  if (!value || typeof value !== "object") return undefined;
  const row = value as Record<string, unknown>;
  const usedBytes = boundedNumber(row.usedBytes);
  const totalBytes = boundedNumber(row.totalBytes);
  if (usedBytes === undefined || totalBytes === undefined || totalBytes === 0 || usedBytes > totalBytes) {
    return undefined;
  }
  return { usedBytes, totalBytes };
}

/** Accept only the small, known shape returned by the host facts action. */
function decodeHostFacts(value: Record<string, unknown>): HostFactsSnapshot | undefined {
  const os = shortText(value.os);
  const version = typeof value.version === "string"
    && value.version.length <= 256
    && !/[\u0000-\u001f\u007f]/u.test(value.version)
    ? value.version
    : undefined;
  const kernel = shortText(value.kernel);
  const architecture = shortText(value.architecture);
  const logicalCpus = boundedNumber(value.logicalCpus, 4_096);
  const executionUid = boundedNumber(value.executionUid, 4_294_967_295);
  const mode = value.mode === "embedded" || value.mode === "remote" ? value.mode : undefined;
  if (
    !os
    || version === undefined
    || !kernel
    || !architecture
    || !logicalCpus
    || !Number.isInteger(logicalCpus)
    || executionUid === undefined
    || !Number.isInteger(executionUid)
    || !mode
  ) return undefined;

  const engines = Array.isArray(value.engines)
    && value.engines.length <= 2
    && value.engines.every((engine) => engine === "Docker" || engine === "Podman")
    ? value.engines as string[]
    : [];
  const load = value.loadAverage;
  const loadAverage = Array.isArray(load) && load.length === 3 ? load.map((item) => boundedNumber(item, 1_000_000)) : undefined;
  const model = shortText(value.model);
  const cpuModel = shortText(value.cpuModel);
  const memory = capacity(value.memory);
  const rootDisk = capacity(value.rootDisk);
  const uptimeSeconds = boundedNumber(value.uptimeSeconds);
  const init = shortText(value.init);
  const virtualization = shortText(value.virtualization);
  const shell = shortText(value.shell);
  const locale = shortText(value.locale);
  return {
    os,
    version,
    kernel,
    architecture,
    logicalCpus,
    executionUid,
    mode,
    engines,
    ...(model ? { model } : {}),
    ...(cpuModel ? { cpuModel } : {}),
    ...(memory ? { memory } : {}),
    ...(rootDisk ? { rootDisk } : {}),
    ...(uptimeSeconds !== undefined ? { uptimeSeconds } : {}),
    ...(loadAverage?.every((item): item is number => item !== undefined)
      ? { loadAverage: loadAverage as [number, number, number] }
      : {}),
    ...(init ? { init } : {}),
    ...(virtualization ? { virtualization } : {}),
    ...(shell ? { shell } : {}),
    ...(locale ? { locale } : {}),
  };
}
