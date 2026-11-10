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

/**
 * Makes the details source for the popover: it reads the host's facts, the connection and the session when the popover is asked for, and keeps
 * the last snapshot of each window. Only terminal windows have facts.
 */
export function createLiveDetails(options: {
  host: { name: string; user?: string };
  connection: MuxConnection;
  inventory?: SessionInventory;
  roundTrip: () => number | undefined;
}): DetailsSource {
  const { host, connection, inventory, roundTrip } = options;
  const snapshots = new Map<string, HostFactsSnapshot>();
  // Windows whose host answered "offline" on the last read; cleared by the next answer or when the popover closes.
  const offline = new Set<string>();
  const lastReadAt = new Map<string, number>();
  return {
    facts(rec) {
      if (rec.model.kind !== "terminal") return undefined;
      const record = rec.model.sessionId ? inventory?.get(rec.model.host, rec.model.sessionId) : undefined;
      const other = rec.model.sessionId ? inventory?.sizedFor(rec.model.host, rec.model.sessionId) : undefined;
      const delay = roundTrip();
      const facts = snapshots.get(rec.model.id);
      const target = factsTarget(rec.model, host);
      const server = target.kind === "server";
      const gone = target.kind === "host" && !facts && offline.has(rec.model.id);
      return detailsFacts({
        extended: readExtendedInfo(),
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
      const target = factsTarget(rec.model, host);
      // A window with no readable host has nothing to ask for; its panel says the facts are not known.
      if (target.kind === "none") return () => {};
      let active = true;
      let inFlight = false;
      let timer = 0;
      const read = async (): Promise<void> => {
        if (!active || inFlight) return;
        const last = lastReadAt.get(id);
        const remaining = last === undefined ? 0 : Math.max(0, 1_000 - (performance.now() - last));
        if (remaining > 0 || !connection.isWelcomed) {
          timer = window.setTimeout(() => { void read(); }, connection.isWelcomed ? remaining : Math.max(1_000, remaining));
          return;
        }
        const now = performance.now();
        for (const [windowId, at] of lastReadAt) {
          if (now - at >= 1_000) lastReadAt.delete(windowId);
        }
        if (lastReadAt.size >= 32 && !lastReadAt.has(id)) {
          const oldest = lastReadAt.keys().next().value;
          if (oldest !== undefined) lastReadAt.delete(oldest);
        }
        lastReadAt.set(id, now);
        inFlight = true;
        try {
          const result = target.kind === "host"
            ? await connection.call("remote.host.facts", { host_id: target.hostId })
            : await connection.call("host.facts.read", { includeLive: true });
          const snapshot = decodeHostFacts(result);
          if (snapshot && active) {
            snapshots.set(id, snapshot);
            offline.delete(id);
            refresh();
          }
        } catch (error) {
          if (target.kind === "host" && error instanceof ActionRefused && error.reason === "host offline") {
            // The machine is admitted but not connected: say so and keep reading, it may come back while the panel is open.
            snapshots.delete(id);
            if (active && !offline.has(id)) { offline.add(id); refresh(); }
          } else if (error instanceof ActionRefused) {
            // Refused actions will not recover by polling; reopening can retry after state changes.
            active = false;
          }
          // Transport failures remain eligible for the next bounded poll after reconnect.
        } finally {
          inFlight = false;
          if (active) timer = window.setTimeout(() => { void read(); }, 1_000);
        }
      };
      void read();
      return () => { active = false; window.clearTimeout(timer); snapshots.delete(id); offline.delete(id); };
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
