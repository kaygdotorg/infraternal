/** The product's details source (#127): reads live host, connection and session data after the popover is requested. */
import { ActionRefused, type MuxConnection } from "../../connection";
import { hostPlatformFromOs } from "../../../../../packages/ui/src/host-icons";
import type { DetailsSource, HostFactsSnapshot } from "../windows/details-source";
import { detailsFacts } from "../windows/details-facts";
import { readExtendedInfo } from "../windows/extended-info";
import type { SessionInventory } from "./inventory";

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
  const lastReadAt = new Map<string, number>();
  return {
    facts(rec) {
      if (rec.model.kind !== "terminal") return undefined;
      const record = rec.model.sessionId ? inventory?.get(rec.model.host, rec.model.sessionId) : undefined;
      const other = rec.model.sessionId ? inventory?.sizedFor(rec.model.host, rec.model.sessionId) : undefined;
      const delay = roundTrip();
      const facts = snapshots.get(rec.model.id);
      return detailsFacts({
        extended: readExtendedInfo(),
        host: {
          name: rec.model.host,
          ...(host.user ? { user: host.user } : {}),
          ...(facts ? { os: hostPlatformFromOs(facts.os) } : {}),
          address: location.hostname,
          reach: "Directly, over this connection",
          ...(facts ? { facts } : {}),
        },
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
    open(rec, refresh) {
      const id = rec.model.id;
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
          const result = await connection.call("host.facts.read", { includeLive: true });
          const snapshot = decodeHostFacts(result);
          if (snapshot && active) {
            snapshots.set(id, snapshot);
            refresh();
          }
        } catch (error) {
          if (error instanceof ActionRefused) {
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
      return () => { active = false; window.clearTimeout(timer); snapshots.delete(id); };
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
