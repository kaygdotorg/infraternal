/** Test-only retained D255 setup events; host/session coordinates survive wizard closure and retries. */
import type { WebSocket } from "ws";

export type SetupStage = "install" | "join" | "start" | "ready";
export interface SetupEvent {
  host_id: string; session_id: string; attempt: number; sequence: number;
  stage: SetupStage; state: "running" | "done" | "failed"; retry_available: boolean;
  failed_step?: "install" | "join" | "start" | "readiness"; message?: string;
}
interface Host {
  session: string; attempt: number; sequence: number; events: SetupEvent[];
  current: Map<SetupStage, SetupEvent>; listeners: Set<() => void>; running: boolean;
}
const stages: readonly SetupStage[] = ["install", "join", "start", "ready"];
const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const hosts = new Map<string, Host>();

export function publishSetup(host: string, session: string): void {
  if (!uuid.test(host) || !uuid.test(session) || hosts.has(host) || hosts.size >= 10_000) throw new Error("invalid setup publication");
  hosts.set(host, { session, attempt: 1, sequence: 0, events: [], current: new Map(), listeners: new Set(), running: false });
}
export function setupEvents(host: string, windowId: string, after: number): { resync: boolean; events: Array<SetupEvent & { window_id: string }> } {
  const record = hosts.get(host);
  if (!record) throw new Error("setup unavailable");
  const resync = Boolean(record.events[0] && after + 1 < record.events[0].sequence);
  const events = resync ? [...record.current.values()].sort((a, b) => a.sequence - b.sequence) : record.events.filter((event) => event.sequence > after);
  return { resync, events: events.map((event) => ({ ...event, window_id: windowId })) };
}
export function emitSetup(host: string, stage: SetupStage, state: SetupEvent["state"]): void {
  const record = hosts.get(host);
  if (!record) throw new Error("setup unavailable");
  const event: SetupEvent = { host_id: host, session_id: record.session, attempt: record.attempt, sequence: ++record.sequence, stage, state, retry_available: state === "failed" && record.attempt < 8,
    ...(state === "failed" ? { failed_step: stage === "ready" ? "readiness" : stage, message: "Setup needs another try." } : {}) };
  record.events.push(event);
  if (record.events.length > 16) record.events.shift();
  record.current.set(stage, event);
  for (const listener of record.listeners) listener();
}
export function runSetup(host: string, failedStage?: SetupStage, complete?: () => void): void {
  const record = hosts.get(host);
  if (!record || record.running) throw new Error("setup busy");
  record.running = true;
  let index = 0;
  const next = (): void => {
    const stage = stages[index++];
    if (!stage) { record.running = false; complete?.(); return; }
    emitSetup(host, stage, "running");
    // Scripted functional fixture scheduling, never a performance measurement.
    setTimeout(() => {
      emitSetup(host, stage, stage === failedStage ? "failed" : "done");
      if (stage === failedStage) { record.running = false; complete?.(); } else next();
    }, 80);
  };
  next();
}

export function serveSetup(socket: WebSocket): void {
  let selected: string | undefined; let windowId = ""; let after = 0; let stop: (() => void) | undefined;
  const flush = (): void => {
    if (!selected || socket.readyState !== socket.OPEN) return;
    const replay = setupEvents(selected, windowId, after);
    if (replay.resync) socket.send(JSON.stringify({ resync: true, host_id: selected, window_id: windowId }));
    for (const event of replay.events) { socket.send(JSON.stringify({ setup: event })); after = event.sequence; }
  };
  socket.on("message", (bytes) => {
    try {
      if (bytes.toString().length > 4096) throw new Error("oversized request");
      const request: unknown = JSON.parse(bytes.toString());
      if (!request || typeof request !== "object") throw new Error("invalid request");
      const value = request as Record<string, unknown>;
      if (value.action === "subscribe" && !selected && typeof value.host_id === "string" && typeof value.window_id === "string" && /^[A-Za-z0-9._-]{1,128}$/.test(value.window_id)) {
        const record = hosts.get(value.host_id);
        if (!record) throw new Error("setup unavailable");
        selected = value.host_id; windowId = value.window_id; after = typeof value.after === "number" ? value.after : 0;
        record.listeners.add(flush); stop = () => record.listeners.delete(flush); flush();
      } else if (value.action === "replay" && selected && typeof value.after === "number") { after = value.after; flush(); }
      else if (value.action === "retry" && selected === value.host_id) {
        const record = hosts.get(selected!);
        if (!record || record.running || record.attempt >= 8 || ![...record.current.values()].some((event) => event.state === "failed")) throw new Error("retry refused");
        record.attempt++; record.current.clear(); runSetup(selected!);
      } else throw new Error("invalid setup request");
    } catch { socket.send(JSON.stringify({ error: "The host setup status is unavailable." })); }
  });
  socket.on("close", () => stop?.());
}
