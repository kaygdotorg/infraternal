/**
 * Test double for `/v1/bootstrap/ws`, implementing `contracts/ssh-bootstrap.md` ("JSON shapes
 * for the UI") over the add-host fixtures: the same commands, event shapes and ordering the
 * real server speaks, so the UI can move to the real server without change.
 *
 * What is real here: command validation and error shapes, one batch per socket, a global
 * limit of eight active hosts with queueing across batches, global per-batch sequences,
 * per-attempt elapsed time that includes queue time, a 1024-event replay window with the
 * resync notice, retry limited to failed targets (eight attempts), cancellation on close.
 *
 * What is scripted (the double's only invention, all keyed on the fixture, never on the
 * client): per-host step timings are staggered; `unreachable` and `mesh-policy` fixtures
 * fail, and the `authentication: "refused"` fixture fails with `auth`. A retry or a fresh
 * attempt for a failed target succeeds, as if the person had fixed the cause.
 */
import type { IncomingMessage } from "node:http";
import type { WebSocket } from "ws";
import type { AddHostFixture } from "../src/add-host-contract";
import { addHostFixtures } from "./prototype-fixtures";

const MAX_COMMAND_BYTES = 32 * 1024;
const MAX_TARGETS = 100;
const MAX_ATTEMPTS = 8;
const MAX_ACTIVE = 8;
const RETAINED_EVENTS = 1024;
const IDENTIFIER = /^[A-Za-z0-9._-]{1,128}$/;

type Step = "check" | "install" | "facts" | "connect" | "done" | "failed";
type FailureKind = "unreachable" | "auth" | "mesh-policy" | "host-key" | "unsupported" | "install";
const PHASES = [
  { step: "check", message: "Checking the system" },
  { step: "install", message: "Installing the infraternal agent" },
  { step: "facts", message: "Gathering host facts" },
  { step: "connect", message: "Connecting" },
] as const;

interface BootstrapEvent {
  sequence: number;
  target: string;
  attempt: number;
  step: Step;
  message: string;
  elapsed_ms: number;
  log_tail: string[];
  failure?: { kind: FailureKind; message: string; log_tail: string[]; fingerprints?: string[] };
}

interface Target {
  id: string;
  fixture: AddHostFixture | undefined;
  mode: "rootless" | "root";
  attempt: number;
  state: "queued" | "active" | "done" | "failed";
  /** When this attempt entered the scheduler; elapsed_ms counts from here, queue time included. */
  enteredAt: number;
  breadcrumbs: string[];
  timers: Set<ReturnType<typeof setTimeout>>;
  /** True after a failed attempt: the next attempt succeeds. */
  fixed: boolean;
  order: number;
}

/** Active hosts across every batch; the contract limits this, not each socket. */
let active = 0;
const waiting: Array<() => void> = [];

function acquire(run: () => void): void {
  if (active < MAX_ACTIVE) { active += 1; run(); } else waiting.push(run);
}
function release(): void {
  const next = waiting.shift();
  if (next) next(); else active -= 1;
}

function fixtureFor(address: { kind: string; value: string }): AddHostFixture | undefined {
  if (address.kind === "discovered") return addHostFixtures.find((host) => host.id === address.value);
  const host = (/^(?:[^@]+@)?(\[[^\]]+\]|[^:]+)(?::\d+)?$/.exec(address.value) ?? [])[1];
  const known = addHostFixtures.find((item) => item.id === host || item.address === host);
  // Typed addresses in the 10.99 range stand for a host that never answers.
  if (!known && host?.startsWith("10.99.")) {
    return { id: host, user: "root", address: host, operatingSystem: "Linux", architecture: "unknown", sources: [], reachability: "unreachable", evidence: `connect ${host}:22: no response after 3 attempts (5 s each); no login was attempted`, alreadyAdded: false, rootAvailable: false, credentialRequired: false, authentication: "accepted" };
  }
  return known;
}

/** Scripted outcome of one attempt for a fixture: undefined succeeds. */
function outcomeOf(target: Target): { kind: FailureKind; message: string; evidence: string } | undefined {
  if (target.fixed) return undefined;
  const host = target.fixture;
  if (host?.reachability === "unreachable") return { kind: "unreachable", message: "No SSH answer on port 22", evidence: host.evidence };
  if (host?.reachability === "mesh-policy") return { kind: "mesh-policy", message: "Blocked by the mesh policy", evidence: host.evidence };
  if (host?.authentication === "refused") return { kind: "auth", message: "SSH key refused", evidence: "The host answered on port 22 and refused the SSH identity." };
  return undefined;
}

export function serveProvisioning(socket: WebSocket, _request: IncomingMessage): void {
  const targets = new Map<string, Target>();
  const events: BootstrapEvent[] = [];
  let sequence = 0;
  let started = false;
  let closed = false;

  const send = (value: unknown): void => { if (!closed && socket.readyState === socket.OPEN) socket.send(JSON.stringify(value)); };
  const refuse = (message: string): void => send({ error: { kind: "unsupported", message, log_tail: [] } });

  function emit(target: Target, step: Step, message: string, failure?: BootstrapEvent["failure"]): void {
    target.breadcrumbs = [...target.breadcrumbs, message].slice(-8);
    const event: BootstrapEvent = {
      sequence: ++sequence, target: target.id, attempt: target.attempt, step, message,
      elapsed_ms: Date.now() - target.enteredAt, log_tail: [...target.breadcrumbs],
    };
    if (failure) event.failure = failure;
    events.push(event);
    if (events.length > RETAINED_EVENTS) events.shift();
    send(event);
  }

  const later = (target: Target, ms: number, fn: () => void): void => {
    const timer = setTimeout(() => { target.timers.delete(timer); if (!closed) fn(); }, ms);
    target.timers.add(timer);
  };

  /** Staggered, host-dependent pace so a batch looks like separate machines. */
  const pace = (target: Target, phase: number): number => 420 + ((target.id.length * 97 + phase * 53) % 380);

  function schedule(target: Target): void {
    target.state = "queued";
    target.enteredAt = Date.now();
    target.breadcrumbs = [];
    // The first host starts almost at once; later ones stagger so rows do not move in lockstep.
    later(target, 140 + target.order * 110, () => acquire(() => begin(target)));
  }

  function begin(target: Target): void {
    if (closed) { release(); return; }
    target.state = "active";
    const outcome = outcomeOf(target);
    const walk = (phase: number): void => {
      if (phase >= PHASES.length) {
        emit(target, "done", target.mode === "root" ? "Ready · root" : "Ready");
        target.state = "done";
        release();
        return;
      }
      emit(target, PHASES[phase]!.step, PHASES[phase]!.message);
      // A failing host stops after its first phase, once the failure has had time to show.
      if (outcome) {
        later(target, pace(target, phase) + 400, () => {
          emit(target, "failed", outcome.message, { kind: outcome.kind, message: outcome.message, log_tail: [outcome.evidence] });
          target.state = "failed";
          target.fixed = true;
          release();
        });
        return;
      }
      later(target, pace(target, phase), () => walk(phase + 1));
    };
    walk(0);
  }

  function start(command: Record<string, unknown>): void {
    if (started) return refuse("A host batch is already running on this connection.");
    const list = command.targets;
    if (!Array.isArray(list) || list.length === 0 || list.length > MAX_TARGETS) return send({ error: "invalid bootstrap request" });
    const parsed: Target[] = [];
    for (const [index, item] of list.entries()) {
      const entry = item as Record<string, unknown> | null;
      const address = entry?.address as Record<string, unknown> | undefined;
      if (!entry || typeof entry.id !== "string" || !IDENTIFIER.test(entry.id) || parsed.some((target) => target.id === entry.id)
        || !address || (address.kind !== "manual" && address.kind !== "discovered") || typeof address.value !== "string" || !address.value) {
        return send({ error: "invalid bootstrap request" });
      }
      const mode = entry.mode === "root" ? "root" : "rootless";
      // Start validates every target before scheduling anything; root needs explicit consent.
      if (mode === "root" && entry.root_consent !== true) return refuse("Root access needs your explicit consent.");
      parsed.push({
        id: entry.id, fixture: fixtureFor({ kind: address.kind, value: address.value }), mode, attempt: 1, state: "queued",
        enteredAt: Date.now(), breadcrumbs: [], timers: new Set(), fixed: false, order: index,
      });
    }
    started = true;
    for (const target of parsed) { targets.set(target.id, target); schedule(target); }
  }

  function retry(command: Record<string, unknown>): void {
    if (!started) return refuse("Start a host batch first.");
    const target = typeof command.target === "string" ? targets.get(command.target) : undefined;
    if (!target) return refuse("That host is not in this batch.");
    if (target.state !== "failed") return refuse("Only a failed host can be retried.");
    if (target.attempt >= MAX_ATTEMPTS) return refuse("This host has used all its attempts.");
    target.attempt += 1;
    // A retry goes straight to the scheduler: no stagger, since the person is waiting on it.
    target.state = "queued";
    target.enteredAt = Date.now();
    target.breadcrumbs = [];
    acquire(() => begin(target));
  }

  function replay(command: Record<string, unknown>): void {
    if (!started) return refuse("Start a host batch first.");
    const after = command.after;
    if (typeof after !== "number" || !Number.isInteger(after) || after < 0) return send({ error: "invalid bootstrap request" });
    const oldest = events[0]?.sequence ?? sequence + 1;
    if (oldest > after + 1) send({ resync: true, oldest });
    for (const event of events) if (event.sequence > after) send(event);
  }

  socket.on("message", (raw, binary) => {
    const text = raw.toString();
    if (binary || Buffer.byteLength(text) > MAX_COMMAND_BYTES) return send({ error: "invalid bootstrap request" });
    let command: Record<string, unknown>;
    try {
      const value: unknown = JSON.parse(text);
      if (typeof value !== "object" || value === null || Array.isArray(value)) throw new Error("not an object");
      command = value as Record<string, unknown>;
    } catch { return send({ error: "invalid bootstrap request" }); }
    const known = { start: ["action", "targets", "credential"], retry: ["action", "target"], replay: ["action", "after"] } as const;
    const action = command.action;
    if (action !== "start" && action !== "retry" && action !== "replay") return send({ error: "invalid bootstrap request" });
    // Unknown fields are rejected, as the contract says.
    if (Object.keys(command).some((key) => !(known[action] as readonly string[]).includes(key))) return send({ error: "invalid bootstrap request" });
    if (action === "start") start(command); else if (action === "retry") retry(command); else replay(command);
  });

  // Disconnect cancels outstanding work; hosts that were running free their slot.
  socket.on("close", () => {
    closed = true;
    for (const target of targets.values()) {
      const wasRunning = target.state === "active" && target.timers.size > 0;
      for (const timer of target.timers) clearTimeout(timer);
      target.timers.clear();
      if (wasRunning) release();
    }
  });
}
