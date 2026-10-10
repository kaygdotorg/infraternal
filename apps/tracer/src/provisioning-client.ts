/**
 * Typed client for the host-provisioning API (`/v1/bootstrap/ws`), written against
 * `contracts/ssh-bootstrap.md` (branch `ssh-bootstrap`, section "JSON shapes for the UI").
 *
 * One `ProvisioningRun` is one WebSocket and therefore one batch: the contract allows a
 * single `start` per socket, `retry` only for failed targets of that batch, and cancels the
 * batch (with rollback) when the socket closes. Closing a run is thus a real action, not
 * cleanup: callers close it when the person abandons the flow.
 *
 * Invariants the UI relies on:
 * - Events reach the handler once each, in sequence order. Replays and duplicates are
 *   dropped by sequence, as the contract asks of clients.
 * - The client never invents progress. Everything shown comes from an event; there are no
 *   timers here. A target with no event yet is simply not started (queued behind the
 *   server's active-host limit).
 * - Human text is the server's (`message`, `failure.message`); the client never matches on it.
 * - Private sign-in inputs travel once on this authenticated socket; queued inputs are discarded on close.
 */

import { isCanonicalUuid } from "./identifiers";

export type BootstrapStep = "check" | "install" | "facts" | "connect" | "done" | "failed";
export type FailureKind = "unreachable" | "auth" | "mesh-policy" | "host-key" | "unsupported" | "install";
export type BootstrapMode = "rootless" | "root";

/** Phases a target passes through in order, before `done` (or `failed` at any point). */
export const PHASES = ["check", "install", "facts", "connect"] as const satisfies readonly BootstrapStep[];

export type TargetAddress =
  | { kind: "manual"; value: string }
  | { kind: "discovered"; value: string };

export interface StartTarget {
  /** Request-local id: 1-128 ASCII letters, digits, dots, underscores or hyphens. */
  id: string;
  address: TargetAddress;
  mode?: BootstrapMode;
  /** Must be true for `mode: "root"`; sudo availability never supplies it. */
  root_consent?: boolean;
  /** Opaque credential reference, overriding the batch reference. */
  credential?: string;
}

/** How the server signed in (D183). Public metadata only; a provider is named only from trusted discovery. */
export type AuthMethod = "network" | "server-key" | "user-key" | "password";
export type NetworkProvider = "netbird" | "tailscale" | "twingate" | "other";
export interface AuthenticationInfo { method: AuthMethod; network?: NetworkProvider }

export interface FailureDetail {
  kind: FailureKind;
  message: string;
  log_tail: string[];
  /** Observed SHA256 host-key fingerprints; untrusted, present only for `host-key`. */
  fingerprints?: string[];
  host_key_challenge?: string;
  /** Every automatic sign-in method was refused: the person must choose one (D183). Only on `auth`. */
  choose_method?: boolean;
}

export interface BootstrapEvent {
  sequence: number;
  target: string;
  attempt: number;
  step: BootstrapStep;
  message: string;
  /** Cumulative since this attempt entered the scheduler, queue time included. */
  elapsed_ms: number;
  /** At most eight trusted breadcrumbs, not a shell log. */
  log_tail: string[];
  failure?: FailureDetail;
  /** Present on the event that reports a successful sign-in. */
  authentication?: AuthenticationInfo;
  /** The server-owned admitted host UUID, present only after successful installation. */
  host_id?: string;
}

/** A refused command (`{"error":{...}}`) or malformed request (`{"error":"..."}`). No attempt is created. */
export interface CommandError {
  kind: FailureKind | "request";
  message: string;
  log_tail: string[];
}

export interface ProvisioningHandlers {
  onEvent(event: BootstrapEvent): void;
  /** History fell behind: `oldest` is the first retained sequence. Retained events follow. */
  onResync?(oldest: number): void;
  onError?(error: CommandError): void;
  /** The socket ended. The server has cancelled any outstanding work in this batch. */
  onClose?(): void;
}

export interface ProvisioningOptions {
  /** Defaults to `/v1/bootstrap/ws` on the page's origin. */
  url?: string;
  /** Opaque batch credential reference, applying where a target has none. */
  credential?: string;
  /** Consumes a local, target-bound secret immediately before serializing a start. */
  takeAuth?: (target: StartTarget) => OneUseAuth | undefined;
}

/** Transient inputs accepted by the existing SSH bootstrap socket, never by an HTTP credential store. */
export interface OneUseAuth { key?: string; passphrase?: string; password?: string }

const IDENTIFIER = /^[A-Za-z0-9._-]{1,128}$/;
const STEPS: readonly string[] = ["check", "install", "facts", "connect", "done", "failed"];
const KINDS: readonly string[] = ["unreachable", "auth", "mesh-policy", "host-key", "unsupported", "install"];

/** Turns a host label into a valid request-local id (`[A-Za-z0-9._-]{1,128}`). */
export function targetIdFor(label: string): string {
  const id = label.replace(/[^A-Za-z0-9._-]/g, "_").slice(0, 128);
  return id || "host";
}

export function bootstrapUrl(): string {
  const scheme = location.protocol === "https:" ? "wss" : "ws";
  return `${scheme}://${location.host}/v1/bootstrap/ws`;
}

const isRecord = (value: unknown): value is Record<string, unknown> => typeof value === "object" && value !== null && !Array.isArray(value);
const isStrings = (value: unknown): value is string[] => Array.isArray(value) && value.every((item) => typeof item === "string");

function parseFailure(value: unknown): FailureDetail | undefined {
  if (!isRecord(value) || typeof value.kind !== "string" || !KINDS.includes(value.kind) || typeof value.message !== "string") return undefined;
  const failure: FailureDetail = { kind: value.kind as FailureKind, message: value.message, log_tail: isStrings(value.log_tail) ? value.log_tail : [] };
  if (isStrings(value.fingerprints) && value.fingerprints.length) failure.fingerprints = value.fingerprints;
  if (typeof value.host_key_challenge === "string") failure.host_key_challenge = value.host_key_challenge;
  if (value.choose_method === true && value.kind === "auth") failure.choose_method = true;
  return failure;
}

const METHODS: readonly string[] = ["network", "server-key", "user-key", "password"];
const PROVIDERS: readonly string[] = ["netbird", "tailscale", "twingate", "other"];

function parseAuthentication(value: unknown): AuthenticationInfo | undefined {
  if (!isRecord(value) || typeof value.method !== "string" || !METHODS.includes(value.method)) return undefined;
  const info: AuthenticationInfo = { method: value.method as AuthMethod };
  if (typeof value.network === "string" && PROVIDERS.includes(value.network)) info.network = value.network as NetworkProvider;
  return info;
}

function parseEvent(value: Record<string, unknown>): BootstrapEvent | undefined {
  const { sequence, target, attempt, step, message, elapsed_ms: elapsed } = value;
  if (typeof sequence !== "number" || typeof target !== "string" || typeof attempt !== "number" || typeof step !== "string" || !STEPS.includes(step)
    || typeof message !== "string" || typeof elapsed !== "number") return undefined;
  const event: BootstrapEvent = { sequence, target, attempt, step: step as BootstrapStep, message, elapsed_ms: elapsed, log_tail: isStrings(value.log_tail) ? value.log_tail : [] };
  if (value.step === "done" && isCanonicalUuid(value.host_id)) event.host_id = value.host_id;
  const failure = parseFailure(value.failure);
  if (failure) event.failure = failure;
  const authentication = parseAuthentication(value.authentication);
  if (authentication) event.authentication = authentication;
  return event;
}

/** One batch of hosts over one socket. */
export class ProvisioningRun {
  private readonly socket: WebSocket;
  private readonly queue: string[] = [];
  private last = 0;
  private ended = false;
  private confirmation: { target: string; fingerprint: string; resolve: () => void; reject: () => void; timer: ReturnType<typeof setTimeout> } | undefined;

  constructor(private readonly handlers: ProvisioningHandlers, private readonly options: ProvisioningOptions = {}) {
    this.socket = new WebSocket(options.url ?? bootstrapUrl());
    this.socket.addEventListener("open", () => { if (!this.ended) for (const text of this.queue.splice(0)) this.socket.send(text); });
    this.socket.addEventListener("message", (message) => { if (typeof message.data === "string") this.receive(message.data); });
    this.socket.addEventListener("close", () => this.end());
    this.socket.addEventListener("error", () => this.end());
  }

  /** Highest event sequence delivered so far; pass it to `replay` to catch up. */
  get lastSequence(): number { return this.last; }
  get open(): boolean { return !this.ended; }

  /** Admits the batch (up to 100 targets). Valid once per run; the server rejects a second start. */
  start(targets: StartTarget[]): void {
    for (const target of targets) if (!IDENTIFIER.test(target.id)) throw new Error(`invalid target id: ${target.id}`);
    const command: Record<string, unknown> = { action: "start", targets };
    const auth = targets.map((target) => ({ target: target.id, auth: this.options.takeAuth?.(target) })).filter((entry) => entry.auth);
    if (auth.length) {
      command.targets = targets.map(({ credential: _credential, ...target }) => target);
      command.auth_once = auth;
    } else if (this.options.credential) command.credential = this.options.credential;
    this.send(command);
  }

  /** Retries a failed target of this batch under the same address; the server starts the next attempt. */
  retry(target: string): void { this.send({ action: "retry", target }); }

  /** Asks for retained events after a sequence. Defaults to what this client has already seen. */
  replay(after: number = this.last): void { this.send({ action: "replay", after }); }

  /** Resolves only after the server confirms this batch's exact observed key. */
  confirmHostKey(target: string, challenge: string, fingerprint: string): Promise<void> {
    if (this.ended || this.confirmation) return Promise.reject(new Error("Host-key confirmation is unavailable."));
    return new Promise((resolve, reject) => {
      const fail = (): void => { this.confirmation = undefined; reject(new Error("The host key could not be confirmed. Try again.")); };
      this.confirmation = { target, fingerprint, resolve, reject: fail, timer: setTimeout(fail, 5000) };
      this.send({ action: "confirm-host-key", target, challenge, fingerprint });
    });
  }

  /** Ends the batch. The server cancels outstanding work and rolls back. */
  close(): void {
    this.end();
    if (this.socket.readyState === WebSocket.OPEN || this.socket.readyState === WebSocket.CONNECTING) this.socket.close(1000);
  }

  private send(command: Record<string, unknown>): void {
    if (this.ended) return;
    const text = JSON.stringify(command);
    if (new TextEncoder().encode(text).length > 32768) throw new Error("The sign-in input is too large. Use a smaller key or one host at a time.");
    if (this.socket.readyState === WebSocket.CONNECTING) {
      if (this.queue.length >= 8) throw new Error("The connection is busy. Wait for it to open.");
      this.queue.push(text);
    }
    else if (this.socket.readyState === WebSocket.OPEN) this.socket.send(text);
  }

  private end(): void {
    if (this.ended) return;
    this.ended = true;
    this.queue.length = 0;
    if (this.confirmation) { clearTimeout(this.confirmation.timer); this.confirmation.reject(); }
    this.handlers.onClose?.();
  }

  private receive(text: string): void {
    if (this.ended) return;
    let value: unknown;
    try { value = JSON.parse(text); } catch { return; }
    if (!isRecord(value)) return;
    const confirmed = value.host_key_confirmed;
    if (isRecord(confirmed) && this.confirmation && confirmed.target === this.confirmation.target && confirmed.fingerprint === this.confirmation.fingerprint) {
      const pending = this.confirmation;
      this.confirmation = undefined;
      clearTimeout(pending.timer);
      pending.resolve();
      return;
    }
    if ("error" in value) {
      if (this.confirmation) { clearTimeout(this.confirmation.timer); this.confirmation.reject(); }
      const error = value.error;
      if (typeof error === "string") this.handlers.onError?.({ kind: "request", message: error, log_tail: [] });
      else {
        const failure = parseFailure(error);
        if (failure) this.handlers.onError?.(failure);
      }
      return;
    }
    if (value.resync === true && typeof value.oldest === "number") { this.handlers.onResync?.(value.oldest); return; }
    const event = parseEvent(value);
    // Replays repeat events the screen already shows; sequence is the identity.
    if (!event || event.sequence <= this.last) return;
    this.last = event.sequence;
    this.handlers.onEvent(event);
  }
}

/** What a screen needs to draw one target, folded from its events. */
export interface TargetView {
  state: "pending" | "running" | "done" | "failed";
  hostId?: string;
  attempt: number;
  /** Index into `PHASES` of the latest phase entered (a failure keeps the phase it happened in). */
  phase: number;
  /** The server's human text for the latest event. */
  message: string;
  failure: FailureDetail | undefined;
  elapsedMs: number;
  /** How this attempt signed in, once the server reported it. */
  authentication: AuthenticationInfo | undefined;
}

export const pendingTarget = (): TargetView => ({ state: "pending", attempt: 0, phase: 0, message: "", failure: undefined, elapsedMs: 0, authentication: undefined });

/** Folds one event into a target's view; events of an older attempt are ignored. */
export function foldEvent(view: TargetView, event: BootstrapEvent): TargetView {
  if (event.attempt < view.attempt) return view;
  const fresh = event.attempt > view.attempt;
  const phase = (PHASES as readonly string[]).indexOf(event.step);
  // The sign-in method sticks for the attempt, so a later failure still knows it got past authentication.
  const base: TargetView = { ...(fresh ? { ...pendingTarget(), attempt: event.attempt } : view) };
  if (event.authentication) base.authentication = event.authentication;
  if (event.step === "done") return { ...base, ...(isCanonicalUuid(event.host_id) ? { hostId: event.host_id } : {}), state: "done", phase: PHASES.length, message: event.message, failure: undefined, elapsedMs: event.elapsed_ms };
  if (event.step === "failed") return { ...base, state: "failed", message: event.message, failure: event.failure, elapsedMs: event.elapsed_ms };
  // Rollback and warnings may emit extra install events; the phase never moves backwards.
  return { ...base, state: "running", phase: Math.max(base.phase, phase), message: event.message, failure: undefined, elapsedMs: event.elapsed_ms };
}
