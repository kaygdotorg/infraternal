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
/** Public failure categories from the server (contracts/ssh-bootstrap.md); the page for each lives in addhost/model.ts. */
export type FailureKind = "unreachable" | "auth" | "mesh-policy" | "host-key" | "unsupported" | "install" | "stale_previous_attempt" | "setup_running" | "unrecognized_install" | "unproven_files" | "no_account";
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

/** A failed or paused step as the server describes it: the public failure fields the add-host pages read. */
/**
 * One open terminal of an old install that confirming Take over closes (D368, #433): the account and
 * foreground program, when it opened (Unix seconds), its `pts/<n>` when the host knows it, and how many
 * other programs (its shell, background jobs) run in it and close with it.
 */
export interface TakeoverTerminal { account: string; program: string; since: number; tty?: string; others?: number }

/** Why one host's setup stopped, as the server sent it: only fields the decoder validated survive (#87, D359, D368). */
export interface FailureDetail {
  kind: FailureKind;
  message: string;
  log_tail: string[];
  /** The host command's byte-sized exit status, used to explain Take over failures (#433). */
  exit_status?: number;
  /** Validated host-local setup lease coordinates for lock and interrupted-upgrade guidance. */
  setup_lock?: {
    machine: string; pid?: number; since: string; active: boolean;
    /** The holding setup attempt's first id characters (#305). */
    attempt?: string;
    /** Open terminal sessions that replacing the stuck install ends (#305). */
    sessions?: number;
    /** The other server the stuck install is enrolled with ("" when unnamed); joining makes a new host (D335). */
    enrolled_with?: string;
    /** An earlier add-host set this install aside and did not put it back (#305). */
    set_aside?: boolean;
    /** The stuck install's infraternal agent is running and may be connected to its other server now (#305). */
    live?: boolean;
    /** Another server's install runs with open terminals and may be in use there: refused, not offered (D337). */
    in_use?: boolean;
  };
  /** Which staging check refused, only on `unproven_files`, when the host named it (#394). */
  refusal?: "cache" | "prepared" | "foreign";
  /**
   * A finished install of another server that a root-mode add may take over (D359), only on
   * `unrecognized_install`: the old install's id (32 lowercase hex characters), which the
   * confirmation names, and whether its infraternal agent is running (Take over stops it).
   */
  takeover?: { install: string; live: boolean; terminals?: TakeoverTerminal[]; close_challenge?: string };
  /**
   * `stale_previous_attempt`: the stuck first install's own open terminals that Start fresh closes, and the
   * challenge only a confirmation that lists them may send (D368, #433).
   */
  closes?: { terminals: TakeoverTerminal[]; close_challenge: string };
  /** Observed SHA256 host-key fingerprints; untrusted, present only for `host-key`. */
  fingerprints?: string[];
  host_key_challenge?: string;
  already_added?: boolean;
  /** Existing host matched by an owner-scoped duplicate check; only on `already_added`. */
  host_id?: string;
  missing_binary?: { architecture: string; path: string };
  failed_step?: "get-arm64-binary" | "get-x86-64-binary" | "connect" | "upload" | "install" | "join" | "start" | "readiness";
  host_key_type?: string;
  host_key_changed?: boolean;
  /** Every automatic sign-in method was refused: the person must choose one (D183). Only on `auth`. */
  choose_method?: boolean;
}

/**
 * What an earlier, interrupted setup left on a host (`failure.kind` is `stale_previous_attempt`). `challenge` is the
 * one-use handle `start-fresh` must echo; `findings` are short public sentences, never paths or raw server text.
 */
export interface Leftovers { challenge: string; mode: BootstrapMode; findings: string[] }

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
  /** Present with a `stale_previous_attempt` failure. */
  leftovers?: Leftovers;
  /** Present on the event that reports a successful sign-in. */
  authentication?: AuthenticationInfo;
  /** The server-owned admitted host UUID, present only after successful installation. */
  host_id?: string;
  /** Existing shim-owned session published before background setup finishes (D255). */
  session_id?: string;
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
/** Every failure kind the server may send; anything else is dropped rather than shown (see {@link FailureKind}). */
const KINDS: readonly string[] = ["unreachable", "auth", "mesh-policy", "host-key", "unsupported", "install", "stale_previous_attempt", "setup_running", "unrecognized_install", "unproven_files", "no_account"];

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

function parseSetupLock(value: unknown): FailureDetail["setup_lock"] | undefined {
  if (!isRecord(value)
    || typeof value.machine !== "string"
    || !/^[A-Za-z0-9][A-Za-z0-9._-]{0,252}$/.test(value.machine)
    || typeof value.since !== "string"
    || !(value.since === "unknown" || /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(value.since))
    || typeof value.active !== "boolean"
    || (value.pid !== undefined && value.pid !== null
      && (typeof value.pid !== "number" || !Number.isSafeInteger(value.pid) || value.pid < 1 || value.pid > 0xffff_ffff))) {
    return undefined;
  }
  const lock: NonNullable<FailureDetail["setup_lock"]> = {
    machine: value.machine,
    since: value.since,
    active: value.active,
  };
  if (typeof value.pid === "number") lock.pid = value.pid;
  if (typeof value.attempt === "string" && /^[0-9a-f]{8}$/.test(value.attempt)) lock.attempt = value.attempt;
  if (typeof value.sessions === "number" && Number.isSafeInteger(value.sessions) && value.sessions >= 0 && value.sessions <= 1024) lock.sessions = value.sessions;
  if (typeof value.enrolled_with === "string" && (value.enrolled_with === "" || /^[A-Za-z0-9][A-Za-z0-9._-]{0,252}$/.test(value.enrolled_with))) lock.enrolled_with = value.enrolled_with;
  if (value.set_aside === true) lock.set_aside = true;
  if (value.live === true) lock.live = true;
  if (value.in_use === true) lock.in_use = true;
  return lock;
}

/** Keeps only the known, well-formed fields of a server failure; anything else is dropped, never shown. */
/** Whether `value` is a bounded list of well-formed terminal rows a confirmation may show (D368). */
function areTerminals(value: unknown): value is TakeoverTerminal[] {
  return Array.isArray(value) && value.length <= 1024 && value.every((terminal: unknown) => isRecord(terminal)
    && typeof terminal.account === "string" && terminal.account.length > 0 && terminal.account.length <= 64 && !/[\u0000-\u001f\u007f-\u009f]/.test(terminal.account)
    && typeof terminal.program === "string" && terminal.program.length > 0 && terminal.program.length <= 64 && !/[\u0000-\u001f\u007f-\u009f]/.test(terminal.program)
    && typeof terminal.since === "number" && Number.isSafeInteger(terminal.since) && terminal.since > 0 && terminal.since <= 253402300799
    && (terminal.tty === undefined || (typeof terminal.tty === "string" && /^pts\/(0|[1-9][0-9]{0,6})$/.test(terminal.tty)))
    && (terminal.others === undefined || (typeof terminal.others === "number" && Number.isSafeInteger(terminal.others) && terminal.others >= 0 && terminal.others <= 1024)));
}

/** Decode a failure from the server, dropping any field that is not in its exact public shape. */
function parseFailure(value: unknown): FailureDetail | undefined {
  if (!isRecord(value) || typeof value.kind !== "string" || !KINDS.includes(value.kind) || typeof value.message !== "string") return undefined;
  const failure: FailureDetail = { kind: value.kind as FailureKind, message: value.message, log_tail: isStrings(value.log_tail) ? value.log_tail : [] };
  if (typeof value.exit_status === "number" && Number.isInteger(value.exit_status) && value.exit_status >= 0 && value.exit_status <= 255) failure.exit_status = value.exit_status;
  if (value.kind === "setup_running" || value.kind === "stale_previous_attempt") {
    const setupLock = parseSetupLock(value.setup_lock);
    if (setupLock) failure.setup_lock = setupLock;
  }
  if (value.kind === "unproven_files" && (value.refusal === "cache" || value.refusal === "prepared" || value.refusal === "foreign")) failure.refusal = value.refusal;
  if (value.kind === "unrecognized_install" && isRecord(value.takeover) && typeof value.takeover.install === "string"
    && /^[0-9a-f]{32}$/.test(value.takeover.install) && typeof value.takeover.live === "boolean") {
    const terminals = value.takeover.terminals;
    // Unknown or malformed terminal metadata must never turn into an offer with an empty list.
    if (terminals !== undefined && !areTerminals(terminals)) return failure;
    const closeChallenge = value.takeover.close_challenge;
    if (Array.isArray(terminals) && terminals.length && (!isCanonicalUuid(closeChallenge) || closeChallenge === "00000000-0000-0000-0000-000000000000")) return failure;
    failure.takeover = { install: value.takeover.install, live: value.takeover.live,
      ...(isCanonicalUuid(closeChallenge) ? { close_challenge: closeChallenge } : {}),
      ...(Array.isArray(terminals) ? { terminals: terminals as TakeoverTerminal[] } : {}) };
  }
  // A Start fresh that closes the stuck setup's own terminals (D368, #433): both the list and its own challenge, or neither.
  if (value.kind === "stale_previous_attempt" && isRecord(value.closes) && areTerminals(value.closes.terminals) && value.closes.terminals.length
    && isCanonicalUuid(value.closes.close_challenge) && value.closes.close_challenge !== "00000000-0000-0000-0000-000000000000") {
    failure.closes = { terminals: value.closes.terminals, close_challenge: value.closes.close_challenge };
  }
  if (isStrings(value.fingerprints) && value.fingerprints.length) failure.fingerprints = value.fingerprints;
  if (typeof value.host_key_challenge === "string") failure.host_key_challenge = value.host_key_challenge;
  if (["get-arm64-binary", "get-x86-64-binary", "connect", "upload", "install", "join", "start", "readiness"].includes(String(value.failed_step))) failure.failed_step = value.failed_step as NonNullable<FailureDetail["failed_step"]>;
  if (typeof value.host_key_type === "string") failure.host_key_type = value.host_key_type;
  if (value.host_key_changed === true) failure.host_key_changed = true;
  if (value.already_added === true) failure.already_added = true;
  if (failure.already_added && isCanonicalUuid(value.host_id)) failure.host_id = value.host_id;
  if (isRecord(value.missing_binary) && typeof value.missing_binary.architecture === "string" && typeof value.missing_binary.path === "string") {
    failure.missing_binary = { architecture: value.missing_binary.architecture, path: value.missing_binary.path };
  }
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

function parseLeftovers(value: unknown): Leftovers | undefined {
  if (!isRecord(value) || !isCanonicalUuid(value.challenge) || !isStrings(value.findings)) return undefined;
  return { challenge: value.challenge, mode: value.mode === "root" ? "root" : "rootless", findings: value.findings.slice(0, 16) };
}

/**
 * Validates one server event. Its failure is kept only in its known shape, and `leftovers` only on a failure that
 * pauses for confirmation (pausesForConfirmation).
 */
function parseEvent(value: Record<string, unknown>): BootstrapEvent | undefined {
  const { sequence, target, attempt, step, message, elapsed_ms: elapsed } = value;
  if (typeof sequence !== "number" || typeof target !== "string" || typeof attempt !== "number" || typeof step !== "string" || !STEPS.includes(step)
    || typeof message !== "string" || typeof elapsed !== "number") return undefined;
  const event: BootstrapEvent = { sequence, target, attempt, step: step as BootstrapStep, message, elapsed_ms: elapsed, log_tail: isStrings(value.log_tail) ? value.log_tail : [] };
  if (value.step === "done" && isCanonicalUuid(value.host_id)) {
    event.host_id = value.host_id;
    if (isCanonicalUuid(value.session_id)) event.session_id = value.session_id;
  }
  const failure = parseFailure(value.failure);
  if (failure) event.failure = failure;
  const leftovers = parseLeftovers(value.leftovers);
  // Leftovers without the matching failure kind would offer a cleanup nobody proved; ignore them.
  if (leftovers && pausesForConfirmation(failure)) event.leftovers = leftovers;
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

  /**
   * Removes exactly what the earlier attempt left on a host (the `ssh.start-fresh` action, #169) and continues the same
   * attempt. `challenge` comes from the failed event's leftovers, or its terminal-close offer; the server refuses any other.
   */
  startFresh(target: string, challenge: string): void { this.send({ action: "start-fresh", target, challenge }); }

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
  sessionId?: string;
  attempt: number;
  /** Index into `PHASES` of the latest phase entered (a failure keeps the phase it happened in). */
  phase: number;
  /** The server's human text for the latest event. */
  message: string;
  failure: FailureDetail | undefined;
  /** What an earlier setup left behind, while the running attempt is paused on the person's "Start fresh". */
  leftovers: Leftovers | undefined;
  elapsedMs: number;
  /** How this attempt signed in, once the server reported it. */
  authentication: AuthenticationInfo | undefined;
}

/**
 * A host whose SSH key this server has never pinned. The server still reports it as a `host-key` failure (the wire
 * contract is unchanged, #397), but it is a question for the person, not a fault: the wizard shows it as an ordinary
 * step. A changed pin (`host_key_changed`) or a report without fingerprints is not covered and stays a failure.
 */
export const awaitingKey = (view: TargetView): boolean =>
  view.state === "failed" && view.failure?.kind === "host-key" && view.failure.host_key_changed !== true && !!view.failure.fingerprints?.length;
/**
 * Whether a failure pauses its attempt for the person's confirmation: earlier-setup leftovers (#169), or a finished
 * install of another server offered for Take over (D359). Only these carry `leftovers` and its challenge.
 */
function pausesForConfirmation(failure: FailureDetail | undefined): boolean {
  return failure?.kind === "stale_previous_attempt" || (failure?.kind === "unrecognized_install" && !!failure.takeover);
}

/** True while the attempt is paused on earlier-setup leftovers: it waits for the person, nothing is running. */
export const awaitingFresh = (view: TargetView): boolean => view.state === "running" && !!view.leftovers;

export const pendingTarget = (): TargetView => ({ state: "pending", attempt: 0, phase: 0, message: "", failure: undefined, leftovers: undefined, elapsedMs: 0, authentication: undefined });

/** Folds one event into a target's view; events of an older attempt are ignored. */
export function foldEvent(view: TargetView, event: BootstrapEvent): TargetView {
  if (event.attempt < view.attempt) return view;
  const fresh = event.attempt > view.attempt;
  const phase = (PHASES as readonly string[]).indexOf(event.step);
  // The sign-in method sticks for the attempt, so a later failure still knows it got past authentication.
  const base: TargetView = { ...(fresh ? { ...pendingTarget(), attempt: event.attempt } : view) };
  if (event.authentication) base.authentication = event.authentication;
  if (event.step === "done") return { ...base, ...(isCanonicalUuid(event.host_id) ? { hostId: event.host_id, ...(isCanonicalUuid(event.session_id) ? { sessionId: event.session_id } : {}) } : {}), state: "done", phase: PHASES.length, message: event.message, failure: undefined, leftovers: undefined, elapsedMs: event.elapsed_ms };
  if (event.step === "failed") return { ...base, state: "failed", message: event.message, failure: event.failure, leftovers: event.leftovers, elapsedMs: event.elapsed_ms };
  // Earlier-setup leftovers are a pause inside the open attempt (a `check` event, #169): the attempt stays running and
  // waits for `startFresh`. The next event of the attempt clears the pause.
  const paused = pausesForConfirmation(event.failure) && !!event.leftovers;
  // Rollback and warnings may emit extra install events; the phase never moves backwards.
  return { ...base, state: "running", phase: Math.max(base.phase, phase), message: event.message, failure: paused ? event.failure : undefined, leftovers: paused ? event.leftovers : undefined, elapsedMs: event.elapsed_ms };
}
