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
 * What is scripted (the double's only invention, all keyed on the fixture or the host name,
 * never on the client): per-host step timings are staggered; `unreachable` and `mesh-policy`
 * fixtures fail, and the `authentication: "refused"` fixture fails with `auth` and
 * `choose_method` until a one-connection credential is supplied. A retry or a fresh attempt
 * for a failed target succeeds, as if the person had fixed the cause.
 *
 * D183 paths, by host (a typed host name matches the same patterns):
 * - network: edge-arm (Tailscale), o1 and mon-02 (NetBird), remoternal (Tailscale)
 * - dedicated server key: every other host that signs in
 * - saved key / password: one-use `auth_once` inputs on the bootstrap socket
 * - `needs-key*` / nix-cache: every automatic method refused (auth + choose_method) until a credential is given
 * - `refused*`: one refusal without `choose_method`; the retry signs in
 * - `newkey*`: unknown host key (host-key + fingerprint) until confirmed on the same bootstrap socket
 * - `changedkey*`: the pinned key differs (host-key + fingerprint + `host_key_changed`) until confirmed
 * - `stale*`: an earlier setup left leftovers: the attempt pauses on a `check` event carrying
 *   `failure.kind: "stale_previous_attempt"` and `leftovers` (challenge, mode, findings); `start-fresh` with that challenge
 *   continues the same attempt to done. Closing the socket cancels the pause (contracts/ssh-bootstrap.md, #169)
 * - `stuck*`: an interrupted upgrade carries its validated lock coordinates and resumes through the explicit replacement action
 * - `foreign*`: the interrupted upgrade belongs to another server; it resumes by joining as a new host (D335)
 * - `added*`: the host is already added: an `install` failure with `already_added` and the existing `host_id`, no details
 * - `running*`: `setup_running` once; the retry succeeds
 * - `unsupported*`: reported after sign-in, never succeeds; `broken*`: install fails, the retry works
 * - `installed*`: a finished install this server doesn't know (#394); `noacct*`: the login name is no account there
 * - `unproven-cache*` / `unproven-prepared*` / `unproven-foreign*`: a staging step refused files it can't prove are its own (`unproven_files`
 *   with that `refusal`, J314 P2-1)
 * - `takeover*`: the same, but proven ours: in root mode the attempt pauses on the Take over offer (D359), carrying
 *   `failure.takeover` (the old install's id) and `leftovers`; `start-fresh` with that challenge sets it aside and
 *   continues to done. A rootless add of it fails like `installed*`
 * HTTP side (`handleBootstrapHttp`): the proposed endpoints of #87 (ssh-key, discovery, credential, host-key,
 * install-command) plus `/__mock/bootstrap/*` switches the specs use to reach empty and error states.
 */
import { createHash, randomUUID } from "node:crypto";
import type { IncomingMessage, ServerResponse } from "node:http";
import type { WebSocket } from "ws";
import type { AddHostFixture } from "../src/add-host-contract";
import { publishSetup, runSetup } from "./setup-double";
import { addHostFixtures } from "./prototype-fixtures";

const MAX_COMMAND_BYTES = 32 * 1024;
/** The old install's id that `takeover*` hosts report (D359): 32 lowercase hex characters, as in `.bootstrap-owner`. */
export const TAKEOVER_INSTALL = "c10909d16e8147a3b0f2e5d4c3b2a190";
const MAX_TARGETS = 100;
const MAX_ATTEMPTS = 8;
const MAX_ACTIVE = 8;
const RETAINED_EVENTS = 1024;
const IDENTIFIER = /^[A-Za-z0-9._-]{1,128}$/;

type Step = "check" | "install" | "facts" | "connect" | "done" | "failed";
/** The failure kinds the double can script, mirroring the server contract (contracts/ssh-bootstrap.md). */
type FailureKind = "unreachable" | "auth" | "mesh-policy" | "host-key" | "unsupported" | "install" | "stale_previous_attempt" | "setup_running" | "unrecognized_install" | "unproven_files" | "no_account";
const PHASES = [
  { step: "check", message: "Checking the system" },
  { step: "install", message: "Installing the infraternal agent" },
  { step: "facts", message: "Gathering host facts" },
  { step: "connect", message: "Connecting" },
] as const;

/** One bootstrap event as the double sends it over the socket, in the server's wire shape. */
interface BootstrapEvent {
  sequence: number;
  target: string;
  attempt: number;
  step: Step;
  message: string;
  elapsed_ms: number;
  log_tail: string[];
  host_id?: string;
  session_id?: string;
  leftovers?: { challenge: string; mode: "rootless" | "root"; findings: string[] };
  failure?: { host_key_changed?: boolean; failed_step?: "connect" | "upload" | "start"; refusal?: "cache" | "prepared" | "foreign"; kind: FailureKind; message: string; log_tail: string[]; setup_lock?: { machine: string; pid?: number; since: string; active: boolean; attempt?: string; sessions?: number; enrolled_with?: string; set_aside?: boolean; live?: boolean; in_use?: boolean }; fingerprints?: string[]; host_key_challenge?: string; host_key_type?: string; choose_method?: boolean; already_added?: boolean; host_id?: string; takeover?: { install: string; live: boolean } };
  authentication?: { method: "network" | "server-key" | "user-key" | "password"; network?: "netbird" | "tailscale" };
}

interface Target {
  id: string;
  publication?: { host_id: string; session_id: string };
  /** The host name the scripted patterns match: the fixture id or the typed host. */
  name: string;
  /** Kind of the one-connection credential this target was started with. */
  credential: "private-key" | "password" | undefined;
  fixture: AddHostFixture | undefined;
  mode: "rootless" | "root";
  attempt: number;
  state: "queued" | "active" | "done" | "failed";
  /** When this attempt entered the scheduler; elapsed_ms counts from here, queue time included. */
  enteredAt: number;
  breadcrumbs: string[];
  timers: Set<ReturnType<typeof setTimeout>>;
  /** The one-use handle of the leftovers the attempt is paused on (#169); the attempt waits for `start-fresh`. */
  challenge: string | undefined;
  /** Continues a paused attempt after `start-fresh`. */
  resume: (() => void) | undefined;
  /** Leftovers were removed (or never existed) for this host in this socket. */
  fresh: boolean;
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

/** The host part of an address: a discovered id, or the host of `user@host:port`. */
function hostNameOf(address: { kind: string; value: string }): string {
  if (address.kind === "discovered") return address.value;
  return ((/^(?:[^@]+@)?(\[[^\]]+\]|[^:]+)(?::\d+)?$/.exec(address.value) ?? [])[1] ?? address.value).toLowerCase();
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

/** The scripted failure of a named host: where it stops, what it reports and what Details shows. */
interface Failure { failed_step?: "connect" | "upload" | "start"; phase: number; beforeLogin: boolean; kind: FailureKind; message: string; evidence: string; choose?: boolean; fingerprints?: string[]; keyChanged?: boolean; alreadyAdded?: boolean; refusal?: "cache" | "prepared" | "foreign" }

/** The existing host a duplicate (`added*`) names; the mock world maps it to a host it already has. */
const ADDED_HOST_ID = "6f1d0a52-7c3e-4b8a-9d21-0a5e4c7b1f30";

/** Host keys the person trusted on the same bootstrap socket, until `reset`. */
const trusted = new Set<string>();
let sshKeyMode: "ok" | "locked" | "missing" = "ok";
let discoveryMode: "ok" | "empty" | "error" | "hang" | "off" = "ok";
let installMode: "ok" | "off" = "ok";

export function resetBootstrapDouble(): void {
  trusted.clear();
  sshKeyMode = "ok";
  discoveryMode = "ok";
  installMode = "ok";
}

/** A fixed v4-shaped UUID per target, so specs can assert the challenge round trip. */
const challengeOf = (id: string): string => { const hex = createHash("sha256").update(`challenge:${id}`).digest("hex"); return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-4${hex.slice(13, 16)}-8${hex.slice(17, 20)}-${hex.slice(20, 32)}`; };

const fingerprintOf = (name: string): string => `SHA256:${createHash("sha256").update(`host-key:${name}`).digest("base64").replace(/=+$/, "")}`;

/** Scripted outcome of one attempt for a host: undefined succeeds. */
function failureOf(target: Target): Failure | undefined {
  const host = target.fixture;
  const name = target.name;
  if (/^unsupported/.test(name)) return { phase: 0, beforeLogin: false, kind: "unsupported", message: "This host does not run systemd as a user service.", evidence: "init: openrc\nuser systemd: unavailable" };
  if (/^(newkey|changedkey)/.test(name) && !trusted.has(name)) {
    return { phase: 0, beforeLogin: true, kind: "host-key", message: "The SSH host key is not trusted.", evidence: "Checking SSH and host support.", fingerprints: [fingerprintOf(name)], ...(name.startsWith("changedkey") ? { keyChanged: true } : {}) };
  }
  if (target.fixed) return undefined;
  if (host?.reachability === "unreachable") return { phase: 0, beforeLogin: true, kind: "unreachable", message: "No SSH answer on port 22", evidence: host.evidence };
  if (host?.reachability === "mesh-policy") return { phase: 0, beforeLogin: true, kind: "mesh-policy", message: "Blocked by the mesh policy", evidence: host.evidence };
  if ((host?.authentication === "refused" || /^needs-key/.test(name)) && !target.credential) {
    return { phase: 0, beforeLogin: true, kind: "auth", message: "No sign-in method was accepted.", evidence: "Network access, the server key and a saved key were not accepted.", choose: true };
  }
  if (/^refused/.test(name)) return { phase: 0, beforeLogin: true, kind: "auth", message: "The host refused the server key.", evidence: "The host answered on port 22 and refused the SSH identity." };
  if (/^running/.test(name)) return { phase: 0, beforeLogin: false, kind: "setup_running", message: "Another setup is still running on this host.", evidence: "A setup holds the lock on this host." };
  if (/^added/.test(name)) return { phase: 0, beforeLogin: true, kind: "install", message: "This host is already added. Open its terminal from Console.", evidence: "", alreadyAdded: true };
  if (/^nodetail/.test(name)) return { phase: 0, beforeLogin: true, kind: "install", message: "Setup stopped before this host was ready.", evidence: "Setup stopped before this host was ready." };
  if (/^connectfail/.test(name)) return { failed_step: "connect", phase: 0, beforeLogin: true, kind: "install", message: "Connecting to the host failed. Check SSH access and the host service, then try again.", evidence: "The SSH connection setup failed." };
  if (/^(installed|takeover)/.test(name)) return { failed_step: "connect", phase: 0, beforeLogin: false, kind: "unrecognized_install", message: "This machine already has an infraternal agent from an earlier setup, so nothing was changed. If an infraternal server still lists it, remove it there to uninstall it, then add it here again.", evidence: "Setup location: /var/lib/infraternal" };
  for (const refusal of ["cache", "prepared", "foreign"] as const) {
    if (name.startsWith(`unproven-${refusal}`)) return { failed_step: "upload", phase: 1, beforeLogin: false, kind: "unproven_files", refusal, message: "Setup changed nothing.", evidence: "Setup location: /var/lib/infraternal" };
  }
  if (/^noacct/.test(name)) return { phase: 0, beforeLogin: false, kind: "no_account", message: "This host has no account with that user name.", evidence: "The host's SSH server reported no such account." };
  if (/^broken/.test(name)) return { failed_step: "start", phase: 1, beforeLogin: false, kind: "install", message: "The installation did not finish and was rolled back.", evidence: "Uploaded the binary.\nThe unit failed to start." };
  return undefined;
}

const NETWORK: Record<string, "netbird" | "tailscale"> = { "edge-arm": "tailscale", o1: "netbird", "mon-02": "netbird", remoternal: "tailscale" };

function authOf(target: Target): NonNullable<BootstrapEvent["authentication"]> {
  if (target.credential === "password") return { method: "password" };
  if (target.credential === "private-key") return { method: "user-key" };
  const network = NETWORK[target.name];
  return network ? { method: "network", network } : { method: "server-key" };
}

/** Serves one bootstrap socket: starts, retries, confirms and replays scripted host attempts. */
export function serveProvisioning(socket: WebSocket, _request: IncomingMessage, publishTerminal?: (hostId: string) => string): void {
  const targets = new Map<string, Target>();
  const events: BootstrapEvent[] = [];
  let sequence = 0;
  let started = false;
  let closed = false;

  const send = (value: unknown): void => { if (!closed && socket.readyState === socket.OPEN) socket.send(JSON.stringify(value)); };
  const refuse = (message: string): void => send({ error: { kind: "unsupported", message, log_tail: [] } });

  function emit(target: Target, step: Step, message: string, failure?: BootstrapEvent["failure"], authentication?: BootstrapEvent["authentication"], leftovers?: BootstrapEvent["leftovers"]): void {
    target.breadcrumbs = [...target.breadcrumbs, message].slice(-8);
    const event: BootstrapEvent = {
      sequence: ++sequence, target: target.id, attempt: target.attempt, step, message,
      elapsed_ms: Date.now() - target.enteredAt, log_tail: [...target.breadcrumbs],
    };
    if (step === "done" && target.publication) Object.assign(event, target.publication);
    if (failure) event.failure = failure;
    if (authentication) event.authentication = authentication;
    if (leftovers) event.leftovers = leftovers;
    events.push(event);
    if (events.length > RETAINED_EVENTS) events.shift();
    send(event);
  }

  const later = (target: Target, ms: number, fn: () => void): void => {
    const timer = setTimeout(() => { target.timers.delete(timer); if (!closed) fn(); }, ms);
    target.timers.add(timer);
  };

  /** Staggered, host-dependent pace so a batch looks like separate machines. */
  // Cancellation owns a deliberately pending fixture; it must not turn into a
  // successful install while a loaded browser is opening the confirmation.
  const pace = (target: Target, phase: number): number => target.name === "cancellation.lab" && phase === 1 ? 60_000 : 420 + ((target.id.length * 97 + phase * 53) % 380);

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
    const failure = failureOf(target);
    const fail = (): void => {
      if (!failure) return;
      emit(target, "failed", failure.message, {
        ...(failure.failed_step ? { failed_step: failure.failed_step } : {}), ...(failure.refusal ? { refusal: failure.refusal } : {}), kind: failure.kind, message: failure.message, log_tail: failure.evidence ? [failure.evidence] : [],
        ...(failure.alreadyAdded ? { already_added: true, host_id: ADDED_HOST_ID } : {}),
        ...(failure.fingerprints ? { fingerprints: failure.fingerprints, host_key_challenge: target.id, host_key_type: "ssh-ed25519", ...(failure.keyChanged ? { host_key_changed: true } : {}) } : {}), ...(failure.choose ? { choose_method: true } : {}),
      });
      target.state = "failed";
      target.fixed = true;
      release();
    };
    const walk = (phase: number): void => {
      if (phase === 1 && /^instant/.test(target.name) && publishTerminal) {
        const host = randomUUID();
        const session = publishTerminal(host);
        target.publication = { host_id: host, session_id: session };
        publishSetup(host, session);
        emit(target, "done", "The terminal is ready; setup steps continue.");
        target.state = "done";
        runSetup(host, target.name.includes("fail") ? "join" : undefined, release);
        return;
      }
      if (phase >= PHASES.length) {
        emit(target, "done", target.mode === "root" ? "Ready · root" : "Ready");
        target.state = "done";
        release();
        return;
      }
      emit(target, PHASES[phase]!.step, PHASES[phase]!.message);
      if (phase === 0) {
        // The server reports how it signed in as soon as it has; failures before that never do.
        if (failure?.beforeLogin) { later(target, pace(target, 0) + 400, fail); return; }
        later(target, pace(target, 0) / 2, () => {
          emit(target, "check", "Signed in. Checking the system.", undefined, authOf(target));
          // Hosts named `stuck*`: the check finds an interrupted upgrade and pauses on the explicit replacement action.
          if (/^stuck/.test(target.name) && !target.fresh) {
            target.challenge = challengeOf(target.id);
            target.resume = () => walk(1);
            emit(target, "check", "A stuck infraternal agent was found", {
              kind: "stale_previous_attempt",
              message: "The failed setup on build-node left a lease last held by setup attempt d831a93a (process 254) since 2026-11-02T04:05:06Z. Replace the stuck install to continue. 1 open terminal session will carry over.",
              log_tail: [],
              setup_lock: { machine: "build-node", pid: 254, since: "2026-11-02T04:05:06Z", active: false, attempt: "d831a93a", sessions: 1 },
            }, undefined, {
              challenge: target.challenge,
              mode: target.mode,
              findings: ["An interrupted upgrade journal", "The enrolled host identity is kept", "1 open terminal session will carry over"],
            });
            return;
          }
          // Hosts named `live*`: another server's stuck install whose infraternal agent is running with no open terminals (#305, D337).
          if (/^live/.test(target.name) && !target.fresh) {
            target.challenge = challengeOf(target.id);
            target.resume = () => walk(1);
            emit(target, "check", "This host has leftovers from an earlier setup", {
              kind: "stale_previous_attempt",
              message: "The failed setup on build-node left a lease last held by setup attempt d831a93a (process 254) since 2026-11-02T04:05:06Z. This machine is enrolled with another server, monitor01.example. Its infraternal agent is running and may be connected to monitor01.example now. Joining it here disconnects it from monitor01.example; remove it there afterwards. Joining it to this server makes it a new host with a new key; its old infraternal agent and key are deleted once it has joined. No terminal sessions are open.",
              log_tail: [],
              setup_lock: { machine: "build-node", pid: 254, since: "2026-11-02T04:05:06Z", active: false, attempt: "d831a93a", sessions: 0, enrolled_with: "monitor01.example", live: true },
            }, undefined, {
              challenge: target.challenge,
              mode: target.mode,
              findings: ["Enrolled with another server: monitor01.example", "Its infraternal agent is running and may be connected to that server now; joining here disconnects it", "No open terminal sessions"],
            });
            return;
          }
          // Hosts named `inuse*`: another server's install runs with open terminals and may be in use
          // there, so taking it over is refused by name, with nothing to confirm (D337).
          if (/^inuse/.test(target.name)) {
            const message = "build-node is enrolled with monitor01.example. Its infraternal agent is running with 2 open terminals and may still be connected to monitor01.example. Prove you own monitor01.example to take it over; that isn't available yet.";
            emit(target, "failed", message, {
              kind: "stale_previous_attempt",
              message,
              log_tail: [],
              setup_lock: { machine: "build-node", pid: 254, since: "2026-11-02T04:05:06Z", active: false, attempt: "d831a93a", sessions: 2, enrolled_with: "monitor01.example", live: true, in_use: true },
            });
            target.state = "failed";
            target.fixed = true;
            release();
            return;
          }
          // Hosts named `aside*`: an earlier add-host set the install aside and could not put it back (#305).
          if (/^aside/.test(target.name) && !target.fresh) {
            target.challenge = challengeOf(target.id);
            target.resume = () => walk(1);
            emit(target, "check", "This host has leftovers from an earlier setup", {
              kind: "stale_previous_attempt",
              message: "An earlier add-host on build-node set this machine's infraternal agent aside and did not put it back. Nothing was deleted. Put it back as it was found, then add the host again to continue.",
              log_tail: [],
              setup_lock: { machine: "build-node", since: "unknown", active: false, attempt: "d831a93a", set_aside: true },
            }, undefined, {
              challenge: target.challenge,
              mode: target.mode,
              findings: ["An infraternal agent an earlier add-host set aside", "Nothing was deleted; it goes back where it was", "Its service is enabled and started again, as it was found"],
            });
            return;
          }
          // Hosts named `foreign*`: the stuck install was enrolled by another server; confirming joins it as a new host (D335).
          if (/^foreign/.test(target.name) && !target.fresh) {
            target.challenge = challengeOf(target.id);
            target.resume = () => walk(1);
            emit(target, "check", "This host has leftovers from an earlier setup", {
              kind: "stale_previous_attempt",
              message: "The failed setup on build-node left a lease last held by setup attempt d831a93a (process 254) since 2026-11-02T04:05:06Z. This machine is enrolled with another server, monitor01.example. Joining it to this server makes it a new host with a new key; its old infraternal agent and key are deleted once it has joined. 1 open terminal session will end.",
              log_tail: [],
              setup_lock: { machine: "build-node", pid: 254, since: "2026-11-02T04:05:06Z", active: false, attempt: "d831a93a", sessions: 1, enrolled_with: "monitor01.example" },
            }, undefined, {
              challenge: target.challenge,
              mode: target.mode,
              findings: ["Enrolled with another server: monitor01.example", "It joins this server as a new host; the old install and its key are deleted once it has joined", "1 open terminal session will end"],
            });
            return;
          }
          // Hosts named `takeover*`, added as root: the old install is offered for Take over, named by its id (D359).
          if (/^takeover/.test(target.name) && target.mode === "root" && !target.fresh) {
            target.challenge = challengeOf(target.id);
            target.resume = () => walk(1);
            emit(target, "check", "This machine has an infraternal agent from an earlier setup", {
              failed_step: "connect",
              kind: "unrecognized_install",
              message: "This machine already has an infraternal agent from an earlier setup that isn't one of this server's hosts. Take it over to set it up here.",
              log_tail: ["Setup location: /var/lib/infraternal"],
              takeover: { install: TAKEOVER_INSTALL, live: true },
            }, undefined, {
              challenge: target.challenge,
              mode: target.mode,
              findings: ["An infraternal agent from an earlier setup that isn't one of this server's hosts", "Its infraternal agent is running; Take over stops it", "It is set aside, put back if setup fails, and deleted once this machine has joined"],
            });
            return;
          }
          // Hosts named `stale*`: the check finds leftovers and the attempt pauses on a `check` event until `start-fresh`.
          if (/^stale/.test(target.name) && !target.fresh) {
            target.challenge = challengeOf(target.id);
            target.resume = () => walk(1);
            emit(target, "check", "This host has leftovers from an earlier setup", { kind: "stale_previous_attempt", message: "infraternal didn't finish setting up here before. Start fresh to remove what it left behind and continue.", log_tail: [] }, undefined,
              { challenge: target.challenge, mode: target.mode, findings: ["An unfinished setup lock", "Files from an interrupted install"] });
            return;
          }
          if (failure?.phase === 0) later(target, 300, fail); else later(target, pace(target, 0) / 2, () => walk(1));
        });
        return;
      }
      // A failing host stops at its phase, once the failure has had time to show.
      if (failure?.phase === phase) { later(target, pace(target, phase) + 400, fail); return; }
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
      const auth = Array.isArray(command.auth_once) ? command.auth_once.find((item) => item?.target === entry.id)?.auth : undefined;
      const credential = auth?.password ? "password" as const : auth?.key ? "private-key" as const : undefined;
      if (mode === "root" && entry.root_consent !== true) return refuse("Root access needs your explicit consent.");
      parsed.push({
        id: entry.id, name: hostNameOf(address as { kind: string; value: string }), credential,
        fixture: fixtureFor({ kind: address.kind, value: address.value }), mode, attempt: 1, state: "queued",
        enteredAt: Date.now(), breadcrumbs: [], timers: new Set(), fixed: false, challenge: undefined, resume: undefined, fresh: false, order: index,
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

  /** `start-fresh`: valid only for a target paused on leftovers, with that pause's single-use challenge. */
  function startFresh(command: Record<string, unknown>): void {
    if (!started) return refuse("Start a host batch first.");
    const target = typeof command.target === "string" ? targets.get(command.target) : undefined;
    if (!target) return refuse("That host is not in this batch.");
    if (!target.challenge || !target.resume || command.challenge !== target.challenge) return refuse("This earlier setup observation is no longer available. Retry the host check.");
    const resume = target.resume;
    target.challenge = undefined;
    target.resume = undefined;
    target.fresh = true;
    // The same attempt continues: no new attempt number, then the normal steps.
    emit(target, "check", "Earlier setup leftovers removed. Continuing the setup steps.");
    later(target, 250, resume);
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
    const known = { start: ["action", "targets", "credential", "auth_once"], "confirm-host-key": ["action", "target", "challenge", "fingerprint"], retry: ["action", "target"], "start-fresh": ["action", "target", "challenge"], replay: ["action", "after"] } as const;
    const action = command.action;
    if (action !== "start" && action !== "retry" && action !== "start-fresh" && action !== "replay" && action !== "confirm-host-key") return send({ error: "invalid bootstrap request" });
    // Unknown fields are rejected, as the contract says.
    if (Object.keys(command).some((key) => !(known[action] as readonly string[]).includes(key))) return send({ error: "invalid bootstrap request" });
    if (action === "confirm-host-key") {
      const target = typeof command.target === "string" ? targets.get(command.target) : undefined;
      if (!target || target.state !== "failed" || command.challenge !== target.id || command.fingerprint !== fingerprintOf(target.name)) return refuse("Check the host key again.");
      trusted.add(target.name);
      send({ host_key_confirmed: { target: target.id, fingerprint: command.fingerprint } });
    } else if (action === "start") start(command); else if (action === "retry") retry(command); else if (action === "start-fresh") startFresh(command); else replay(command);
  });

  // Disconnect cancels outstanding work; hosts that were running free their slot.
  socket.on("close", () => {
    closed = true;
    for (const target of targets.values()) {
      const wasRunning = target.state === "active" && (target.timers.size > 0 || !!target.challenge);
      for (const timer of target.timers) clearTimeout(timer);
      target.timers.clear();
      if (wasRunning) release();
    }
  });
}

// ── HTTP side: the endpoints around the socket ───────────────────────────────

const SERVER_KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFh2R0N1c3RvbVRlc3REb3VibGVLZXlPbmx5SW5NZW1vcnk infraternal-server";
const SERVER_KEY_FINGERPRINT = `SHA256:${createHash("sha256").update(SERVER_KEY).digest("base64").replace(/=+$/, "")}`;

const json = (response: ServerResponse, status: number, value: unknown): void => {
  response.statusCode = status;
  response.setHeader("Content-Type", "application/json; charset=utf-8");
  response.setHeader("Cache-Control", "no-store");
  response.end(JSON.stringify(value));
};

async function bodyOf(request: IncomingMessage): Promise<Record<string, unknown> | undefined> {
  const chunks: Buffer[] = [];
  let total = 0;
  for await (const chunk of request) {
    const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    total += bytes.byteLength;
    if (total > MAX_COMMAND_BYTES) return undefined;
    chunks.push(bytes);
  }
  try {
    const value: unknown = JSON.parse(Buffer.concat(chunks).toString("utf8"));
    return typeof value === "object" && value !== null && !Array.isArray(value) ? value as Record<string, unknown> : undefined;
  } catch { return undefined; }
}

/** Discovery rows in the proposed wire shape (snake_case), from the add-host fixtures. */
function discoveryRows(): unknown[] {
  return addHostFixtures.map((host) => ({
    id: host.id, user: host.user, address: host.address, operating_system: host.operatingSystem, architecture: host.architecture,
    sources: host.sources, reach: host.reachability, evidence: host.evidence, already_added: host.alreadyAdded, root_available: host.rootAvailable,
  }));
}

/**
 * The HTTP endpoints of the provisioning API that are not the socket. `authorized` is the same check the
 * socket upgrade makes (exact Origin, unlocked owner session). Returns true when it answered.
 */
export async function handleBootstrapHttp(request: IncomingMessage, response: ServerResponse, path: string, authorized: boolean): Promise<boolean> {
  if (path === "/__mock/bootstrap/reset" && request.method === "POST") { resetBootstrapDouble(); json(response, 200, { ok: true }); return true; }
  if (path === "/__mock/bootstrap/config" && request.method === "POST") {
    const body = await bodyOf(request);
    if (body?.sshKey === "ok" || body?.sshKey === "locked" || body?.sshKey === "missing") sshKeyMode = body.sshKey;
    if (body?.discovery === "ok" || body?.discovery === "empty" || body?.discovery === "error" || body?.discovery === "hang" || body?.discovery === "off") discoveryMode = body.discovery;
    if (body?.install === "ok" || body?.install === "off") installMode = body.install;
    json(response, 200, { ok: true });
    return true;
  }
  if (!path.startsWith("/v1/bootstrap/") || path === "/v1/bootstrap/ws") return false;
  if (!authorized) { json(response, 401, { error: "authorization failed" }); return true; }

  if (path === "/v1/bootstrap/ssh-key" && request.method === "GET") {
    if (sshKeyMode === "missing") json(response, 503, { error: "custody unavailable" });
    else json(response, 200, { public_key: SERVER_KEY, fingerprint: SERVER_KEY_FINGERPRINT, locked: sshKeyMode === "locked" });
    return true;
  }
  if (path === "/v1/bootstrap/discovery" && request.method === "GET") {
    if (discoveryMode === "off") json(response, 404, { error: "not found" });
    else if (discoveryMode === "error") json(response, 500, { error: "discovery failed" });
    // Answers late, so the loading state stays on screen long enough to read, then ends: an answer that never
    // came would pin the test proxy's connection.
    else if (discoveryMode === "hang") setTimeout(() => json(response, 200, { hosts: discoveryRows() }), 5000);
    else json(response, 200, { hosts: discoveryMode === "empty" ? [] : discoveryRows() });
    return true;
  }
  if (path === "/v1/bootstrap/install-command" && request.method === "POST") {
    if (installMode === "off") json(response, 404, { error: "not found" });
    else json(response, 200, { command: "curl -fsSL https://infraternal.test/join | sh -s -- --one-time", expires_in_seconds: 900 });
    return true;
  }
  json(response, 404, { error: "not found" });
  return true;
}
