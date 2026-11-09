// SPDX-License-Identifier: AGPL-3.0-only
/**
 * Uses the authenticated bootstrap socket for one-use sign-in and exact host-key confirmation.
 * Local references live for at most a minute, are bound to a target, and are consumed before sending.
 * Discovery, public SSH keys and install commands use their existing same-origin endpoints.
 */
import { randomUuid } from "../../identifiers";
import { onDemand } from "../../on-demand";
import type { HostSource } from "../../../../../packages/ui/src/source-icons";
import type { HostPlatform } from "../../../../../packages/ui/src/host-icons";
import { ProvisioningRun, type ProvisioningHandlers, type ProvisioningOptions, type OneUseAuth } from "../../provisioning-client";
import { ServiceError, type DiscoveredHost, type InstallCommand, type OneTimeSecret, type ProvisioningService, type SavedKey, type ServerKey } from "./service";

/** True for a plain object (not null, not an array); narrows an unknown server value. */
const isRecord = (value: unknown): value is Record<string, unknown> => typeof value === "object" && value !== null && !Array.isArray(value);
/** Operating-system names the wizard has an icon for; any other value from the server is ignored. */
const PLATFORMS: readonly string[] = ["ubuntu", "debian", "proxmox", "redhat", "nixos", "apple", "unknown"];
/** Discovery sources the wizard knows how to label; unknown sources are dropped from a row. */
const SOURCES: readonly string[] = ["netbird", "tailscale", "known-hosts", "ssh-config", "already-added"];

/** Reads a discovery row defensively: the server's data is untrusted until shaped. */
export function parseDiscovered(value: unknown): DiscoveredHost | undefined {
  if (!isRecord(value) || typeof value.id !== "string" || !/^[A-Za-z0-9._-]{1,128}$/.test(value.id) || typeof value.address !== "string") return undefined;
  const host: DiscoveredHost = {
    id: value.id,
    address: value.address,
    sources: Array.isArray(value.sources) ? value.sources.filter((item): item is HostSource => typeof item === "string" && SOURCES.includes(item)) : [],
  };
  if (typeof value.user === "string") host.user = value.user;
  if (typeof value.os === "string" && PLATFORMS.includes(value.os)) host.os = value.os as HostPlatform;
  if (typeof value.operating_system === "string") host.operatingSystem = value.operating_system;
  if (typeof value.architecture === "string") host.architecture = value.architecture;
  if (value.reach === "ready" || value.reach === "unreachable" || value.reach === "mesh-policy") host.reach = value.reach;
  if (typeof value.evidence === "string") host.evidence = value.evidence;
  if (value.already_added === true) host.alreadyAdded = true;
  if (value.root_available === true) host.rootAvailable = true;
  return host;
}

/** Reads the server's SSH public key answer. Returns `undefined` unless the key and its fingerprint are both strings; `locked` is true only when the server says so. */
export function parseServerKey(value: unknown): ServerKey | undefined {
  if (!isRecord(value) || typeof value.public_key !== "string" || typeof value.fingerprint !== "string") return undefined;
  return { publicKey: value.public_key, fingerprint: value.fingerprint, locked: value.locked === true };
}

/** Reads the install-command answer. Returns `undefined` unless it has the command text and a numeric expiry in seconds. */
export function parseInstallCommand(value: unknown): InstallCommand | undefined {
  if (!isRecord(value) || typeof value.command !== "string" || typeof value.expires_in_seconds !== "number") return undefined;
  return { command: value.command, expiresInSeconds: value.expires_in_seconds };
}

/**
 * One same-origin request that is never cached. With `init` it sends the body as JSON. It does not look at the status: callers
 * decide what each status means. If the network fails it throws a `ServiceError` of kind "network".
 */
async function call(path: string, init?: { method: string; body: unknown }): Promise<Response> {
  try {
    return await fetch(path, {
      method: init?.method ?? "GET",
      cache: "no-store",
      credentials: "same-origin",
      ...(init ? { headers: { "content-type": "application/json" }, body: JSON.stringify(init.body) } : {}),
    });
  } catch {
    throw new ServiceError("The server could not be reached. Check your connection and try again.", "network");
  }
}

/**
 * The body as JSON, or undefined when it is not JSON. A server that serves the web app for every unknown path
 * answers 200 with HTML for an endpoint it does not have; that is "not available", not a broken answer.
 */
async function jsonOf(response: Response): Promise<unknown> {
  if (!(response.headers.get("content-type") ?? "").includes("json")) return undefined;
  try { return await response.json(); } catch { return undefined; }
}

/** Maps a refusal to words the person can act on. `what` completes "…can't <what>". */
function refusal(response: Response, what: string): ServiceError {
  if (response.status === 404 || response.status === 405 || response.status === 501) return new ServiceError(`This server can't ${what} yet.`, "unavailable");
  if (response.status === 401 || response.status === 403) return new ServiceError("Unlock with your passkey, then try again.");
  if (response.status === 429) return new ServiceError("Too many attempts. Wait a moment and try again.");
  return new ServiceError(`Couldn't ${what}. Try again.`, response.status === 503 ? "unavailable" : "refused");
}

/**
 * The real `ProvisioningService`, talking to the server's bootstrap endpoints.
 * Secrets (a password or private key the person typed) are never sent by this object directly: `mintCredential` checks their size and
 * content, then keeps them in memory under a random reference for 60 seconds, bound to one target and address, at most 16 at a time. A
 * run takes the secret once (`takeAuth` deletes it before use). Host-key challenges seen during a run are remembered so that
 * `trustHostKey` can only trust a fingerprint the server really showed. `dispose` forgets every secret and challenge.
 */
export function createRealProvisioning(): ProvisioningService {
  const secrets = new Map<string, { target: string; address: string; auth: OneUseAuth; expires: number }>();
  const observations = new Map<string, { run: ProvisioningRun; target: string; challenge: string; fingerprints: string[] }>();
  /** Trusts in flight, by the challenge they confirm; a repeated call for the same one joins the promise already running. */
  const trusting = new Map<string, { fingerprint: string; work: Promise<void> }>();
  /** Host and fingerprint pairs already confirmed; a repeat answers success until the host shows a new observation. */
  const trusted = new Set<string>();
  const prune = (): void => { for (const [key, value] of secrets) if (value.expires <= Date.now()) secrets.delete(key); };
  return {
    authorityStatus: () => onDemand(() => import("./authority.on-demand")).then((module) => module.authorityStatus()),
    unlockAuthority: () => onDemand(() => import("./authority.on-demand")).then((module) => module.unlockAuthority()),
    async discover() {
      const response = await call("/v1/bootstrap/discovery");
      // No discovery on this server: the person types or pastes hosts instead. Not an error.
      if (response.status === 404 || response.status === 405 || response.status === 501 || response.status === 503) return [];
      if (!response.ok) throw refusal(response, "list hosts");
      const body = await jsonOf(response);
      const rows = isRecord(body) && Array.isArray(body.hosts) ? body.hosts : [];
      return rows.map(parseDiscovered).filter((host): host is DiscoveredHost => !!host);
    },

    async serverKey() {
      const response = await call("/v1/bootstrap/ssh-key");
      if (!response.ok) return undefined;
      return parseServerKey(await jsonOf(response));
    },

    // The browser keeps no passkey-wrapped SSH key yet; the choose-a-method page then offers paste and password only.
    async savedKey(): Promise<SavedKey | undefined> { return undefined; },

    open(handlers: ProvisioningHandlers, options?: ProvisioningOptions) {
      const addresses = new Map<string, string>();
      const run = new ProvisioningRun({
        ...handlers,
        onEvent(event) {
          const address = addresses.get(event.target);
          const challenge = event.failure?.host_key_challenge;
          if (address && challenge && event.failure?.fingerprints) {
            // A new observation means the earlier trust did not hold: it must be confirmed again for real.
            for (const key of trusted) if (key.startsWith(`${address}\n`)) trusted.delete(key);
            observations.set(address, { run, target: event.target, challenge, fingerprints: event.failure.fingerprints });
          }
          handlers.onEvent(event);
        },
        onClose() {
          for (const [address, observation] of observations) if (observation.run === run) observations.delete(address);
          if (options?.credential) secrets.delete(options.credential);
          handlers.onClose?.();
        },
      }, { ...options, takeAuth(target) {
        addresses.set(target.id, target.address.value);
        const reference = target.credential ?? options?.credential;
        if (!reference) return undefined;
        prune();
        const secret = secrets.get(reference);
        secrets.delete(reference);
        if (!secret || secret.target !== target.id || secret.address !== target.address.value) throw new ServiceError("That sign-in expired or belongs to another host. Enter it again.");
        return secret.auth;
      } });
      return run;
    },

    async mintCredential(secret: OneTimeSecret, target: string, address: string) {
      prune();
      const bytes = new TextEncoder();
      const prompt = (value: string): boolean => !!value && bytes.encode(value).length <= 16384 && !/[\0\r\n]/.test(value);
      if (!address || address.length > 512 || /[\0\r\n]/.test(address) || !/^[A-Za-z0-9._-]{1,128}$/.test(target) || secrets.size >= 16
        || (secret.kind === "password" ? !prompt(secret.text) : !secret.text || bytes.encode(secret.text).length > 24576 || secret.text.includes("\0") || secret.passphrase !== undefined && !prompt(secret.passphrase))) {
        throw new ServiceError("The sign-in input is invalid or too large. Enter it again.");
      }
      const reference = randomUuid();
      const auth = secret.kind === "password" ? { password: secret.text } : { key: secret.text, ...(secret.passphrase ? { passphrase: secret.passphrase } : {}) };
      secrets.set(reference, { target, address, auth, expires: Date.now() + 60000 });
      return reference;
    },

    dispose() { secrets.clear(); observations.clear(); trusting.clear(); trusted.clear(); },

    /**
     * Trusting is idempotent: any number of calls for the same observation make one confirmation.
     * A call while one is in flight for the same challenge and fingerprint joins it; a call after it succeeded
     * (and before the host shows another key) resolves at once. A newer observation of the host is its own
     * trust, never joined to an older one. A fingerprint the server never showed is refused every time.
     */
    trustHostKey(host, fingerprint) {
      const refuse = (): Promise<void> => Promise.reject(new ServiceError("Check the host key again before trusting it."));
      const key = `${host}\n${fingerprint}`;
      const observed = observations.get(host);
      if (!observed) return trusted.has(key) ? Promise.resolve() : refuse();
      if (!observed.fingerprints.includes(fingerprint)) return refuse();
      const flying = trusting.get(observed.challenge);
      if (flying && flying.fingerprint === fingerprint) return flying.work;
      const work = observed.run.confirmHostKey(observed.target, observed.challenge, fingerprint).then(() => {
        // Only the observation this trust confirmed is finished; a newer one for the host stays.
        if (observations.get(host) === observed) {
          observations.delete(host);
          trusted.add(key);
        }
      }).finally(() => { trusting.delete(observed.challenge); });
      trusting.set(observed.challenge, { fingerprint, work });
      return work;
    },

    async installCommand(host) {
      const response = await call("/v1/bootstrap/install-command", { method: "POST", body: { host } });
      if (response.status === 404 || response.status === 405 || response.status === 501) return undefined;
      if (!response.ok) throw refusal(response, "make an install command");
      return parseInstallCommand(await jsonOf(response));
    },
  };
}
