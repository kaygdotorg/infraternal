// SPDX-License-Identifier: AGPL-3.0-only
/**
 * The product `ProvisioningService`: the provisioning API on the page's own origin.
 *
 * Specified by contracts/ssh-bootstrap.md (branch `ssh-bootstrap`, #87):
 * - `/v1/bootstrap/ws` (via `ProvisioningRun`): start, retry, replay and the event stream.
 * - `GET /v1/bootstrap/ssh-key`: the dedicated server key's public half (D181, D183).
 *
 * Proposed on #87 and not mounted by the server at the time of writing; each answers 404 or 405 until it
 * exists, and this adapter then reports the feature as unavailable instead of pretending:
 * - `GET  /v1/bootstrap/discovery`    -> `{"hosts":[DiscoveredHost-like]}` (authorized inventory only)
 * - `POST /v1/bootstrap/credential`   `{"kind":"private-key"|"password","secret":"...","passphrase"?}` -> `{"reference":"..."}`
 *   (one use, bound to this session, expires with it; the reference goes into `start`)
 * - `POST /v1/bootstrap/host-key`     `{"host":"user@host:22","fingerprint":"SHA256:..."}` -> 204
 *   (owner action that pins the observed key; the observation alone never updates known_hosts)
 * - `POST /v1/bootstrap/install-command` `{"host":"..."}` -> `{"command":"...","expires_in_seconds":900}`
 *
 * Secrets: bodies are sent once over the page's TLS connection with `cache: "no-store"`. Nothing is put in
 * a URL, a header or a log line, and the error text never repeats a body.
 */
import type { HostSource } from "../../../../../packages/ui/src/source-icons";
import type { HostPlatform } from "../../../../../packages/ui/src/host-icons";
import { ProvisioningRun, type ProvisioningHandlers, type ProvisioningOptions } from "../../provisioning-client";
import { ServiceError, type DiscoveredHost, type InstallCommand, type OneTimeSecret, type ProvisioningService, type SavedKey, type ServerKey } from "./service";

const isRecord = (value: unknown): value is Record<string, unknown> => typeof value === "object" && value !== null && !Array.isArray(value);
const PLATFORMS: readonly string[] = ["ubuntu", "debian", "proxmox", "redhat", "nixos", "apple", "unknown"];
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

export function parseServerKey(value: unknown): ServerKey | undefined {
  if (!isRecord(value) || typeof value.public_key !== "string" || typeof value.fingerprint !== "string") return undefined;
  return { publicKey: value.public_key, fingerprint: value.fingerprint, locked: value.locked === true };
}

export function parseInstallCommand(value: unknown): InstallCommand | undefined {
  if (!isRecord(value) || typeof value.command !== "string" || typeof value.expires_in_seconds !== "number") return undefined;
  return { command: value.command, expiresInSeconds: value.expires_in_seconds };
}

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
  return new ServiceError(`The server couldn't ${what} (${response.status}).`, response.status === 503 ? "unavailable" : "refused");
}

export function createRealProvisioning(): ProvisioningService {
  return {
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

    open(handlers: ProvisioningHandlers, options?: ProvisioningOptions) { return new ProvisioningRun(handlers, options); },

    async mintCredential(secret: OneTimeSecret) {
      const body = secret.kind === "private-key"
        ? { kind: secret.kind, secret: secret.text, ...(secret.passphrase ? { passphrase: secret.passphrase } : {}) }
        : { kind: secret.kind, secret: secret.text };
      const response = await call("/v1/bootstrap/credential", { method: "POST", body });
      if (!response.ok) throw refusal(response, "take a one-time sign-in");
      const reply = await jsonOf(response);
      if (reply === undefined) throw new ServiceError("This server can't take a one-time sign-in yet.", "unavailable");
      if (!isRecord(reply) || typeof reply.reference !== "string" || !/^[A-Za-z0-9._-]{1,128}$/.test(reply.reference)) throw new ServiceError("The server's answer was not understood.");
      return reply.reference;
    },

    async trustHostKey(host, fingerprint) {
      const response = await call("/v1/bootstrap/host-key", { method: "POST", body: { host, fingerprint } });
      if (!response.ok) throw refusal(response, "trust a host key");
    },

    async installCommand(host) {
      const response = await call("/v1/bootstrap/install-command", { method: "POST", body: { host } });
      if (response.status === 404 || response.status === 405 || response.status === 501) return undefined;
      if (!response.ok) throw refusal(response, "make an install command");
      return parseInstallCommand(await jsonOf(response));
    },
  };
}
