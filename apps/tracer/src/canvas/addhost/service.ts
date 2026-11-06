// SPDX-License-Identifier: AGPL-3.0-only
/**
 * The seam between the add-host wizard and whatever provisions hosts (D183, #87).
 *
 * The wizard never talks to a socket or an endpoint. It asks a `ProvisioningService` for the things it
 * needs and gets plain data back. Two implementations exist: `real.ts` speaks the provisioning API of
 * contracts/ssh-bootstrap.md on the page's origin, and `mock/addhost-service.ts` (mockups only) speaks the
 * same wire protocol to the test double and adds fake discovery. A feature the server cannot do yet is a
 * method that returns `undefined` or rejects with a `ServiceError` whose text is shown as is; the wizard
 * never fakes success.
 *
 * Secrets: local one-use references are bound to a target; their private inputs travel only on the
 * authenticated bootstrap socket and are discarded when the run ends.
 */
import type { HostPlatform } from "../../../../../packages/ui/src/host-icons";
import type { HostSource } from "../../../../../packages/ui/src/source-icons";
import type { ProvisioningHandlers, ProvisioningOptions, ProvisioningRun } from "../../provisioning-client";

/** A host the server found and may be able to add. Every field beyond the identity is optional. */
export interface DiscoveredHost {
  /** The inventory id sent as `{kind: "discovered"}`. */
  id: string;
  /** Login name the server would use. */
  user?: string;
  address: string;
  os?: HostPlatform;
  operatingSystem?: string;
  architecture?: string;
  sources: HostSource[];
  /** What discovery knows without logging in. */
  reach?: "ready" | "unreachable" | "mesh-policy";
  evidence?: string;
  alreadyAdded?: boolean;
  /** Discovery saw passwordless sudo; only then is the root choice offered (D139). */
  rootAvailable?: boolean;
}

/** The server's own public key (D181, D183): what the person adds to a host's authorized keys. */
export interface ServerKey {
  publicKey: string;
  fingerprint: string;
  /** The private half is not unlocked yet (cold start); the public key can still be trusted on hosts. */
  locked: boolean;
}

/** Public root metadata returned with CA lock state; the root certificate body stays unused by status surfaces. */
export interface AuthorityRootStatus {
  generation: number;
  fingerprint: string;
  not_after: number;
  remaining_seconds: number | null;
  warning_level: "none" | "365d" | "90d" | "30d" | "7d" | "expired" | "unknown";
}

/** Public-only CA status for administrators. Older servers may return only initialization and lock state. */
export interface AuthorityStatus {
  available?: boolean;
  initialized: boolean;
  locked: boolean | null;
  clock_healthy?: boolean;
  roots?: AuthorityRootStatus[];
}

/** What the person typed once for one connection. It is consumed once by the authenticated bootstrap socket. */
export type OneTimeSecret =
  | { kind: "private-key"; text: string; passphrase?: string }
  | { kind: "password"; text: string };

/** The one-line command for a host this server cannot reach (the host dials in, D64). */
export interface InstallCommand {
  command: string;
  /** Seconds the invitation inside it stays valid (900 per contracts/remote.md). */
  expiresInSeconds: number;
}

/** A key the person keeps in this browser, wrapped by their passkey. Unwrapped only for one connection. */
export interface SavedKey {
  /** A name to show, e.g. "work laptop key". */
  label: string;
  /** Asks for the passkey and returns the private key text. Rejects when the person cancels. */
  unwrap(): Promise<string>;
}

/** A failure the wizard shows as is. `unavailable` means the server does not offer the feature yet. */
export class ServiceError extends Error {
  constructor(message: string, readonly kind: "unavailable" | "refused" | "network" = "refused") { super(message); }
}

/** What the add-host flow needs from the server: discovery, CA status and unlock, and enrollment. */
export interface ProvisioningService {
  /** Hosts this server can reach and the person may add. Empty when discovery is off or finds nothing. */
  discover(): Promise<DiscoveredHost[]>;
  /** Checks CA lock and public expiry status before SSH; the server restricts root metadata to administrators. */
  authorityStatus?(): Promise<AuthorityStatus>;
  unlockAuthority?(): Promise<void>;
  /** The dedicated server key, or undefined when this server has none to show (no custody yet). */
  serverKey(): Promise<ServerKey | undefined>;
  /** The passkey-wrapped key this browser holds, if any. */
  savedKey(): Promise<SavedKey | undefined>;
  /** Opens one provisioning batch (one socket). The caller closes it. */
  open(handlers: ProvisioningHandlers, options?: ProvisioningOptions): ProvisioningRun;
  /** Keeps one secret briefly for one target; resolves to a local one-use reference. */
  mintCredential(secret: OneTimeSecret, target: string, address: string): Promise<string>;
  /** Discards private inputs when the flow is disposed. */
  dispose?(): void;
  /** Pins an observed host key after the person compared its fingerprint. Never called without a click. */
  trustHostKey(host: string, fingerprint: string): Promise<void>;
  /** The install command for a host that cannot be reached from here, or undefined if unavailable. */
  installCommand(host: string): Promise<InstallCommand | undefined>;
}

/** What the canvas receives when hosts finish enrolling (the hook the composition root implements). */
export interface EnrolledHost {
  /** The admitted remote host UUID returned by the server. */
  hostId?: string;
  /** An already-running shim session; opening the canvas must attach to it. */
  sessionId?: string;
  address?: string;
  /** Stable key in the wizard: the discovered id or the typed host. */
  id: string;
  name: string;
  user: string | undefined;
  os: HostPlatform;
  mode: "rootless" | "root";
}

export interface AddHostSink {
  /** Start optional local renderer preparation alongside sign-in. */
  prepareTerminal?(): void;
  /**
   * Called once per batch result with the hosts that are ready, in the order they finished. `status` is the wizard's
   * glyph for the host just handed over (D255): the canvas moves the setup that goes on behind the shell from there into
   * the new window's machine pill, so it must read the glyph's box before returning.
   */
  enrolled(hosts: EnrolledHost[], status?: Element): void;
  /** True when the canvas shows each host's remaining setup in its machine pill: the wizard then skips its "ready" toast. */
  readonly setupInPill?: boolean;
  /** Opens a new terminal on a host that is already added (the failure named it); the canvas focuses it. */
  openHost?(hostId: string): void;
  /** Whether this page lists the host. An id the page does not know would open a window titled with a raw UUID. */
  hasHost?(hostId: string): boolean;
}
