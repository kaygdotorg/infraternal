// SPDX-License-Identifier: AGPL-3.0-only
/**
 * The canvas's handle on the client's view of the certificate authority: its lock and its roots' expiry warnings
 * (D168, D217, D234, #285).
 *
 * The control itself (the status check, the sign-in toast, the inbox card, the palette row) is
 * `authority-control.on-demand.ts`. Nothing about it is needed for the first screen or the first interaction: it learns
 * the state 1.2 s after the canvas is made, so this handle fetches the module when the browser is idle before then (D188, #322)
 * and every call that arrives earlier waits for it. Until it has loaded, the state is "unknown", which is also what the
 * control answers until its first status check: nothing is offered and nothing is shown.
 *
 * This file holds the types every user of the control shares, and nothing else that costs bytes.
 */
import type { CoreScreen } from "../../core-screen";
import { onDemand, whenIdle } from "../../on-demand";
import type { ProvisioningService } from "./service";

export type AuthorityState = "unknown" | "locked" | "unlocked";

/** The canvas's view of the CA: its lock state, root expiry warnings and the unlock ceremony. */
export interface AuthorityControl {
  /** What was last learned from the server. */
  state(): AuthorityState;
  /** False for a viewer who is not an administrator: the state is shown, nothing can be done about it. */
  canUnlock(): boolean;
  /**
   * One line per CA root inside a warning window (365/90/30/7 days, expired, or unknown time), already worded.
   * Empty for viewers who are not administrators: the server is the authority on who may see root expiry.
   */
  expiryWarnings(): readonly string[];
  /** Opens Settings → Hosts, where the warning is shown next to the lock. */
  review(): void;
  /** Asks the server again; listeners hear it when the answer changes. */
  refresh(): Promise<void>;
  /** Runs the ceremony, tells the person the outcome, and refreshes. */
  unlock(): Promise<void>;
  /** Called when the state changes; returns a remover. */
  onChange(listener: () => void): () => void;
  dispose(): void;
}

export interface AuthorityOptions {
  service: () => Promise<ProvisioningService>;
  /** Whether the viewer is an administrator, when the client knows; the server enforces it either way. */
  canUnlock?: () => boolean;
  /** Whether any host other than this server itself exists; see `authority-control.on-demand.ts`. Absent means "yes". */
  hasRemoteHosts?: () => boolean;
}

/** Waits at most this long for the browser to be idle: the real control's first check is due 1.2 s after the handle. */
const WARM_WITHIN_MS = 600;

/** Create the thin CA control handle; the real control loads on demand when the browser is idle. */
export function createAuthorityControl(core: CoreScreen, options: AuthorityOptions): AuthorityControl {
  const createdAt = Date.now();
  const listeners = new Set<() => void>();
  let real: AuthorityControl | undefined;
  let loading: Promise<AuthorityControl | undefined> | undefined;
  let disposed = false;
  let off: (() => void) | undefined;
  const load = (): Promise<AuthorityControl | undefined> => loading ??= onDemand(() => import("./authority-control.on-demand")).then((m) => {
    if (disposed) return undefined;
    real = m.makeAuthorityControl(core, options, createdAt);
    off = real.onChange(() => { for (const listener of [...listeners]) listener(); });
    return real;
  }, (error: unknown) => { loading = undefined; throw error; });
  whenIdle(() => { void load().catch(() => undefined); }, WARM_WITHIN_MS);
  return {
    state: () => real?.state() ?? "unknown",
    canUnlock: () => real?.canUnlock() ?? options.canUnlock?.() ?? true,
    expiryWarnings: () => real?.expiryWarnings() ?? [],
    review: () => { void load().then((control) => control?.review(), () => undefined); },
    refresh: () => load().then((control) => control?.refresh(), () => undefined),
    unlock: () => load().then((control) => control?.unlock(), () => undefined),
    onChange(listener) { listeners.add(listener); return () => { listeners.delete(listener); }; },
    dispose() { disposed = true; off?.(); real?.dispose(); listeners.clear(); },
  };
}
