// SPDX-License-Identifier: AGPL-3.0-only
/**
 * Unlocking host connections (the CA, D168, D217), shared by every place that can do it.
 *
 * After a server restart the certificate authority is locked until an administrator confirms with a passkey. Three
 * surfaces offer that: the add-host wizard's first step, the command palette and Settings → Hosts. They must behave
 * identically, so the call and its words live here once:
 *
 * - `runUnlock` (authority-run.on-demand.ts) is the one ceremony call and the one failure wording; the wizard uses it
 *   directly because it continues into its own flow afterwards. It loads on first use, not with the canvas.
 * - `createAuthorityControl` is the client's view of the lock: it asks the server (`authorityStatus`) when the page
 *   starts, when Settings opens and after an unlock, keeps the answer, offers the palette row while it is locked,
 *   and runs the ceremony for the palette and Settings. No timers poll; the palette row reads the kept answer and
 *   asks again, in the background, each time it is built from an answer older than `STALE_MS`.
 *
 * A status the server refuses (a non-administrator, a server without the remote component) leaves the state
 * "unknown": nothing is offered and nothing is shown, because a control that cannot act is not drawn.
 */
import type { CoreScreen } from "../../core-screen";
import { ICONS } from "../../../../../packages/ui/src/icons";
import { onDemand } from "../../on-demand";
import type { ProvisioningService } from "./service";

export const ACTION_UNLOCK = "canvas:unlockauthority";
const STALE_MS = 30_000;

export type AuthorityState = "unknown" | "locked" | "unlocked";

export interface AuthorityControl {
  /** What was last learned from the server. */
  state(): AuthorityState;
  /** False for a viewer who is not an administrator: the state is shown, nothing can be done about it. */
  canUnlock(): boolean;
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
}

export function createAuthorityControl(core: CoreScreen, options: AuthorityOptions): AuthorityControl {
  let state: AuthorityState = "unknown";
  let busy = false;
  let checkedAt = 0;
  let pending: Promise<void> | undefined;
  const listeners = new Set<() => void>();
  const emit = (): void => { for (const listener of [...listeners]) listener(); };
  const service = options.service;

  const run = () => onDemand(() => import("./authority-run.on-demand"));
  const refresh = (): Promise<void> => pending ??= run().then(async (m) => {
    const next = await m.readState(await service());
    checkedAt = Date.now();
    if (next !== state) { state = next; emit(); }
  }).catch(() => undefined).then(() => { pending = undefined; });

  const unlock = async (): Promise<void> => {
    if (busy || state !== "locked") return;
    busy = true;
    // A failed chunk load leaves the lock as it was; the next try loads again.
    await run().then(async (m) => m.announce(core.toast, await m.runUnlock(await service()))).catch(() => undefined);
    busy = false;
    await refresh();
  };

  const canUnlock = options.canUnlock ?? ((): boolean => true);
  const removeProvider = core.addPaletteProvider(() => {
    if (Date.now() - checkedAt > STALE_MS) void refresh();
    if (state !== "locked" || !canUnlock()) return [];
    return [{
      group: "Actions", glyph: "◇", icon: ICONS.unlock,
      label: "Unlock host connections", hint: "confirm with your passkey", action: ACTION_UNLOCK,
    }];
  });
  const onAction = (event: Event): void => {
    if ((event as CustomEvent<{ action?: string }>).detail?.action === ACTION_UNLOCK) void unlock();
  };
  window.addEventListener("tracer:canvas-action", onAction);
  // Learn the state once the first screen has painted; it costs a status call and loads the ceremony code.
  const first = window.setTimeout(() => { void refresh(); }, 1200);

  return {
    state: () => state, canUnlock, refresh, unlock,
    onChange(listener) { listeners.add(listener); return () => { listeners.delete(listener); }; },
    dispose() { window.clearTimeout(first); window.removeEventListener("tracer:canvas-action", onAction); removeProvider(); listeners.clear(); },
  };
}
