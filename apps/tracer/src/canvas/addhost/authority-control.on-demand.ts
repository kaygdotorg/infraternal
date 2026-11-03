// SPDX-License-Identifier: AGPL-3.0-only
/**
 * Unlocking host connections (the CA, D168, D217), shared by every place that can do it. This is the real control; the
 * canvas holds the thin handle in `authority-unlock.ts` (types, the same calls) and fetches this module when the browser is
 * idle after the first screen, so the status check, the inbox card and their code stay out of the deferred transfer
 * (D188, #322). A call made before it has arrived waits for it.
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
 * The lock is also a pending item (D234). When a page learns for the first time that the CA is locked and the viewer
 * can unlock it, one persistent toast offers "Unlock" (at every sign-in, because every sign-in is a fresh page). It
 * carries the lock glyph, not the success tick: a locked state is waiting, not done. It expires after `TOAST_MS`
 * (the owner allows this: the item then lives in the inbox, so nothing is lost) or when the person dismisses it.
 * When that toast is dismissed or expires the item moves to the sidebar inbox and stays there until the state
 * changes, however it changes: the same refresh points as above (page start, Settings, the palette, an unlock, and the
 * page becoming visible again, which is how another tab's unlock reaches this one) make the card and the dot
 * vanish by themselves. Nothing polls.
 *
 * A status the server refuses (a non-administrator, a server without the remote component) leaves the state
 * "unknown": nothing is offered and nothing is shown, because a control that cannot act is not drawn.
 */
import type { CoreScreen } from "../../core-screen";
import type { AuthorityControl, AuthorityOptions, AuthorityState } from "./authority-unlock";
import { ACTION_UNLOCK } from "./authority-run.on-demand";
import { ICONS } from "../../../../../packages/ui/src/icons";
import { onDemand } from "../../on-demand";
import { existingInbox, inboxFor } from "../inbox-host";

const STALE_MS = 30_000;
/** The first status check, counted from the handle's creation. */
const FIRST_CHECK_MS = 1200;
/** A page coming back into view asks again when its answer is older than this; it is how another tab's unlock arrives. */
const RESUME_MS = 5_000;
/** The sign-in toast waits this long for the person before it hands the item to the inbox. */
const TOAST_MS = 30_000;
/** Calm and literal: the lock is routine after every restart, so the words say why and what to do, not "locked". */
export const LOCKED_TITLE = "The server restarted. Confirm your passkey once to reconnect your hosts.";
/** The inbox line: what the person does, not the state. The toast keeps the state wording. */
export const UNLOCK_TITLE = "Unlock host connections";
export const LOCKED_DETAIL = "The server restarted, so it needs your passkey once to reconnect your hosts.";

/** `createdAt`: when the handle was made; the first status check keeps its place in time (1.2 s after it) however late this module arrived. */
export function makeAuthorityControl(core: CoreScreen, options: AuthorityOptions, createdAt = Date.now()): AuthorityControl {
  let state: AuthorityState = "unknown";
  let busy = false;
  let checkedAt = 0;
  let pending: Promise<void> | undefined;
  const listeners = new Set<() => void>();
  const emit = (): void => { for (const listener of [...listeners]) listener(); };
  const service = options.service;

  // The item waits in the inbox only once the sign-in toast is over (dismissed, expired, replaced or used), and not
  // while the ceremony runs, so the card never flickers behind the passkey prompt.
  let offered = false;
  let toastOver = false;
  let toastOpen = false;
  const publish = (): void => {
    const waiting = state === "locked" && toastOver && !busy;
    const inbox = waiting ? inboxFor(core) : existingInbox(core);
    inbox?.set("authority", waiting ? [{
      id: "authority-locked", icon: ICONS.lock, title: UNLOCK_TITLE, body: LOCKED_DETAIL, canAct: options.canUnlock?.() ?? true,
      actions: [{ label: "Unlock", primary: true, run: () => { void unlock(); } }],
    }] : []);
  };
  const offerToast = (): void => {
    if (offered || state !== "locked" || !(options.canUnlock?.() ?? true)) return;
    offered = true;
    toastOpen = true;
    core.toast.show({
      message: LOCKED_TITLE, duration: TOAST_MS, dismissible: true, icon: ICONS.lock,
      action: { label: "Unlock", onSelect: () => { void unlock(); } },
      onClose: () => { toastOpen = false; toastOver = true; publish(); },
    });
  };

  const run = () => onDemand(() => import("./authority-run.on-demand"));
  const refresh = (): Promise<void> => pending ??= run().then(async (m) => {
    const next = await m.readState(await service());
    checkedAt = Date.now();
    if (next !== state) {
      state = next;
      // Unlocked elsewhere while the sign-in toast is still up: it has nothing left to offer.
      if (state === "unlocked" && toastOpen) core.toast.dismiss();
      offerToast(); publish(); emit();
    }
  }).catch(() => undefined).then(() => { pending = undefined; });

  const unlock = async (): Promise<void> => {
    if (busy || state !== "locked") return;
    busy = true;
    publish();
    // A failed chunk load leaves the lock as it was; the next try loads again.
    await run().then(async (m) => m.announce(core.toast, await m.runUnlock(await service()))).catch(() => undefined);
    busy = false;
    await refresh();
    publish();
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
  // A page that was hidden (another tab, a locked phone) asks again when it returns: another tab's unlock arrives here.
  const onVisible = (): void => { if (document.visibilityState === "visible" && Date.now() - checkedAt > RESUME_MS) void refresh(); };
  document.addEventListener("visibilitychange", onVisible);
  const first = window.setTimeout(() => { void refresh(); }, Math.max(0, FIRST_CHECK_MS - (Date.now() - createdAt)));

  return {
    state: () => state, canUnlock, refresh, unlock,
    onChange(listener) { listeners.add(listener); return () => { listeners.delete(listener); }; },
    dispose() { window.clearTimeout(first); window.removeEventListener("tracer:canvas-action", onAction); document.removeEventListener("visibilitychange", onVisible); removeProvider(); existingInbox(core)?.set("authority", []); listeners.clear(); },
  };
}
