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
 * The same status carries each CA root's expiry warning level (#285). Administrators see a warning in Settings → Hosts
 * and as an inbox card at 365, 90, 30 and 7 days before a root expires, once it has expired, and when the server cannot
 * trust its own clock. The card's "Review" opens Settings → Hosts.
 *
 * A status the server refuses (a non-administrator, a server without the remote component) leaves the state
 * "unknown": no lock or expiry data is shown, because the server is the authority for administrator visibility.
 */
import type { CoreScreen } from "../../core-screen";
import type { AuthorityControl, AuthorityOptions, AuthorityState } from "./authority-unlock";
import { ACTION_UNLOCK } from "./authority-run.on-demand";
import type { AuthorityRootStatus, AuthorityStatus } from "./service";
import { ICONS } from "../../../../../packages/ui/src/icons";
import type { InboxItem } from "../../../../../packages/ui/src/inbox";
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

/** A compact countdown for Settings and Inbox, based on the server's remaining lifetime. */
export function expiryWarningTitle(root: AuthorityRootStatus): string {
  if (root.warning_level === "expired") return "CA root expired";
  if (root.warning_level === "unknown" || root.remaining_seconds === null) return "CA expiry unknown";
  const days = Math.max(1, Math.ceil(Math.max(0, root.remaining_seconds) / 86_400));
  return `CA expires: ${days} days`;
}

/** `createdAt`: when the handle was made; the first status check keeps its place in time (1.2 s after it) however late this module arrived. */
export function makeAuthorityControl(core: CoreScreen, options: AuthorityOptions, createdAt = Date.now()): AuthorityControl {
  let state: AuthorityState = "unknown";
  let status: AuthorityStatus | undefined;
  let busy = false;
  let checkedAt = 0;
  let pending: Promise<void> | undefined;
  const listeners = new Set<() => void>();
  const emit = (): void => { for (const listener of [...listeners]) listener(); };
  const service = options.service;
  const canUnlock = options.canUnlock ?? ((): boolean => true);
  // "The server restarted, confirm to reconnect your hosts" is news only when a host exists whose connection is
  // locked. A brand-new account has none, so neither the toast nor the inbox card is shown (#512); the palette row
  // stays, because the first host needs the unlock too. Absent answer means a host exists.
  const hasHosts = options.hasRemoteHosts ?? ((): boolean => true);

  const warningRoots = (): AuthorityRootStatus[] => {
    if (!status?.initialized || !canUnlock()) return [];
    return (status.roots ?? []).filter((root) => root.warning_level !== "none");
  };
  const review = (): void => {
    if (!canUnlock()) return;
    window.dispatchEvent(new CustomEvent("tracer:canvas-action", {
      detail: { action: "canvas:settings:hosts", source: "pointer" },
    }));
  };

  // The item waits in the inbox only once the sign-in toast is over (dismissed, expired, replaced or used), and not
  // while the ceremony runs, so the card never flickers behind the passkey prompt.
  let offered = false;
  let toastOver = false;
  let toastOpen = false;
  /** Our sign-in toast only: other toasts in the stack (an error beside it) are not ours to dismiss. */
  let toastId: string | undefined;
  const publish = (): void => {
    const waiting = state === "locked" && toastOver && !busy && hasHosts();
    const items: InboxItem[] = warningRoots().map((root) => ({
      id: `authority-expiry-${root.generation}`,
      icon: ICONS.warning,
      title: expiryWarningTitle(root),
      body: root.warning_level === "unknown" || root.remaining_seconds === null
        ? "Check server time, then review the root in Settings → Hosts."
        : "Review the root in Settings → Hosts.",
      actions: [{ label: "Review", run: review }],
    }));
    if (waiting && canUnlock()) items.unshift({
      id: "authority-locked", icon: ICONS.lock, title: UNLOCK_TITLE, body: LOCKED_DETAIL, canAct: true,
      actions: [{ label: "Unlock", primary: true, run: () => { void unlock(); } }],
    });
    const inbox = items.length ? inboxFor(core) : existingInbox(core);
    inbox?.set("authority", items);
  };
  const offerToast = (): void => {
    if (offered || state !== "locked" || !canUnlock() || !hasHosts()) return;
    offered = true;
    toastOpen = true;
    toastId = core.toast.show({
      message: LOCKED_TITLE, duration: TOAST_MS, dismissible: true, icon: ICONS.lock,
      action: { label: "Unlock", onSelect: () => { void unlock(); } },
      onClose: () => { toastOpen = false; toastOver = true; publish(); },
    });
  };

  const run = () => onDemand(() => import("./authority-run.on-demand"));
  const refresh = (): Promise<void> => pending ??= run().then(async (m) => {
    // Root warnings can change while the lock state stays the same, so every answer republishes.
    status = await m.readStatus(await service());
    state = status?.locked === true ? "locked" : status?.locked === false ? "unlocked" : "unknown";
    checkedAt = Date.now();
    // Unlocked elsewhere while the sign-in toast is still up: it has nothing left to offer.
    if (state === "unlocked" && toastOpen) core.toast.dismiss(toastId);
    offerToast(); publish(); emit();
  }).catch(() => {
    status = undefined;
    state = "unknown";
    checkedAt = Date.now();
    publish(); emit();
  }).then(() => { pending = undefined; });

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
  // The host list can arrive after the first status answer; the toast and the card follow it, in either direction.
  const offHosts = options.onHostsChange?.(() => { offerToast(); publish(); });
  const first = window.setTimeout(() => { void refresh(); }, Math.max(0, FIRST_CHECK_MS - (Date.now() - createdAt)));

  return {
    state: () => state, canUnlock, expiryWarnings: () => warningRoots().map(expiryWarningTitle), review, refresh, unlock,
    onChange(listener) { listeners.add(listener); return () => { listeners.delete(listener); }; },
    dispose() { offHosts?.(); window.clearTimeout(first); window.removeEventListener("tracer:canvas-action", onAction); document.removeEventListener("visibilitychange", onVisible); removeProvider(); existingInbox(core)?.set("authority", []); listeners.clear(); },
  };
}
