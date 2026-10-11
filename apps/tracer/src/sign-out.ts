/**
 * Signing out of this device (#171, TASTE "You can always sign yourself out").
 *
 * One path serves every way in: the profile pill's menu, the command palette and Settings, Account. Each asks once
 * with the shared compact confirmation (`askSignOut`), and a yes runs `signOut`:
 *
 *   1. The server ends this device's session (`logout`). That comes first and must succeed: with the cookie still
 *      valid, tearing the screen down would only look signed out until the next reload.
 *   2. The app lets go of everything the session owned (`registerSignOut`, set by main.ts): the terminals' live
 *      connections, the canvas and its inbox, the core screen, and the tab's session pointers. It then shows the
 *      sign-in screen.
 *
 * What stays: purely local preferences (theme, font, window sizes, toolbar order) and the canvas layout, which is
 * stored per account id and only ever read back by that account. Nothing the server would have to vouch for is kept.
 */
import { logout } from "./auth";
import type { ToastController } from "../../../packages/ui/src/toast";
import { mountConfirmTip, type ConfirmTipController } from "../../../packages/ui/src/tooltip";

/** The screen's transient message surface, narrowed to what a failed sign-out needs. */
export type SignOutToast = Pick<ToastController, "show">;

let teardown: (() => void) | undefined;

/** main.ts hands over the teardown: dispose every live part of the signed-in app and show the sign-in screen. */
export function registerSignOut(run: () => void): void { teardown = run; }

/** Browser-held pointers to this session's terminals; the tab keeps only a public id, never a credential. */
export function forgetSessionPointers(): void {
  try {
    for (const key of Object.keys(sessionStorage)) if (key.startsWith("tracer.session.")) sessionStorage.removeItem(key);
  } catch { /* storage is optional */ }
  // A `?session=` in the address would reattach the old terminal as soon as the next person signs in.
  const url = new URL(location.href);
  if (url.searchParams.has("session")) {
    url.searchParams.delete("session");
    history.replaceState(null, "", url);
  }
}

/** Signs this device out. Rejects, leaving the screen untouched, when the server could not end the session. */
export async function signOut(): Promise<void> {
  await logout();
  forgetSessionPointers();
  teardown?.();
}

/**
 * The compact confirmation, anchored to whatever the person used to ask. A failure is said in plain words on the
 * screen's toast; the person is still signed in and can try again.
 */
export function askSignOut(anchor: HTMLElement, toast: SignOutToast): ConfirmTipController {
  return mountConfirmTip(anchor, {
    label: "Sign out of this device",
    title: "Sign out of this device?",
    effect: "You will need your passkey to sign in again.",
    confirmLabel: "Sign out",
    cancelLabel: "Cancel",
    onConfirm: () => {
      void signOut().catch(() => toast.show({ message: "Could not sign out. Check your connection and try again.", tone: "error", duration: 5000 }));
    },
  });
}
