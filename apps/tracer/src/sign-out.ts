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
 * 3. The browser forgets the account (D245): `clearAccountStorage` removes its canvas layout, its session list and the
 *      tab's terminal pointers, after the teardown so the canvas's last flush cannot write them back, and the
 *      stores ignore writes once disposed. The layout is restored from the server on the next sign-in.
 *
 * What stays: explicit device-bound choices such as a custom toolbar override and device name. The account look
 * cache is removed with that account, while the old unscoped appearance keys remain only until their canvas look is
 * confirmed by the server; their migration owner prevents another account from consuming them. Other accounts' keys
 * on the same browser are untouched.
 */
import { forgetAccountWork, pauseAccountWork } from "./account-lifetime";
import { logout } from "./auth";
import { clearAccountStorage } from "./account-storage";
import type { ToastController } from "../../../packages/ui/src/toast";
import { mountConfirmTip, type ConfirmTipController } from "../../../packages/ui/src/tooltip";

/** The screen's transient message surface, narrowed to what a failed sign-out needs. */
export type SignOutToast = Pick<ToastController, "show">;

let announce: (account: string) => void = () => {};
let freezing: (value: boolean) => void = () => {};
let currentLifetime: () => unknown = () => undefined;
let signingOut: { lifetime: unknown; promise: Promise<void> } | undefined;
let teardown: (() => void) | undefined;
let currentAccount: () => string | undefined = () => undefined;

/**
 * main.ts hands over the teardown (dispose every live part of the signed-in app and show the sign-in screen) and a
 * way to read which account is signed in.
 */
export function registerSignOut(run: () => void, account: () => string | undefined, freeze: (value: boolean) => void = () => {}, notify: (account: string) => void = () => {}, lifetime: () => unknown = () => undefined): void { teardown = run; currentAccount = account; freezing = freeze; announce = notify; currentLifetime = lifetime; }

/** A `?session=` in the address would reattach the old terminal as soon as the next person signs in. */
function forgetSessionAddress(): void {
  const url = new URL(location.href);
  if (url.searchParams.has("session")) {
    url.searchParams.delete("session");
    history.replaceState(null, "", url);
  }
}

/** Signs this device out. Rejects, leaving the screen untouched, when the server could not end the session. */
export function signOut(): Promise<void> {
  const lifetime = currentLifetime();
  if (signingOut && signingOut.lifetime === lifetime) return signingOut.promise;
  const account = currentAccount();
  freezing(true); pauseAccountWork(account, true);
  const promise: Promise<void> = (async () => {
    try { await logout(); }
    catch (error) { if (currentLifetime() === lifetime) { pauseAccountWork(account, false); freezing(false); } throw error; }
    // Another screen may have signed in while this response was delayed. It owns its own work.
    if (currentLifetime() !== lifetime) return;
    if (account) announce(account);
    forgetAccountWork(account); teardown?.();
    if (!clearAccountStorage(account)) {
      // Cleanup is transitional only. No new private writer exists while these retries wait.
      let attempts = 0;
      const retry = (): void => { if (!clearAccountStorage(account) && ++attempts < 3) setTimeout(retry, 1000); };
      setTimeout(retry, 1000);
      console.warn("Some legacy layout data could not be removed from this browser.");
    }
    forgetSessionAddress();
  })().finally(() => { if (signingOut?.promise === promise) signingOut = undefined; });
  signingOut = { lifetime, promise };
  return promise;
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
