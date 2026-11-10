/**
 * Where the browser keeps data that belongs to one account (D245, #171).
 *
 * Account-scoped caches are removed with the signed-in account on sign-out. The derived appearance cache uses the
 * same account id as the server document; only explicitly device-bound choices such as the toolbar override and device
 * name stay outside this scope.
 *
 * Two accounts can share a browser: each key ends in the account id, and clearing removes only the keys of the account
 * that signed out. When the id is not known the sweep removes every account's keys, which loses a layout the server
 * will restore but never leaves a signed-out account's data behind.
 */

const CANVAS = "infraternal.canvas.";
const DRAWING_IDENTITY = "tracer.drawing-identity.";
const INVENTORY = "tracer.sessions.";
const TAB_SESSION = "tracer.session.";
const LAST_ACCOUNT = "tracer.user-id";
const HINTS = "tracer.hints.";
/** localStorage: the public id of the account that owns the not-yet-migrated device-wide appearance values. */
export const LEGACY_OWNER_KEY = "tracer.look.legacy-owner";
/** Device-wide appearance keys of earlier releases; they move into the account look and are removed once the server confirms it. */
export const LEGACY_APPEARANCE_KEYS = [
  "tracer.look", "tracer.theme", "tracer.font", "tracer.ui-size.v2", "tracer.ui-size",
  "tracer.window-size.phone", "tracer.window-size.desktop", "tracer.extended-info", "tracer.card", "tracer.windows", "tracer.background", "tracer.ui-font",
] as const;

/** localStorage: the canvas document (windows, columns, views) of one account. */
export const canvasKey = (account: string): string => CANVAS + account;
/** localStorage: public identity labels needed to draw a cached layout offline, never authority. */
export const drawingIdentityKey = (account: string): string => DRAWING_IDENTITY + account;
/** localStorage: the session names, pins and recency of one account. */
export const inventoryKey = (account: string): string => INVENTORY + account;
/** sessionStorage: the public id of the terminal this tab last had open for one account. */
export const tabSessionKey = (account: string): string => TAB_SESSION + account;
/** Legacy account-scoped hint key, read only for sign-out cleanup. */
export const hintsKey = (account: string): string => HINTS + account;
/** localStorage: the public id of the account that last signed in on this device. */
export const lastAccountKey = LAST_ACCOUNT;

function sweep(area: Storage, prefix: string, account: string | undefined): void {
  const keys: string[] = [];
  for (let i = 0; i < area.length; i++) { const key = area.key(i); if (key?.startsWith(prefix)) keys.push(key); }
  for (const key of keys) if (account === undefined || key === prefix + account || key.startsWith(prefix + account + ".")) area.removeItem(key);
}

/** Removes everything the browser holds for `account` (or for every account when it is unknown). */
export function clearAccountStorage(account: string | undefined): boolean {
  try {
    sweep(localStorage, CANVAS, account);
    sweep(localStorage, "infraternal.canvas-journal.", account);
    sweep(localStorage, "infraternal.canvas-lifetime.", account);
    sweep(localStorage, DRAWING_IDENTITY, account);
    sweep(localStorage, INVENTORY, account);
    sweep(localStorage, "tracer.look.account.", account);
    sweep(localStorage, HINTS, account);
    sweep(sessionStorage, TAB_SESSION, account);
    // The marker names the account that owns the unmigrated old appearance values; it must not outlive that account's
    // sign-out (D245). The old values themselves are device-wide choices and stay, like the toolbar override.
    if (account === undefined || localStorage.getItem(LEGACY_OWNER_KEY) === account) localStorage.removeItem(LEGACY_OWNER_KEY);
    // The last-account pointer names a person; it goes unless another account has since replaced it.
    if (account === undefined || localStorage.getItem(LAST_ACCOUNT) === account) localStorage.removeItem(LAST_ACCOUNT);
    return true;
  } catch { return false; /* Legacy erasure must never claim success when access was refused. */ }
}

/** Read an account drawing cache without making storage availability part of the interaction path. */
export function readStoredJson(key: string, storage?: () => Pick<Storage, "getItem">): unknown {
  try { return JSON.parse((storage ? storage() : localStorage).getItem(key) ?? "null") as unknown; } catch { return undefined; }
}
/** In-memory account notifications share a disposal boundary; there is no storage writer (D312). */
export function createAccountNotifications() {
  let disposed = false;
  const listeners = new Set<() => void>();
  return {
    notify() { if (!disposed) for (const listener of listeners) listener(); },
    subscribe(listener: () => void) { if (!disposed) listeners.add(listener); return () => { listeners.delete(listener); }; },
    dispose() { disposed = true; listeners.clear(); },
  };
}
