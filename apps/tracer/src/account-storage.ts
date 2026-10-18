/**
 * Where the browser keeps data that belongs to one account (D245, #171).
 *
 * Every account-scoped key is built here and nowhere else, so the one function that removes an account's data on
 * sign-out (`clearAccountStorage`) and the code that writes it can never drift apart. Device-wide preferences that
 * hold no account data (theme, font, window sizes, toolbar order, device name) deliberately do not live here.
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

/** localStorage: the canvas document (windows, columns, views) of one account. */
export const canvasKey = (account: string): string => CANVAS + account;
/** localStorage: public identity labels needed to draw a cached layout offline, never authority. */
export const drawingIdentityKey = (account: string): string => DRAWING_IDENTITY + account;
/** localStorage: the session names, pins and recency of one account. */
export const inventoryKey = (account: string): string => INVENTORY + account;
/** sessionStorage: the public id of the terminal this tab last had open for one account. */
export const tabSessionKey = (account: string): string => TAB_SESSION + account;
/**
 * localStorage: how often one account has signed in on this device and which explanatory hints it was already
 * shown (`hints.ts`). It is deliberately not swept by `clearAccountStorage`: a sign-out followed by a sign-in is
 * the next sign-in, not a fresh start, and the hint rule counts sign-ins. It holds two small numbers per hint.
 */
export const hintsKey = (account: string): string => HINTS + account;
/** localStorage: the public id of the account that last signed in on this device. */
export const lastAccountKey = LAST_ACCOUNT;

function sweep(area: Storage, prefix: string, account: string | undefined): void {
  const keys: string[] = [];
  for (let i = 0; i < area.length; i++) { const key = area.key(i); if (key?.startsWith(prefix)) keys.push(key); }
  for (const key of keys) if (account === undefined || key === prefix + account) area.removeItem(key);
}

/** Removes everything the browser holds for `account` (or for every account when it is unknown). */
export function clearAccountStorage(account: string | undefined): void {
  try {
    sweep(localStorage, CANVAS, account);
    sweep(localStorage, DRAWING_IDENTITY, account);
    sweep(localStorage, INVENTORY, account);
    sweep(sessionStorage, TAB_SESSION, account);
    // The last-account pointer names a person; it goes unless another account has since replaced it.
    if (account === undefined || localStorage.getItem(LAST_ACCOUNT) === account) localStorage.removeItem(LAST_ACCOUNT);
  } catch { /* storage is blocked: nothing was written either */ }
}
