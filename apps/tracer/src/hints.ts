/**
 * The "teach once" gate for explanatory hints (docs/design/TASTE.md, "Teach once, then stay quiet").
 *
 * A hint that only explains expected behaviour ("Session keeps running" after a close) shows on the first time in a
 * sign-in, and only during an account's first five sign-ins on this device. After that the action just happens.
 * Errors and things that need the person never go through here.
 *
 * A sign-in is counted once, where it completes (`recordSignIn`: passkey sign-in and recovery), never on a page
 * reload of a live sign-in. The record lives in account-scoped storage (`hintsKey`) as the sign-in count plus, per
 * hint, the sign-in it was last shown in, so a reload inside the same sign-in does not show it again. Storage that
 * cannot be read or written means "do not show": a hint is never worth a throw or a repeated nag.
 */
import { hintsKey } from "./account-storage";

/** Sign-ins during which hints are still shown. */
export const TEACH_SIGN_INS = 5;

interface HintRecord { signIns: number; shown: Record<string, number> }

function read(account: string): HintRecord {
  const raw = localStorage.getItem(hintsKey(account));
  const v = raw ? (JSON.parse(raw) as Partial<HintRecord> | null) : null;
  const signIns = typeof v?.signIns === "number" && Number.isFinite(v.signIns) ? v.signIns : 0;
  const shown = v?.shown && typeof v.shown === "object" ? v.shown : {};
  return { signIns, shown };
}

/** Counts one completed sign-in of `account` on this device. */
export function recordSignIn(account: string): void {
  try {
    const r = (() => { try { return read(account); } catch { return { signIns: 0, shown: {} }; } })();
    localStorage.setItem(hintsKey(account), JSON.stringify({ signIns: r.signIns + 1, shown: r.shown }));
  } catch { /* storage is blocked: hints stay quiet */ }
}

/** True once per sign-in, during the first five, for `hint`; the answer is remembered so the next call is false. */
export function teachOnce(account: string, hint: string): boolean {
  try {
    const r = read(account);
    // An account that signed in before the counter existed counts as being in its first sign-in.
    const nth = Math.max(r.signIns, 1);
    if (nth > TEACH_SIGN_INS || r.shown[hint] === nth) return false;
    r.shown[hint] = nth;
    localStorage.setItem(hintsKey(account), JSON.stringify({ signIns: r.signIns, shown: r.shown }));
    return true;
  } catch { return false; }
}
