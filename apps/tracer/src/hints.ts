/**
 * The "teach once" gate for explanatory hints (docs/design/TASTE.md, "Teach once, then stay quiet").
 *
 * A hint that only explains expected behaviour ("Session keeps running" after a close) shows on the first time in a
 * sign-in, and only during the first five sign-ins on this device. After that the action just happens.
 * Errors and things that need the person never go through here.
 *
 * A sign-in is counted once, where it completes (`recordSignIn`: passkey sign-in and recovery), never on a page
 * reload of a live sign-in. Only anonymous device-wide counters are persisted (D312).
 * Accounts sharing a device share the teaching budget; account identity never enters browser storage.
 * Storage refusal keeps hints quiet.
 */
// Device-wide teaching counters contain no account identifier or account-derived key.
const hintStorageKey = "tracer.hints";

/** Sign-ins during which hints are still shown. */
export const TEACH_SIGN_INS = 5;

interface HintRecord { signIns: number; shown: Record<string, number> }

function read(): HintRecord {
  const raw = localStorage.getItem(hintStorageKey);
  const v = raw ? (JSON.parse(raw) as Partial<HintRecord> | null) : null;
  const signIns = typeof v?.signIns === "number" && Number.isFinite(v.signIns) ? v.signIns : 0;
  const shown = v?.shown && typeof v.shown === "object" ? v.shown : {};
  return { signIns, shown };
}

/** Counts one completed sign-in of `account` on this device. */
export function recordSignIn(_account: string): void {
  try {
    const r = (() => { try { return read(); } catch { return { signIns: 0, shown: {} }; } })();
    localStorage.setItem(hintStorageKey, JSON.stringify({ signIns: r.signIns + 1, shown: r.shown }));
  } catch { /* storage is blocked: hints stay quiet */ }
}

/** True once per sign-in, during the first five, for `hint`; the answer is remembered so the next call is false. */
export function teachOnce(_account: string, hint: string): boolean {
  try {
    const r = read();
    // An account that signed in before the counter existed counts as being in its first sign-in.
    const nth = Math.max(r.signIns, 1);
    if (nth > TEACH_SIGN_INS || r.shown[hint] === nth) return false;
    r.shown[hint] = nth;
    localStorage.setItem(hintStorageKey, JSON.stringify({ signIns: r.signIns, shown: r.shown }));
    return true;
  } catch { return false; }
}
