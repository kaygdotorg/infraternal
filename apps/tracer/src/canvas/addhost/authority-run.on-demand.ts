// SPDX-License-Identifier: AGPL-3.0-only
/**
 * On demand: the one passkey-ceremony call and its failure wording, shared by the add-host wizard, the palette row
 * and Settings → Hosts (see authority-unlock.ts, which keeps the lock's state and loads this on first use).
 */
/** Shown when the ceremony fails without a more specific reason; the same words in the wizard, the palette and Settings. */
export const UNLOCK_FAILED = "Passkey confirmation did not finish. Try again.";
import type { CoreScreen } from "../../core-screen";
import type { AuthorityState } from "./authority-unlock";
import { ServiceError, type ProvisioningService } from "./service";

export const UNLOCKED = "Host connections unlocked";
export const ACTION_UNLOCK = "canvas:unlockauthority";
const STALE_MS = 30_000;

export type UnlockResult = { ok: true } | { ok: false; message: string };

/** Runs the passkey ceremony once. Never throws: the caller shows `message` where it shows errors. */
export async function runUnlock(service: ProvisioningService): Promise<UnlockResult> {
  if (!service.unlockAuthority) return { ok: false, message: UNLOCK_FAILED };
  try { await service.unlockAuthority(); return { ok: true }; }
  catch (error: unknown) { return { ok: false, message: error instanceof ServiceError ? error.message : UNLOCK_FAILED }; }
}

/** What the server says about the lock; "unknown" when it refuses (not an administrator) or has no authority. */
export async function readState(service: ProvisioningService): Promise<AuthorityState> {
  try {
    const status = await service.authorityStatus?.();
    return status ? status.locked ? "locked" : "unlocked" : "unknown";
  } catch { return "unknown"; }
}

/** Tells the person how the ceremony ended, in the words every surface shares. */
export function announce(toast: CoreScreen["toast"], result: UnlockResult): void {
  if (result.ok) toast.show({ message: "Host connections unlocked" });
  else toast.show({ message: result.message, tone: "error", duration: 5000 });
}
