/** Performs passkey recovery and signed-in word replacement with browser-only wrapping [23,25,D113]. */
import { mnemonicToEntropy } from "@scure/bip39";
import { wordlist } from "@scure/bip39/wordlists/english.js";
import { AuthError, recoveryAuth as auth, type AuthStart, type Wrap } from "./auth";

// Resumed deadlines can exceed a day after rollback; cap by the 48-hour
// recovery capability policy, rather than the original 24-hour start delay.
const MAX_RECOVERY_WAIT_SECONDS = 48 * 60 * 60;

export interface RecoveryRequest { token: string; delay_seconds: number; ready_at: number }
export interface RecoveryStatus { ready: boolean; delay_seconds: number; ready_at: number }

function validateWait(result: Pick<RecoveryRequest, "delay_seconds" | "ready_at">): void {
  if (!Number.isSafeInteger(result.delay_seconds) || result.delay_seconds < 0 || result.delay_seconds > MAX_RECOVERY_WAIT_SECONDS || !Number.isSafeInteger(result.ready_at) || result.ready_at <= 0) {
    throw new AuthError("The server's answer could not be used. Try again.");
  }
}

/** Reads the existing capability; polling cannot start recovery or rotate its bearer. */
export async function getRecoveryStatus(token: string): Promise<RecoveryStatus> {
  const result = await auth.post<RecoveryStatus>("recovery-status", { token });
  validateWait(result);
  if (typeof result.ready !== "boolean" || result.ready !== (result.delay_seconds === 0)) {
    throw new AuthError("The server's answer could not be used. Try again.");
  }
  return result;
}

/** Starts recovery with an optional HttpOnly session; the server alone chooses the delay. */
export async function startRecovery(username: string, words: string): Promise<RecoveryRequest> {
  const derived = await auth.recoverySecrets(words);
  let result: RecoveryRequest;
  try {
    result = await auth.post<RecoveryRequest>("recovery-resume", { username, verifier: derived.verifier });
  } finally { derived.wrap.fill(0); }
  auth.requiredString(result.token, "recovery token");
  validateWait(result);
  return result;
}

/** Creates a replacement passkey, then pauses before committing until rotated words are saved. */
export async function replacePasskey(token: string, words: string,
  showWords: (words: string, finish: () => Promise<void>) => Promise<void>,
): Promise<{ userId: string; displayName: string }> {
  const start = await auth.post<AuthStart & { old_recovery_wrap: Wrap; old_recovery_wrap_version?: number }>("recovery-ready", { token });
  const userId = auth.canonicalUuid(start.user_id, "recovery user id");
  const oldEntropy = mnemonicToEntropy(words, wordlist);
  let nextEntropy: Uint8Array | undefined, dek: Uint8Array | undefined, prf: Uint8Array | undefined, input: Uint8Array | undefined;
  try {
    const nextWords = auth.generateRecoveryWords();
    if (oldEntropy.byteLength !== 32) throw new AuthError("Enter all 24 recovery words.");
    // Authenticate the old envelope before creating anything: replacement must retain the DEK.
    dek = await auth.unwrapRecoveryDek(words, start.old_recovery_wrap, userId, start.old_recovery_wrap_version ?? 1);
    if (dek.byteLength !== 32) throw new AuthError("The account key is invalid.");
    const options = auth.creationOptions(start.options.publicKey);
    input = auth.prfInputFrom(options);
    const created = await navigator.credentials.create({ publicKey: options });
    if (!(created instanceof PublicKeyCredential)) throw new AuthError("Passkey registration was cancelled.");
    if (auth.credentialOutputs(created).prf?.enabled !== true) {
      throw new AuthError("This passkey cannot protect your account key. Choose another passkey.");
    }
    prf = auth.prfFrom(created) ?? await auth.credentialPrf(created, options.rp.id, input);
    nextEntropy = mnemonicToEntropy(nextWords, wordlist);
    if (nextEntropy.byteLength !== 32) throw new AuthError("The new recovery key is invalid.");
    const passkeyWrap = await auth.wrapDek(prf, dek, userId, "passkey");
    const recovery = await auth.recoverySecrets(nextWords);
    let recoveryWrap: Wrap;
    try { recoveryWrap = await auth.wrapDek(recovery.wrap, dek, userId, "recovery"); }
    finally { recovery.wrap.fill(0); }
    let finishing: Promise<void> | undefined;
    await showWords(nextWords, () => {
      // Finish is one-shot. A failed ceremony must restart instead of resubmitting consumed proofs.
      finishing ??= auth.post<void>("registration-finish", {
        ceremony: start.ceremony, proof: auth.credentialProof(created),
        passkey_wrap: passkeyWrap, recovery_wrap: recoveryWrap, recovery_verifier: recovery.verifier,
      });
      return finishing;
    });
    return { userId, displayName: options.user.displayName };
  } finally {
    oldEntropy.fill(0); nextEntropy?.fill(0); dek?.fill(0); prf?.fill(0); input?.fill(0);
  }
}

/** Rotates a legacy recovery envelope from an unlocked device; no migration UI is implied.
 * The caller's passkey tap must be bound to `{ kind: "recovery.rotate" }` (D336) and made
 * less than two minutes before finish.
 * The caller owns the DEK and must acknowledge saving words before calling finish.
 * Copy the key for this operation so caller cleanup cannot race local wrapping.
 */
export async function rotateRecoveryWords(userId: string, dataKey: Uint8Array,
  showWords: (words: string, finish: () => Promise<void>) => Promise<void>,
): Promise<void> {
  auth.canonicalUuid(userId, "recovery user id");
  if (dataKey.byteLength !== 32) throw new AuthError("The account key is invalid.");
  const dek = dataKey.slice();
  try {
    const words = auth.generateRecoveryWords();
    const derived = await auth.recoverySecrets(words);
    let recoveryWrap: Wrap;
    try { recoveryWrap = await auth.wrapDek(derived.wrap, dek, userId, "recovery"); }
    finally { derived.wrap.fill(0); }
    let finishing: Promise<void> | undefined;
    let acknowledging = true;
    try {
      await showWords(words, () => {
        if (!acknowledging) return Promise.reject(new AuthError("Recovery replacement was dismissed."));
        // The shared cookie can change in another tab while the new words are shown.
        // Pin the intended account separately from the ciphertext-only request body.
        finishing ??= auth.post<void>("recovery-rotate", {
          recovery_wrap: recoveryWrap, recovery_verifier: derived.verifier,
        }, { "X-Infraternal-User": userId });
        return finishing;
      });
    } finally { acknowledging = false; }
    if (!finishing) throw new AuthError("Save the new recovery words before replacing them.");
    await finishing;
  } finally { dek.fill(0); }
}
