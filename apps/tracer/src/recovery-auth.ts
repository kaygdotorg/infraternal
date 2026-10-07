/** Replaces lost passkeys by unwrapping the original DEK with BIP-39 entropy [23,25,D113]. */
import { mnemonicToEntropy } from "@scure/bip39";
import { wordlist } from "@scure/bip39/wordlists/english.js";
import { AuthError, recoveryAuth as auth, type AuthStart, type Wrap } from "./auth";

export interface RecoveryRequest { token: string; delay_seconds: number; ready_at: number }

/** Starts recovery with an optional HttpOnly session; the server alone chooses the delay. */
export async function startRecovery(username: string, words: string, legacyUpgrade = false): Promise<RecoveryRequest> {
  const derived = await auth.recoverySecrets(words);
  let result: RecoveryRequest;
  try {
    // Probe the verifier first even after explicit legacy selection. A committed
    // upgrade whose response was lost must never retransmit its words on retry.
    try { result = await auth.post<RecoveryRequest>("recovery-resume", { username, verifier: derived.verifier }); }
    catch (failure: unknown) {
      if (!legacyUpgrade || !(failure instanceof AuthError) || failure.status !== 401) throw failure;
      result = await auth.post<RecoveryRequest>("recovery-upgrade", { username, words, verifier: derived.verifier });
    }
  } finally { derived.wrap.fill(0); }
  auth.requiredString(result.token, "recovery token");
  if ((!Number.isSafeInteger(result.delay_seconds) || result.delay_seconds < 0 || result.delay_seconds > 86400) || !Number.isSafeInteger(result.ready_at) || result.ready_at <= 0) {
    throw new AuthError("The server returned an invalid recovery time.");
  }
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
