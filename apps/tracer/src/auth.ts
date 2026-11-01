/** Implements the same-origin passkey ceremonies and browser-only key wrapping contract. */
import { mnemonicToEntropy, entropyToMnemonic } from "@scure/bip39";
import { wordlist } from "@scure/bip39/wordlists/english.js";

const KEY_CONTEXT = "infraternal/keywrap/v1";
const encoder = new TextEncoder();
const bufferByteLength = Object.getOwnPropertyDescriptor(ArrayBuffer.prototype, "byteLength")?.get;

export interface AuthStart {
  ceremony: string;
  user_id?: string;
  recovery_words?: string | null;
  recovery_version?: number;
  options: { publicKey: Record<string, unknown> };
}

interface AuthSession {
  session_incarnation?: string;
  user_id: string;
  username: string;
  display_name: string;
  device: string;
  fresh: number;
  passkey_provider?: string | null;
  recovery_words_need_replacing?: boolean;
  recovery_pending?: { ready_at: number } | null;
}

export interface Wrap {
  salt: string;
  nonce: string;
  ciphertext: string;
}

interface StoredWrap {
  kind: string;
  key_id: string;
  wrap: Wrap;
  prf_input?: string | null;
}

interface PrfOutputs extends Record<string, unknown> {
  enabled?: boolean;
  results?: { first?: unknown; second?: unknown };
}

interface CredentialOutputs extends Record<string, unknown> {
  prf?: PrfOutputs;
}

/** Carries only a safe status message and HTTP code; response bodies may hold secrets. */
export class AuthError extends Error {
  constructor(message: string, readonly status?: number) {
    super(message);
    this.name = "AuthError";
  }
}

/** Public first-run state and its matching local setup-token command. */
export interface AuthStatus {
  setupRequired: boolean;
  setupTokenCommand: string;
}

/** Reads the public first-run state before choosing an access screen. */
export async function checkStatus(): Promise<AuthStatus> {
  const status = await post<{ setup_required: unknown; setup_token_command?: unknown }>("status", {});
  if (typeof status.setup_required !== "boolean") throw new AuthError("The server's answer could not be used. Try again.");
  const setupTokenCommand = status.setup_token_command ?? "infraternal server setup-token";
  if (setupTokenCommand !== "infraternal server setup-token" && setupTokenCommand !== "sudo infraternal server setup-token") {
    throw new AuthError("The server's setup command could not be used. Try again.");
  }
  return { setupRequired: status.setup_required, setupTokenCommand };
}

/** Validates first-run authority without starting or consuming owner enrollment. */
export async function checkSetupToken(token: string): Promise<void> {
  await post<void>("setup-check", { token });
}

/** Checks the secure cookie when the app starts or returns to the foreground. */
export async function checkSession(): Promise<AuthSession | undefined> {
  try {
    return await post<AuthSession>("session", {});
  } catch (error: unknown) {
    if (error instanceof AuthError && error.status === 401) return undefined;
    throw error;
  }
}

/**
 * Ends this device's session on the server, which also drops its sockets. A session the server no longer knows (401) is
 * already signed out, so it counts as done; any other failure is thrown, because the cookie would still be valid and
 * a reload would sign the person straight back in.
 */
export async function logout(): Promise<void> {
  try {
    await post<void>("logout", {});
  } catch (error: unknown) {
    if (error instanceof AuthError && error.status === 401) return;
    throw error;
  }
}

/** Creates the owner, pauses for recovery-key acknowledgement, then commits both wraps. */
export async function registerOwner(
  token: string,
  username: string,
  displayName: string,
  showRecoveryWords: (words: string, finishRegistration: () => Promise<void>) => Promise<void>,
): Promise<string> {
  const start = await post<AuthStart>("setup-start", { token, username, display_name: displayName });
  const userId = canonicalUuid(start.user_id, "setup user id");
  const recoveryWords = generateRecoveryWords();
  const publicKey = creationOptions(start.options.publicKey);
  const prfInput = prfInputFrom(publicKey);
  let prf: Uint8Array | undefined;
  let dek: Uint8Array | undefined;

  try {
    const created = await navigator.credentials.create({ publicKey });
    if (!(created instanceof PublicKeyCredential)) throw new AuthError("Passkey registration was cancelled.");
    const creationOutputs = credentialOutputs(created);
    if (creationOutputs.prf?.enabled !== true) {
      throw new AuthError("This passkey cannot protect your account key. Choose another passkey.");
    }

    prf = prfFrom(created);
    if (!prf) {
      prf = await credentialPrf(created, publicKey.rp.id, prfInput);
    }

    // The recovery phrase is parsed before display so invalid server output cannot be wrapped.
    const recovery = await recoverySecrets(recoveryWords);
    try {

      dek = crypto.getRandomValues(new Uint8Array(32));
      const passkeyWrap = await wrapDek(prf, dek, userId, "passkey");
      const recoveryWrap = await wrapDek(recovery.wrap, dek, userId, "recovery");
      let finishPromise: Promise<void> | undefined;
      await showRecoveryWords(recoveryWords, () => {
        // Keep a single ceremony response if the confirmation button is activated twice.
        if (!finishPromise) {
          finishPromise = post("registration-finish", {
            ceremony: requiredString(start.ceremony, "registration ceremony"),
            proof: credentialProof(created),
            passkey_wrap: passkeyWrap,
            recovery_wrap: recoveryWrap,
            recovery_verifier: recovery.verifier,
          }).then(() => undefined).catch((error: unknown) => {
            // A transient rejection can be retried with the same ceremony proof.
            finishPromise = undefined;
            throw error;
          });
        }
        return finishPromise;
      });
      return userId;
    } finally {
      recovery.wrap.fill(0);
    }
  } finally {
    prf?.fill(0);
    dek?.fill(0);
    prfInput.fill(0);
  }
}

/** Completes a UV-required passkey login and verifies its DEK envelope locally. */
export async function loginWithPasskey(device: string): Promise<string> {
  const start = await post<AuthStart>("login-start", {});
  const publicKey = requestOptions(start.options.publicKey);
  let prf: Uint8Array | undefined;
  let userId: string;

  try {
    const assertion = await navigator.credentials.get({ publicKey });
    if (!(assertion instanceof PublicKeyCredential)) throw new AuthError("Passkey login was cancelled.");
    prf = prfFrom(assertion);
    const pending = await post<{ pending_transaction: string }>("login-finish", {
      ceremony: requiredString(start.ceremony, "login ceremony"),
      proof: credentialProof(assertion),
      device: device.slice(0, 128),
    });

    // Keep completion in this page call; shared cookies cannot identify which tab unwrapped.
    const transaction = requiredString(pending?.pending_transaction, "pending login transaction");
    try {
      const session = await post<AuthSession>("unlock-session", {});
      userId = canonicalUuid(session?.user_id, "session user id");
      const stored = await post<StoredWrap[]>("wraps", {});
      const keyId = base64url(copyBytes(assertion.rawId, "rawId"));
      const entry = stored.find((entry) => entry.kind === "passkey" && entry.key_id === keyId);
      const envelope = entry?.wrap;
      if (!envelope) throw new AuthError("Your account key is unavailable on the server. Try again.");
      const first = decodeBase64url(requiredString(entry?.prf_input, "passkey input"));
      try {
        // Stored v1/v2 envelopes keep their input and require the local fallback.
        const requested = publicKey.extensions && (publicKey.extensions as CredentialOutputs).prf;
        const matches = requested && base64url(prfInputFrom(publicKey)) === entry?.prf_input;
        if (!prf || !matches) {
          prf?.fill(0);
          prf = await credentialPrf(assertion, publicKey.rpId, first);
        }
      } finally { first.fill(0); }
      const dek = await unwrapDek(prf, envelope, userId, "passkey");
      if (dek.byteLength !== 32) throw new AuthError("Your account key could not be unlocked. Try again.");
      dek.fill(0);
      await post("unlock-finish", { pending_transaction: transaction });
    } catch (error: unknown) {
      try { await post("logout", { pending_transaction: transaction }); }
      catch { throw new AuthError("Your account key was not unlocked. Sign in again; this incomplete session cannot access the terminal."); }
      throw error;
    }
    return userId;
  } finally {
    prf?.fill(0);
  }
}

async function post<Result = unknown>(action: string, body: unknown, headers: Readonly<Record<string, string>> = {}): Promise<Result> {
  let response: Response;
  try {
    response = await fetch(`/auth/${action}`, {
      method: "POST",
      credentials: "same-origin",
      cache: "no-store",
      headers: { "Content-Type": "application/json", ...headers },
      body: JSON.stringify(body),
    });
  } catch {
    throw new AuthError("The infraternal server could not be reached.");
  }
  if (!response.ok) {
    const message = response.status >= 500 ? "The server could not complete the request. Try again."
      : response.status === 429 ? "Too many attempts. Wait a minute and try again."
      : action === "setup-check" && response.status === 401 ? "That token doesn't match. Run the command shown on the setup screen."
      : action === "setup-start" && response.status === 401 ? "The setup token is invalid or expired. Get the current token from the server."
      : action === "setup-start" && response.status === 409 ? "That username is already in use. Choose another username."
      : action === "login-finish" ? "This passkey could not sign in. Try your registered passkey."
      : "The request could not be accepted. Check your details and try again.";
    throw new AuthError(message, response.status);
  }
  if (response.status === 204) return undefined as Result;
  try {
    return (await response.json()) as Result;
  } catch {
    throw new AuthError("The server sent a response this browser could not use. Try again.");
  }
}

function creationOptions(value: Record<string, unknown>): PublicKeyCredentialCreationOptions {
  const options = normalizePublicKey(value, true);
  const extensions = record(options.extensions, "registration extensions");
  options.extensions = { ...extensions, credProps: true };
  return options as unknown as PublicKeyCredentialCreationOptions;
}

function requestOptions(value: Record<string, unknown>): PublicKeyCredentialRequestOptions {
  return normalizePublicKey(value, false) as unknown as PublicKeyCredentialRequestOptions;
}

function normalizePublicKey(value: Record<string, unknown>, isRegistration: boolean): Record<string, unknown> {
  const options = structuredClone(value);
  options.challenge = decodeBase64url(requiredString(options.challenge, "WebAuthn challenge"));
  if (isRegistration) {
    const user = record(options.user, "WebAuthn user");
    user.id = decodeBase64url(requiredString(user.id, "WebAuthn user id"));
  }
  for (const field of ["allowCredentials", "excludeCredentials"]) {
    const credentials = options[field];
    if (Array.isArray(credentials)) {
      options[field] = credentials.map((credential) => {
        const item = record(credential, "WebAuthn credential");
        return { ...item, id: decodeBase64url(requiredString(item.id, "WebAuthn credential id")) };
      });
    }
  }
  if (!options.extensions || !record(options.extensions, "WebAuthn extensions").prf) return options;
  const extensions = record(options.extensions, "WebAuthn extensions");
  const prf = record(extensions.prf, "WebAuthn PRF extension");
  const evaluation = record(prf.eval, "WebAuthn PRF input");
  evaluation.first = decodeBase64url(requiredString(evaluation.first, "WebAuthn PRF input"));
  options.extensions = { ...extensions, prf: { ...prf, eval: evaluation } };
  return options;
}

function prfInputFrom(options: PublicKeyCredentialCreationOptions | PublicKeyCredentialRequestOptions): Uint8Array {
  const extensions = options.extensions as (AuthenticationExtensionsClientInputs & {
    prf?: { eval?: { first?: BufferSource } };
  }) | undefined;
  const first = extensions?.prf?.eval?.first;
  if (!first) throw new AuthError("The server could not prepare your account key. Try again.");
  return first instanceof ArrayBuffer
    ? new Uint8Array(first)
    : new Uint8Array(first.buffer, first.byteOffset, first.byteLength);
}

async function credentialPrf(
  credential: PublicKeyCredential,
  rpId: string | undefined,
  first: Uint8Array,
): Promise<Uint8Array> {
  const result = await navigator.credentials.get({
    publicKey: {
      challenge: toArrayBuffer(crypto.getRandomValues(new Uint8Array(32))),
      ...(rpId ? { rpId } : {}),
      allowCredentials: [{ type: "public-key", id: toArrayBuffer(copyBytes(credential.rawId, "rawId")) }],
      userVerification: "required",
      extensions: { prf: { eval: { first: toArrayBuffer(first) } } } as AuthenticationExtensionsClientInputs,
    },
  });
  if (!(result instanceof PublicKeyCredential)) throw new AuthError("The passkey prompt was cancelled.");
  const prf = prfFrom(result);
  if (!prf) {
    binaryDiagnostic(undefined, "prf.first");
    throw new AuthError("This passkey could not unlock your account key. Try again or choose another passkey.");
  }
  return prf;
}

function credentialOutputs(credential: PublicKeyCredential): CredentialOutputs {
  return credential.getClientExtensionResults() as CredentialOutputs;
}

function prfFrom(credential: PublicKeyCredential): Uint8Array | undefined {
  const outputs = credentialOutputs(credential).prf?.results;
  const first = outputs?.first;
  let result: Uint8Array | undefined;
  try {
    const second = outputs?.second;
    if (second !== undefined) {
      const bytes = copyBytes(second, "prf.second");
      const length = bytes.byteLength;
      bytes.fill(0);
      if (length !== 32) {
        binaryDiagnostic(second, "prf.second");
        throw new AuthError("Your passkey could not unlock your account key. Try again.");
      }
    }
    if (first === undefined) return undefined;
    result = copyBytes(first, "prf.first");
    if (result.byteLength !== 32) throw new Error("invalid PRF length");
    return result;
  } catch (error: unknown) {
    result?.fill(0);
    if (!(error instanceof AuthError)) binaryDiagnostic(first, "prf.first");
    throw new AuthError("Your passkey could not unlock your account key. Try again.");
  }
}

function credentialProof(credential: PublicKeyCredential): Record<string, unknown> {
  const response = credential.response;
  const fields: Record<string, string | string[] | null> = {
    clientDataJSON: base64url(copyBytes(response.clientDataJSON, "clientDataJSON")),
  };
  if (response instanceof AuthenticatorAttestationResponse) {
    fields.attestationObject = base64url(copyBytes(response.attestationObject, "attestationObject"));
    fields.transports = response.getTransports();
  } else if (response instanceof AuthenticatorAssertionResponse) {
    fields.authenticatorData = base64url(copyBytes(response.authenticatorData, "authenticatorData"));
    fields.signature = base64url(copyBytes(response.signature, "signature"));
    fields.userHandle = response.userHandle === null ? null : base64url(copyBytes(response.userHandle, "userHandle"));
  } else {
    throw new AuthError("This browser could not use your passkey. Try another browser.");
  }

  // PRF output is local key material. Remove the whole extension before serialization.
  const extensions = { ...credentialOutputs(credential) };
  delete extensions.prf;
  return {
    id: credential.id,
    rawId: base64url(copyBytes(credential.rawId, "rawId")),
    type: credential.type,
    response: fields,
    extensions,
  };
}

/** Creates recovery words locally; neither entropy nor the mnemonic reaches enrollment. */
function generateRecoveryWords(): string {
  const entropy = crypto.getRandomValues(new Uint8Array(32));
  try { return entropyToMnemonic(entropy, wordlist); }
  finally { entropy.fill(0); }
}

/** Independent HKDF siblings: only verifier is transmitted; wrap always stays local [D151]. */
async function recoverySecrets(words: string): Promise<{ verifier: string; wrap: Uint8Array }> {
  const entropy = mnemonicToEntropy(words, wordlist);
  let authBytes: Uint8Array | undefined;
  try {
    if (entropy.byteLength !== 32) throw new AuthError("Enter all 24 recovery words.");
    const material = await crypto.subtle.importKey("raw", toArrayBuffer(entropy), "HKDF", false, ["deriveBits"]);
    const derive = async (kind: string): Promise<Uint8Array> => new Uint8Array(await crypto.subtle.deriveBits({
      name: "HKDF", hash: "SHA-256", salt: new ArrayBuffer(0), info: toArrayBuffer(encoder.encode(`infraternal/recovery/${kind}/v2`)),
    }, material, 256));
    authBytes = await derive("auth");
    const wrap = await derive("wrap");
    return { verifier: base64url(authBytes), wrap };
  } finally { entropy.fill(0); authBytes?.fill(0); }
}

/** Stored metadata determines derivation; old envelopes are never silently relabeled. */
async function unwrapRecoveryDek(words: string, wrap: Wrap, userId: string, version: number): Promise<Uint8Array> {
  if (version !== 1 && version !== 2) throw new AuthError("This recovery key was made by a newer version of infraternal. Update this app and try again.");
  const material = version === 1 ? mnemonicToEntropy(words, wordlist) : (await recoverySecrets(words)).wrap;
  try { return await unwrapDek(material, wrap, userId, "recovery"); }
  finally { material.fill(0); }
}

async function wrapDek(ikm: Uint8Array, dek: Uint8Array, userId: string, kind: "passkey" | "recovery"): Promise<Wrap> {
  const salt = crypto.getRandomValues(new Uint8Array(32));
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const aad = encoder.encode(`${KEY_CONTEXT}|${userId}|${kind}`);
  const key = await deriveWrappingKey(ikm, salt, aad);
  const ciphertext = await crypto.subtle.encrypt({
    name: "AES-GCM",
    iv: toArrayBuffer(nonce),
    additionalData: toArrayBuffer(aad),
    tagLength: 128,
  }, key, toArrayBuffer(dek));
  return { salt: base64url(salt), nonce: base64url(nonce), ciphertext: base64url(new Uint8Array(ciphertext)) };
}

async function unwrapDek(ikm: Uint8Array, wrap: Wrap, userId: string, kind: "passkey" | "recovery"): Promise<Uint8Array> {
  const salt = decodeBase64url(wrap.salt);
  const nonce = decodeBase64url(wrap.nonce);
  const ciphertext = decodeBase64url(wrap.ciphertext);
  if (salt.byteLength !== 32 || nonce.byteLength !== 12 || ciphertext.byteLength !== 48) {
    throw new AuthError("The server sent an unusable account key. Try again.");
  }
  const aad = encoder.encode(`${KEY_CONTEXT}|${userId}|${kind}`);
  const key = await deriveWrappingKey(ikm, salt, aad);
  try {
    return new Uint8Array(await crypto.subtle.decrypt({
      name: "AES-GCM",
      iv: toArrayBuffer(nonce),
      additionalData: toArrayBuffer(aad),
      tagLength: 128,
    }, key, toArrayBuffer(ciphertext)));
  } catch {
    throw new AuthError("The passkey could not unlock this account key.");
  }
}

async function deriveWrappingKey(ikm: Uint8Array, salt: Uint8Array, info: Uint8Array): Promise<CryptoKey> {
  const material = await crypto.subtle.importKey("raw", toArrayBuffer(ikm), "HKDF", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt: toArrayBuffer(salt), info: toArrayBuffer(info) },
    material,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

/** Copy at the WebAuthn boundary so views preserve offsets and extension arrays cannot coerce bytes. */
function copyBytes(input: unknown, field: string): Uint8Array {
  try {
    if (ArrayBuffer.isView(input)) {
      return new Uint8Array(new Uint8Array(input.buffer, input.byteOffset, input.byteLength));
    }
    if (input instanceof ArrayBuffer) return new Uint8Array(new Uint8Array(input));
    if (Object.prototype.toString.call(input) === "[object ArrayBuffer]") {
      // The intrinsic getter also rejects objects spoofing Symbol.toStringTag.
      const length = bufferByteLength?.call(input) as number;
      const source = new Uint8Array(input as ArrayBuffer);
      if (source.byteLength !== length) throw new Error("invalid buffer");
      return new Uint8Array(source);
    }
    if (Array.isArray(input)) {
      // Visit every index: Array.every skips holes, which must be rejected.
      for (let index = 0; index < input.length; index += 1) {
        const value: unknown = input[index];
        if (typeof value !== "number" || !Number.isInteger(value) || value < 0 || value > 255) throw new Error("invalid byte");
      }
      return Uint8Array.from(input as number[]);
    }
  } catch {
    binaryDiagnostic(input, field);
    throw new AuthError("This browser returned passkey data that could not be read. Try another browser.");
  }
  binaryDiagnostic(input, field);
  throw new AuthError("This browser returned passkey data that could not be read. Try another browser.");
}

/** Log only fixed shape codes and sizes; never values, credential IDs or arbitrary object tags. */
function binaryDiagnostic(input: unknown, field: string): void {
  let shape = "unsupported";
  let length: number | null = null;
  try {
    if (Array.isArray(input)) { shape = "array"; length = input.length; }
    else if (ArrayBuffer.isView(input)) { shape = "view"; length = input.byteLength; }
    else if (Object.prototype.toString.call(input) === "[object ArrayBuffer]") {
      shape = "array-buffer";
      length = bufferByteLength?.call(input) as number;
    }
  } catch { /* A malformed object's getters must not escape into error messages or logs. */ }
  console.warn("AUTH_BINARY_INVALID", { field, shape, length });
}

function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  const buffer = new ArrayBuffer(bytes.byteLength);
  new Uint8Array(buffer).set(bytes);
  return buffer;
}

function base64url(bytes: Uint8Array): string {
  let binary = "";
  for (let index = 0; index < bytes.byteLength; index += 1) binary += String.fromCharCode(bytes[index] ?? 0);
  return btoa(binary).replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
}

function decodeBase64url(value: string): Uint8Array {
  if (!/^[A-Za-z0-9_-]*$/.test(value) || value.length % 4 === 1) throw new AuthError("The server's answer could not be used. Try again.");
  const binary = atob(value.replace(/-/g, "+").replace(/_/g, "/"));
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) bytes[index] = binary.charCodeAt(index);
  if (base64url(bytes) !== value) throw new AuthError("The server's answer could not be used. Try again.");
  return bytes;
}

function record(value: unknown, name: string): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) throw new AuthError("The server's answer could not be used. Try again.");
  return value as Record<string, unknown>;
}

function requiredString(value: unknown, name: string): string {
  if (typeof value !== "string" || value.length === 0) throw new AuthError("The server's answer was incomplete. Try again.");
  return value;
}

function canonicalUuid(value: unknown, name: string): string {
  const result = requiredString(value, name);
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(result)) {
    throw new AuthError("The server's answer could not be used. Try again.");
  }
  return result;
}

/** Shares existing ceremony and crypto implementations with account-key workflows; binary handling stays here. */
export const recoveryAuth = {
  post, creationOptions, requestOptions, copyBytes, base64url, decodeBase64url, toArrayBuffer, prfInputFrom, credentialOutputs, prfFrom, credentialPrf,
  credentialProof, wrapDek, unwrapDek, requiredString, canonicalUuid,
  generateRecoveryWords, recoverySecrets, unwrapRecoveryDek,
};
