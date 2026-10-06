/** Implements the same-origin passkey ceremonies and browser-only key wrapping contract. */
import { mnemonicToEntropy } from "@scure/bip39";
import { wordlist } from "@scure/bip39/wordlists/english.js";

const KEY_CONTEXT = "infraternal/keywrap/v1";
const encoder = new TextEncoder();

interface AuthStart {
  ceremony: string;
  user_id?: string;
  recovery_words?: string | null;
  options: { publicKey: Record<string, unknown> };
}

interface AuthSession {
  user_id: string;
  device: string;
  fresh: boolean;
}

interface Wrap {
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
  results?: { first?: ArrayBuffer | ArrayBufferView };
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

/** Reads only the public first-run flag before choosing an access screen. */
export async function checkStatus(): Promise<boolean> {
  const status = await post<{ setup_required: unknown }>("status", {});
  if (typeof status.setup_required !== "boolean") throw new AuthError("The server returned an invalid setup status.");
  return status.setup_required;
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

/** Creates the owner, pauses for recovery-key acknowledgement, then commits both wraps. */
export async function registerOwner(
  token: string,
  name: string,
  showRecoveryWords: (words: string, userId: string) => Promise<void>,
): Promise<string> {
  const start = await post<AuthStart>("setup-start", { token, name });
  const userId = canonicalUuid(start.user_id, "setup user id");
  const recoveryWords = requiredString(start.recovery_words, "recovery words");
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
    const recoveryEntropy = mnemonicToEntropy(recoveryWords, wordlist);
    try {
      if (recoveryEntropy.byteLength !== 32) throw new AuthError("The recovery phrase is invalid.");
      dek = crypto.getRandomValues(new Uint8Array(32));
      const passkeyWrap = await wrapDek(prf, dek, userId, "passkey");
      const recoveryWrap = await wrapDek(recoveryEntropy, dek, userId, "recovery");
      await showRecoveryWords(recoveryWords, userId);
      await post("registration-finish", {
        ceremony: requiredString(start.ceremony, "registration ceremony"),
        proof: credentialProof(created),
        passkey_wrap: passkeyWrap,
        recovery_wrap: recoveryWrap,
      });
      return userId;
    } finally {
      recoveryEntropy.fill(0);
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
    await post("login-finish", {
      ceremony: requiredString(start.ceremony, "login ceremony"),
      proof: credentialProof(assertion),
      device: device.slice(0, 128),
    });

    try {
      const session = await checkSession();
      userId = canonicalUuid(session?.user_id, "session user id");
      const stored = await post<StoredWrap[]>("wraps", {});
      const keyId = base64url(new Uint8Array(assertion.rawId));
      const entry = stored.find((entry) => entry.kind === "passkey" && entry.key_id === keyId);
      const envelope = entry?.wrap;
      if (!envelope) throw new AuthError("Your account key is unavailable on the server. Try again.");
      const first = decodeBase64url(requiredString(entry?.prf_input, "passkey input"));
      try {
        prf = await credentialPrf(assertion, publicKey.rpId, first);
      } finally { first.fill(0); }
      const dek = await unwrapDek(prf, envelope, userId, "passkey");
      if (dek.byteLength !== 32) throw new AuthError("Your account key could not be unlocked. Try again.");
      dek.fill(0);
    } catch (error: unknown) {
      await post("logout", {}).catch(() => undefined);
      throw error;
    }
    return userId;
  } finally {
    prf?.fill(0);
  }
}

async function post<Result = unknown>(action: string, body: unknown): Promise<Result> {
  let response: Response;
  try {
    response = await fetch(`/auth/${action}`, {
      method: "POST",
      credentials: "same-origin",
      cache: "no-store",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
  } catch {
    throw new AuthError("The infraternal server could not be reached.");
  }
  if (!response.ok) {
    const message = response.status >= 500 ? "The server could not complete the request. Try again."
      : response.status === 429 ? "Too many attempts. Wait a minute and try again."
      : action === "setup-start" && response.status === 401 ? "The setup token is invalid or expired. Get the current token from the server."
      : action === "login-finish" ? "This passkey could not sign in. Try your registered passkey."
      : "The request could not be accepted. Check your details and try again.";
    throw new AuthError(message, response.status);
  }
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
      allowCredentials: [{ type: "public-key", id: credential.rawId }],
      userVerification: "required",
      extensions: { prf: { eval: { first: toArrayBuffer(first) } } } as AuthenticationExtensionsClientInputs,
    },
  });
  if (!(result instanceof PublicKeyCredential)) throw new AuthError("The passkey key proof was cancelled.");
  const prf = prfFrom(result);
  if (!prf) throw new AuthError("This passkey could not unlock your account key. Try again or choose another passkey.");
  return prf;
}

function credentialOutputs(credential: PublicKeyCredential): CredentialOutputs {
  return credential.getClientExtensionResults() as CredentialOutputs;
}

function prfFrom(credential: PublicKeyCredential): Uint8Array | undefined {
  const first = credentialOutputs(credential).prf?.results?.first;
  if (!first) return undefined;
  const result = copyBytes(first);
  if (result.byteLength !== 32) throw new AuthError("Your passkey could not unlock your account key. Try again.");
  return result;
}

function credentialProof(credential: PublicKeyCredential): Record<string, unknown> {
  const response = credential.response;
  const fields: Record<string, string | string[] | null> = {
    clientDataJSON: base64url(new Uint8Array(response.clientDataJSON)),
  };
  if (response instanceof AuthenticatorAttestationResponse) {
    fields.attestationObject = base64url(new Uint8Array(response.attestationObject));
    fields.transports = response.getTransports();
  } else if (response instanceof AuthenticatorAssertionResponse) {
    fields.authenticatorData = base64url(new Uint8Array(response.authenticatorData));
    fields.signature = base64url(new Uint8Array(response.signature));
    fields.userHandle = response.userHandle ? base64url(new Uint8Array(response.userHandle)) : null;
  } else {
    throw new AuthError("This browser could not use your passkey. Try another browser.");
  }

  // PRF output is local key material. Remove the whole extension before serialization.
  const extensions = { ...credentialOutputs(credential) };
  delete extensions.prf;
  return {
    id: credential.id,
    rawId: base64url(new Uint8Array(credential.rawId)),
    type: credential.type,
    response: fields,
    extensions,
  };
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

function copyBytes(input: ArrayBuffer | ArrayBufferView): Uint8Array {
  const result = new Uint8Array(input.byteLength);
  const source = input instanceof ArrayBuffer
    ? new Uint8Array(input)
    : new Uint8Array(input.buffer, input.byteOffset, input.byteLength);
  result.set(source);
  return result;
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
  if (!/^[A-Za-z0-9_-]*$/.test(value) || value.length % 4 === 1) throw new AuthError("The server returned invalid binary data.");
  const binary = atob(value.replace(/-/g, "+").replace(/_/g, "/"));
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) bytes[index] = binary.charCodeAt(index);
  if (base64url(bytes) !== value) throw new AuthError("The server returned non-canonical binary data.");
  return bytes;
}

function record(value: unknown, name: string): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) throw new AuthError(`The server returned invalid ${name}.`);
  return value as Record<string, unknown>;
}

function requiredString(value: unknown, name: string): string {
  if (typeof value !== "string" || value.length === 0) throw new AuthError(`The server omitted ${name}.`);
  return value;
}

function canonicalUuid(value: unknown, name: string): string {
  const result = requiredString(value, name);
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(result)) {
    throw new AuthError(`The server returned an invalid ${name}.`);
  }
  return result;
}
