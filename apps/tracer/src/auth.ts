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

/** The exact device identity and access requested by the CLI, before passkey approval. */
export interface DeviceApprovalReview {
  kind: "sign_in";
  device: string;
  scopes: string[];
  /** How long the approved key lasts; the tap approves this together with the scopes (D333). */
  lifetimeSeconds: number;
}

/** Bounds the server applies to a requested key lifetime: 1 hour up to the 365-day policy maximum. */
const MIN_KEY_LIFETIME_SECONDS = 3_600;
const MAX_KEY_LIFETIME_SECONDS = 365 * 86_400;

/**
 * A key lifetime as a person reads it: hours up to two days ("24 hours"), days after.
 * The tap approves what this says, and the requester picks the number, so it is exact: every
 * leftover minute and second is named ("1 hour, 59 minutes and 59 seconds"), never rounded down.
 */
export function keyLifetimeLabel(seconds: number): string {
  const days = seconds >= 2 * 86_400 ? Math.floor(seconds / 86_400) : 0;
  let rest = seconds - days * 86_400;
  const hours = Math.floor(rest / 3_600);
  rest -= hours * 3_600;
  const minutes = Math.floor(rest / 60);
  const parts = ([[days, "day"], [hours, "hour"], [minutes, "minute"], [rest - minutes * 60, "second"]] as const)
    .filter(([count]) => count > 0)
    .map(([count, unit]) => `${count} ${unit}${count === 1 ? "" : "s"}`);
  if (parts.length < 2) return parts[0] ?? "0 seconds";
  return `${parts.slice(0, -1).join(", ")} and ${parts.at(-1)}`;
}

const DEVICE_APPROVAL_SCOPES = new Set([
  "hosts:read",
  "hosts:write",
  "sessions:read",
  "status:read",
  "terminal:connect",
  "actions:dry-run",
]);

/**
 * A machine asking to join this server (`infraternal up`): its name, how it will run, and the fingerprint of the key it
 * will enroll with. The approval is bound to exactly this key and mode on the server.
 */
export interface JoinApprovalReview {
  kind: "join_machine";
  hostname: string;
  mode: "system" | "user";
  keyFingerprint: string;
}

export type ApprovalReview = DeviceApprovalReview | JoinApprovalReview;


/** Server-generated user codes are 12 random bytes encoded as unpadded base64url. */
export function isDeviceUserCode(code: string): boolean {
  return /^[A-Za-z0-9_-]{16}$/.test(code);
}

/**
 * A name a person will read: non-empty, bounded, and free of control and format characters. Format characters (bidi
 * overrides and isolates, zero-width characters) can make one name read as another (#263, J134 P3-3).
 */
function isShownName(value: unknown): value is string {
  return typeof value === "string" && value.length > 0 && value.length <= 128 && !/[\p{Cc}\p{Cf}\u2028\u2029]/u.test(value);
}

/** A machine's host name: exactly the ASCII set `infraternal up` sends and the server accepts. */
function isHostName(value: unknown): value is string {
  return typeof value === "string" && /^[A-Za-z0-9._-]{1,128}$/.test(value);
}

/**
 * Reads what the code asks for; the browser session is required by the server. The link form decides which answer is
 * acceptable (`expected`): a sign-in link only opens a sign-in review and a join link only a join review, so a link
 * cannot dress one request up as the other.
 */
export async function inspectDeviceApproval(code: string, expected: "sign_in"): Promise<DeviceApprovalReview>;
export async function inspectDeviceApproval(code: string, expected: "join_machine"): Promise<JoinApprovalReview>;
export async function inspectDeviceApproval(code: string, expected: ApprovalReview["kind"] = "sign_in"): Promise<ApprovalReview> {
  if (!isDeviceUserCode(code)) throw invalidDeviceApprovalLink(expected);
  let review: { kind?: unknown; device?: unknown; scopes?: unknown; lifetime_seconds?: unknown; hostname?: unknown; mode?: unknown; key_fingerprint?: unknown };
  try {
    review = await post("device-inspect", { code });
  } catch (error: unknown) {
    throw deviceApprovalError(error, expected);
  }
  if (expected === "join_machine") {
    if (review?.kind === "join_machine"
      && isHostName(review.hostname)
      && (review.mode === "system" || review.mode === "user")
      && typeof review.key_fingerprint === "string"
      && FINGERPRINT.test(review.key_fingerprint)) {
      return { kind: "join_machine", hostname: review.hostname, mode: review.mode, keyFingerprint: review.key_fingerprint };
    }
    throw new AuthError("The server's request to add this machine could not be reviewed. Check that the server is up to date, then run infraternal up again.");
  }
  const scopes = review?.scopes;
  if ((review?.kind !== undefined && review.kind !== "sign_in")
    || !isShownName(review?.device)
    || !Array.isArray(scopes)
    || scopes.length === 0
    || scopes.length > 32
    || new Set(scopes).size !== scopes.length
    || !scopes.every((scope) => typeof scope === "string" && DEVICE_APPROVAL_SCOPES.has(scope))
    || typeof review.lifetime_seconds !== "number"
    || !Number.isInteger(review.lifetime_seconds)
    || review.lifetime_seconds < MIN_KEY_LIFETIME_SECONDS
    || review.lifetime_seconds > MAX_KEY_LIFETIME_SECONDS) {
    throw new AuthError("The server's sign-in request could not be reviewed. Check that the server is up to date, then ask for a new link.");
  }
  return { kind: "sign_in", device: review.device as string, scopes: [...scopes] as string[], lifetimeSeconds: review.lifetime_seconds };
}

/** `SHA256:` and the 43 unpadded base64 characters of a SHA-256 digest. */
const FINGERPRINT = /^SHA256:[A-Za-z0-9+/]{43}$/;

/**
 * Approves from a user action with a passkey tap for this request alone: the server binds the ceremony to this code
 * and this session, so no earlier login can approve a CLI sign-in or a machine join (#263, J134 P3-2, J145 P3-3).
 */
export async function approveDeviceApproval(code: string, kind: ApprovalReview["kind"] = "sign_in"): Promise<void> {
  if (!isDeviceUserCode(code)) throw invalidDeviceApprovalLink(kind);
  try {
    const start = await post<AuthStart>("device-approve-start", { code });
    const assertion = await navigator.credentials.get({ publicKey: requestOptions(start.options.publicKey) });
    if (!(assertion instanceof PublicKeyCredential)) throw new AuthError("Passkey approval was cancelled.");
    await post("device-approve-finish", {
      code,
      ceremony: requiredString(start.ceremony, "approval ceremony"),
      proof: credentialProof(assertion),
    });
  } catch (error: unknown) {
    throw deviceApprovalError(error, kind);
  }
}

function invalidDeviceApprovalLink(kind: ApprovalReview["kind"]): AuthError {
  return new AuthError(kind === "join_machine"
    ? "This link is incomplete. Run infraternal up again on the machine you want to add."
    : "This sign-in link is incomplete. Ask the person who started it to run infraternal sign-in again.");
}

function deviceApprovalError(error: unknown, kind: ApprovalReview["kind"]): unknown {
  const join = kind === "join_machine";
  if (error instanceof AuthError && error.status === 401) {
    return new AuthError(join
      ? "This request to add a machine expired or was already used. Run infraternal up again on the machine."
      : "This sign-in request expired or was already used. Ask the person who started it to run infraternal sign-in again.", 401);
  }
  if (error instanceof AuthError && error.status === 404) {
    return new AuthError(join
      ? "This server cannot add machines this way yet. Upgrade the server, then run infraternal up again."
      : "This server does not support device sign-in yet. Upgrade the server, then ask for a new link.", 404);
  }
  return error;
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

/** How long an API key may go unused before it stops working, in days. Owner only: anyone else gets `undefined`. */
export async function readKeyLifetime(): Promise<number | undefined> {
  try {
    const days = (await post<{ api_key_lifetime_days?: unknown }>("security-settings", {})).api_key_lifetime_days;
    return typeof days === "number" ? days : undefined;
  } catch (error: unknown) {
    if (error instanceof AuthError && (error.status === 401 || error.status === 403)) return undefined;
    throw error;
  }
}

/**
 * Sets that lifetime. The server wants a passkey login from the last few minutes, so a refusal is answered once with a fresh
 * passkey confirmation (a user action, as for a device approval) and the same request again; a second refusal is final.
 */
export async function writeKeyLifetime(days: number, device: string): Promise<void> {
  const body = { api_key_lifetime_days: days };
  try {
    await post("security-settings-update", body);
  } catch (error: unknown) {
    if (!(error instanceof AuthError) || (error.status !== 401 && error.status !== 403)) throw error;
    await loginWithPasskey(device);
    await post("security-settings-update", body);
  }
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

/** Setup facts only. No verification timestamp exists yet, so none is inferred. */
export interface AccountSummary {
  user_id: string;
  session_incarnation: string;
  passkeys: number;
  recovery_set_up: boolean;
}

export async function readAccountSummary(): Promise<AccountSummary> {
  const summary = await post<AccountSummary>("account-summary", {});
  if (typeof summary.user_id !== "string" || typeof summary.session_incarnation !== "string"
    || !Number.isSafeInteger(summary.passkeys) || summary.passkeys < 0 || typeof summary.recovery_set_up !== "boolean") {
    throw new AuthError("Your account summary could not be read. Try again.");
  }
  return summary;
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

/**
 * The one change a passkey tap is for (D336). The server binds the tap to exactly this action and
 * these parameters, once, for two minutes; a sign-in without one authorizes none of these changes.
 * Key approval is not listed: its tap is its own ceremony (`approveDeviceApproval`), bound to its code.
 */
export type TapAction =
  | { kind: "passkey.add" }
  | { kind: "recovery.rotate" }
  | { kind: "security.settings"; api_key_lifetime_days: number };

/** Completes a UV-required passkey login and verifies its DEK envelope locally. */
export async function loginWithPasskey(device: string, action?: TapAction): Promise<string> {
  return unlockWithPasskey(device, undefined, undefined, action);
}

/** Adding a key needs the same authenticated local unwrap, without retaining a DEK in the screen. */
export async function addSecondPasskey(userId: string): Promise<void> {
  await unlockWithPasskey("Browser", userId, async (dek) => {
    const start = await post<AuthStart>("add-start", {});
    if (canonicalUuid(start.user_id, "passkey user id") !== userId) throw new AuthError("Your signed-in account changed. Reload and try again.");
    const publicKey = creationOptions(start.options.publicKey);
    const input = prfInputFrom(publicKey);
    let prf: Uint8Array | undefined;
    try {
      const created = await navigator.credentials.create({ publicKey });
      if (!(created instanceof PublicKeyCredential)) throw new AuthError("Passkey registration was cancelled.");
      if (credentialOutputs(created).prf?.enabled !== true) throw new AuthError("This passkey cannot protect your account key. Choose another passkey.");
      prf = prfFrom(created) ?? await credentialPrf(created, publicKey.rp.id, input);
      const wrap = await wrapDek(prf, dek, userId, "passkey");
      await post("registration-finish", { ceremony: requiredString(start.ceremony, "registration ceremony"), proof: credentialProof(created), passkey_wrap: wrap });
    } finally { prf?.fill(0); input.fill(0); }
  }, { kind: "passkey.add" });
}

async function unlockWithPasskey(
  device: string,
  expectedUser?: string,
  useKey?: (key: Uint8Array) => Promise<void>,
  action?: TapAction,
): Promise<string> {
  const start = await post<AuthStart>("login-start", {
    ...(expectedUser ? { user_id: expectedUser } : {}),
    ...(action ? { action } : {}),
  });
  const publicKey = requestOptions(start.options.publicKey);
  let prf: Uint8Array | undefined;
  let userId: string;
  let unlockedKey: Uint8Array | undefined;

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
      if (expectedUser && userId !== expectedUser) throw new AuthError("Choose a passkey for the account you are adding to.");
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
      unlockedKey = await unwrapDek(prf, envelope, userId, "passkey");
      if (unlockedKey.byteLength !== 32) throw new AuthError("Your account key could not be unlocked. Try again.");
      if (!useKey) { unlockedKey.fill(0); unlockedKey = undefined; }
      await post("unlock-finish", { pending_transaction: transaction });
    } catch (error: unknown) {
      try { await post("logout", { pending_transaction: transaction }); }
      catch { throw new AuthError("Your account key was not unlocked. Sign in again; this incomplete session cannot access the terminal."); }
      throw error;
    }
    if (useKey && unlockedKey) await useKey(unlockedKey);
    return userId;
  } finally {
    prf?.fill(0);
    unlockedKey?.fill(0);
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
