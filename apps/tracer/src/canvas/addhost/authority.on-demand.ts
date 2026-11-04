/**
 * Reads public CA lock and root-expiry status and runs the existing purpose-bound passkey ceremony [D168].
 * Status contains only public root metadata; malformed or unavailable status never implies an unlocked CA.
 */
import { recoveryAuth as auth, type AuthStart, type Wrap } from "../../auth";
import { isCanonicalUuid } from "../../identifiers";
import { ServiceError, type AuthorityRootStatus, type AuthorityStatus } from "./service";

interface CaStart extends AuthStart { ca: { member: string; generation: number; salt: string; operation?: "setup" | "unlock" } }
interface StoredWrap { kind: string; key_id: string; wrap: Wrap; prf_input?: string }

async function post<T>(path: string, body: unknown): Promise<T> {
  const response = await fetch(`/remote/ca/${path}`, { method: "POST", credentials: "same-origin", cache: "no-store", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
  if (!response.ok) throw new ServiceError(response.status === 404 || response.status === 503 ? "Host connections are not configured on this server. Configure the remote component on the server, then try again." : "Host connections could not be unlocked. Use an administrator passkey and try again.");
  try { return await response.json() as T; } catch { throw new ServiceError("Host connections are not configured on this server. Set up the remote component first."); }
}

export async function authorityStatus(): Promise<AuthorityStatus> {
  const status = await post<AuthorityStatus>("status", {});
  if (status.available === false) throw new ServiceError("Host connections are not configured on this server. Configure the remote component on the server, then try again.");
  if (status.available !== undefined && typeof status.available !== "boolean") throw new ServiceError("Host connection status needs a server update. Try again.");
  if (typeof status.initialized !== "boolean" || (status.locked !== null && typeof status.locked !== "boolean")) throw new ServiceError("Host connections need a server update before setup is available.");
  if (status.clock_healthy !== undefined && typeof status.clock_healthy !== "boolean") throw new ServiceError("Host connection status needs a server update. Try again.");
  if (status.roots !== undefined && (!Array.isArray(status.roots) || status.roots.some((root) => !validRootStatus(root)))) {
    throw new ServiceError("Host connection status needs a server update. Try again.");
  }
  return status;
}

/** Whether one root's status from the server has the documented shape and a known warning level. */
function validRootStatus(value: unknown): value is AuthorityRootStatus {
  if (typeof value !== "object" || value === null) return false;
  const root = value as Partial<AuthorityRootStatus>;
  return typeof root.generation === "number" && Number.isSafeInteger(root.generation) && root.generation > 0
    && typeof root.fingerprint === "string"
    && typeof root.not_after === "number" && Number.isSafeInteger(root.not_after)
    && (root.remaining_seconds === null || (typeof root.remaining_seconds === "number" && Number.isSafeInteger(root.remaining_seconds)))
    && typeof root.warning_level === "string"
    && ["none", "365d", "90d", "30d", "7d", "expired", "unknown"].includes(root.warning_level);
}

/** This domain is specified by the retained CA copy contract, including the exact membership generation. */
export async function deriveCaKey(dek: Uint8Array, salt: Uint8Array, member: string, generation: number): Promise<Uint8Array> {
  if (dek.length !== 32 || salt.length !== 32 || !isCanonicalUuid(member) || !Number.isSafeInteger(generation) || generation < 1) throw new ServiceError("Host connection setup returned an invalid answer. Try again.");
  const material = await crypto.subtle.importKey("raw", auth.toArrayBuffer(dek), "HKDF", false, ["deriveBits"]);
  return new Uint8Array(await crypto.subtle.deriveBits({ name: "HKDF", hash: "SHA-256", salt: auth.toArrayBuffer(salt), info: auth.toArrayBuffer(new TextEncoder().encode(`infraternal/ca-wrap/v1|${member}|${generation}`)) }, material, 256));
}

/** Shown when a passkey proves who you are but cannot give the secret that unlocks your account key (#153). */
const NO_PRF = "This passkey signed you in, but it can't unlock host connections from here. Try again where your passkey app works directly, such as its browser extension or your own computer, instead of scanning a QR code.";

export async function unlockAuthority(): Promise<void> {
  // Bootstrap chooses setup for a fresh server and ordinary unlock for retained trust.
  const start = await post<CaStart>("bootstrap/start", {});
  const publicKey = auth.requestOptions(start.options.publicKey);
  let prf: Uint8Array | undefined;
  let dek: Uint8Array | undefined;
  let scoped: Uint8Array | undefined;
  let input: Uint8Array | undefined;
  let salt: Uint8Array | undefined;
  try {
    const assertion = await navigator.credentials.get({ publicKey });
    if (!(assertion instanceof PublicKeyCredential)) throw new ServiceError("Passkey confirmation was cancelled. Try again.");
    const session = await auth.post<{ user_id: string }>("session", {});
    const member = auth.canonicalUuid(start.ca.member, "CA member");
    if (session.user_id !== member) throw new ServiceError("Use the current administrator's passkey.");
    const wraps = await auth.post<StoredWrap[]>("wraps", {});
    const keyId = auth.base64url(auth.copyBytes(assertion.rawId, "rawId"));
    const entry = wraps.find((wrap) => wrap.kind === "passkey" && wrap.key_id === keyId);
    if (!entry?.prf_input || !entry.wrap) throw new ServiceError("This passkey cannot unlock your account key. Sign in with an administrator passkey and try again.");
    input = auth.decodeBase64url(entry.prf_input);
    prf = auth.prfFrom(assertion);
    const requested = publicKey.extensions && (publicKey.extensions as { prf?: unknown }).prf;
    const askedThisCredential = !!requested && auth.base64url(auth.prfInputFrom(publicKey)) === entry.prf_input;
    // The passkey was asked for its unlock secret and gave none: a second prompt would fail the same way (common on
    // the phone/QR route), so say what happened and what works instead (#153). A second prompt stays only for the
    // case where the first request could not have asked this credential the right question.
    if (!prf && askedThisCredential) throw new ServiceError(NO_PRF);
    if (!prf || !askedThisCredential) {
      prf?.fill(0);
      try { prf = await auth.credentialPrf(assertion, publicKey.rpId, input); }
      catch { throw new ServiceError(NO_PRF); }
    }
    dek = await auth.unwrapDek(prf, entry.wrap, member, "passkey");
    salt = auth.decodeBase64url(start.ca.salt);
    scoped = await deriveCaKey(dek, salt, member, start.ca.generation);
    await post("bootstrap/finish", { ceremony: auth.requiredString(start.ceremony, "CA ceremony"), proof: auth.credentialProof(assertion), scoped_key: [...scoped] });
  } finally {
    prf?.fill(0); dek?.fill(0); scoped?.fill(0); input?.fill(0); salt?.fill(0);
  }
}
