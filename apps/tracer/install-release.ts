// SPDX-License-Identifier: AGPL-3.0-only
/**
 * Resolves and verifies a release channel pointer (`stable` or `edge`) for the install page (#211, D184, D224, D226).
 *
 * This mirrors the server updater's verification flow (`crates/plugins/release/src/latest.rs` and `pointer.rs`):
 * 1. Fetch `<origin>/releases/channels/<channel>.json` (at most 64 KiB) and parse its untrusted candidate version,
 *    refusing unknown JSON fields and cross-channel versions.
 * 2. Fetch `SHA256SUMS` (<= 64 KiB), `SHA256SUMS.sig` (<= 1 KiB), and `VERSION` (<= 128 B) under
 *    `<origin>/releases/<version>/`.
 * 3. Verify the OpenSSH `SSHSIG` Ed25519 signature over `SHA256SUMS` against the trusted keys from
 *    `release/allowed_signers` in namespace `infraternal-release` using WebCrypto (`crypto.subtle`), with zero
 *    external dependencies.
 * 4. Check that `SHA256SUMS` lists `VERSION` and the server image `infraternal`, that `VERSION` matches its signed
 *    SHA-256 digest, and that `VERSION` contains `<version>\n`.
 *
 * The default channel is always `stable`; `edge` is selected only when explicitly requested (`?channel=edge`).
 * Stable never falls back to edge.
 */

/** A release channel name supported by the release bucket and updater. */
export type ReleaseChannel = "stable" | "edge";

/** The public origin for installation scripts, trust anchors and signed release files (D401). */
export const DEFAULT_SITE_ORIGIN = "https://infraternal.com";

/** The OpenSSH signature namespace every release signature must bind to (`apps/release-signer/src/index.js`). */
export const RELEASE_SIGNER_NAMESPACE = "infraternal-release";

/** The principal name listed in `release/allowed_signers`. */
export const RELEASE_SIGNER_PRINCIPAL = "release@infraternal.com";

/** The server image filename offered on `/install/` (x86-64 Linux only, J1134/J1135). */
export const SERVER_IMAGE_NAME = "infraternal";

/** Maximum byte size accepted for `pointer.json` and `SHA256SUMS`, matching `crates/plugins/release/src/latest.rs`. */
const MAX_MANIFEST_BYTES = 65_536;

/** Maximum byte size accepted for `SHA256SUMS.sig`, matching `crates/plugins/release/src/latest.rs`. */
const MAX_SIGNATURE_BYTES = 1_024;

/** Maximum byte size accepted for `VERSION`, matching `crates/plugins/release/src/latest.rs`. */
const MAX_VERSION_BYTES = 128;

/** Allowed top-level keys in a channel pointer JSON object (`crates/plugins/release/src/pointer.rs`). */
const ALLOWED_POINTER_KEYS = new Set(["version", "channel", "files", "sums_sha256", "signed_at"]);

/** Stable release version grammar (`x.y.z`). */
const STABLE_VERSION_RE = /^[0-9]+\.[0-9]+\.[0-9]+$/;

/** Edge release version grammar (`edge-YYYYMMDDTHHMMSSZ`). */
const EDGE_VERSION_RE = /^edge-[0-9]{8}T[0-9]{6}Z$/;

/** One line of a `SHA256SUMS` manifest: 64 lowercase hex characters, two spaces, and a relative filename. */
const SUMS_LINE_RE = /^([0-9a-f]{64})  ([^\s/].*)$/;

/** OpenSSH `SSHSIG` wire magic prefix (6 ASCII bytes). */
const SSHSIG_MAGIC = new TextEncoder().encode("SSHSIG");

/** Shared UTF-8 encoder for wire-format framing. */
const encoder = new TextEncoder();

/** Shared strict UTF-8 decoder for release metadata text. */
const decoder = new TextDecoder("utf-8", { fatal: true });

/** Result of resolving and verifying one release channel. */
export type ResolvedRelease =
  | {
      state: "verified";
      channel: ReleaseChannel;
      version: string;
      baseUrl: string;
      binaryUrl: string;
      sumsUrl: string;
      signatureUrl: string;
      binarySha256: string;
    }
  | {
      state: "empty";
      channel: ReleaseChannel;
      message: string;
    }
  | {
      state: "refused";
      channel: ReleaseChannel;
      message: string;
    };

/** Inputs to {@link resolveChannelRelease}. */
export interface ResolveChannelOptions {
  /** Origin serving the release files (defaults to {@link DEFAULT_SITE_ORIGIN}). */
  origin?: string;
  /** The channel to resolve (`stable` by default; `edge` only when explicitly requested). */
  channel: ReleaseChannel;
  /** Contents of `release/allowed_signers` holding the trusted Ed25519 release signing keys. */
  allowedSigners: string;
  /** Optional `fetch` implementation for tests. */
  fetchFn?: typeof fetch;
}

/**
 * Selects the release channel from a URL query string.
 * Only an explicit `channel=edge` selects `edge`; every other value or absence stays on `stable`.
 */
export function selectChannel(search: string): ReleaseChannel {
  const params = new URLSearchParams(search);
  return params.get("channel") === "edge" ? "edge" : "stable";
}

/**
 * Returns the `curl` one-liner for `channel`.
 * Stable omits `--channel` so the public command stays short; edge passes `--channel edge` explicitly.
 */
export function installCommandFor(origin: string, channel: ReleaseChannel): string {
  const cleanOrigin = origin.replace(/\/+$/, "");
  return channel === "edge"
    ? `curl -fsSL ${cleanOrigin}/install.sh | sh -s -- --channel edge`
    : `curl -fsSL ${cleanOrigin}/install.sh | sh`;
}

/**
 * Classifies a release version string into `"stable"` or `"edge"`, or `null` if malformed.
 * Matches `crates/infraternal-plugin-api/src/release_version.rs`.
 */
export function versionChannel(version: string): ReleaseChannel | null {
  if (STABLE_VERSION_RE.test(version)) return "stable";
  if (EDGE_VERSION_RE.test(version)) return "edge";
  return null;
}

/**
 * Validates an untrusted channel pointer JSON payload and returns its candidate version string.
 * Refuses oversized payloads, non-objects, unknown fields, and versions belonging to another channel.
 * The returned version is still unauthenticated until verified against the signed `VERSION` file.
 */
export function parseChannelPointer(bytes: Uint8Array, channel: ReleaseChannel): string {
  if (bytes.byteLength > MAX_MANIFEST_BYTES) throw new Error("invalid release pointer");
  let firstNonWs: number | undefined;
  for (const byte of bytes) {
    if (byte !== 0x20 && byte !== 0x09 && byte !== 0x0a && byte !== 0x0d) {
      firstNonWs = byte;
      break;
    }
  }
  if (firstNonWs !== 0x7b) throw new Error("invalid release pointer");
  let parsed: unknown;
  try {
    parsed = JSON.parse(decoder.decode(bytes));
  } catch {
    throw new Error("invalid release pointer");
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    throw new Error("invalid release pointer");
  }
  const record = parsed as Record<string, unknown>;
  for (const key of Object.keys(record)) {
    if (!ALLOWED_POINTER_KEYS.has(key)) throw new Error("invalid release pointer");
  }
  if (typeof record.version !== "string") throw new Error("invalid release pointer");
  if (versionChannel(record.version) !== channel) {
    throw new Error("release pointer belongs to another channel");
  }
  return record.version;
}

/** Decodes a standard base64 string into bytes, rejecting invalid characters or padding. */
function decodeBase64(b64: string): Uint8Array {
  const clean = b64.replace(/\s+/g, "");
  if (clean.length === 0 || clean.length % 4 !== 0 || !/^[A-Za-z0-9+/]*={0,2}$/.test(clean)) {
    throw new Error("invalid base64 encoding");
  }
  const raw = atob(clean);
  const out = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i++) out[i] = raw.charCodeAt(i);
  return out;
}

/** Compares two byte arrays for exact equality. */
function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.byteLength !== b.byteLength) return false;
  let diff = 0;
  for (let i = 0; i < a.byteLength; i++) diff |= a[i]! ^ b[i]!;
  return diff === 0;
}

/** Encodes a big-endian 32-bit unsigned integer for OpenSSH wire framing. */
function encodeU32(n: number): Uint8Array {
  return new Uint8Array([(n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff]);
}

/** Encodes a length-prefixed OpenSSH wire string. */
function encodeSshString(bytes: Uint8Array): Uint8Array {
  const out = new Uint8Array(4 + bytes.byteLength);
  out.set(encodeU32(bytes.byteLength), 0);
  out.set(bytes, 4);
  return out;
}

/** Concatenates multiple byte slices into one buffer. */
function concatBytes(...parts: readonly Uint8Array[]): Uint8Array {
  const total = parts.reduce((sum, part) => sum + part.byteLength, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.byteLength;
  }
  return out;
}

/** Cursor for reading big-endian integers and length-prefixed strings from an OpenSSH wire blob. */
class SshReader {
  private readonly bytes: Uint8Array;
  private offset = 0;

  /** Creates a reader over `bytes` starting at offset 0. */
  constructor(bytes: Uint8Array) {
    this.bytes = bytes;
  }

  /** Number of unread bytes remaining in the buffer. */
  remaining(): number {
    return this.bytes.byteLength - this.offset;
  }

  /** Reads `count` raw bytes or throws if the buffer ends early. */
  readBytes(count: number): Uint8Array {
    if (count < 0 || this.offset + count > this.bytes.byteLength) {
      throw new Error("truncated SSH signature");
    }
    const slice = this.bytes.subarray(this.offset, this.offset + count);
    this.offset += count;
    return slice;
  }

  /** Reads a big-endian 32-bit unsigned integer. */
  readU32(): number {
    const b = this.readBytes(4);
    return ((b[0]! << 24) | (b[1]! << 16) | (b[2]! << 8) | b[3]!) >>> 0;
  }

  /** Reads a length-prefixed OpenSSH wire string. */
  readString(): Uint8Array {
    return this.readBytes(this.readU32());
  }
}

/** Extracts the 32-byte raw Ed25519 public key from a 51-byte OpenSSH `ssh-ed25519` public key blob. */
function extractEd25519RawPublicKey(blob: Uint8Array): Uint8Array {
  if (blob.byteLength !== 51) throw new Error("unsupported signing key");
  const reader = new SshReader(blob);
  const keyType = decoder.decode(reader.readString());
  const raw = reader.readString();
  if (keyType !== "ssh-ed25519" || raw.byteLength !== 32 || reader.remaining() !== 0) {
    throw new Error("unsupported signing key");
  }
  return raw;
}

/**
 * Parses `release/allowed_signers` into trusted 51-byte OpenSSH Ed25519 public key blobs.
 * Only lines matching {@link RELEASE_SIGNER_PRINCIPAL} and {@link RELEASE_SIGNER_NAMESPACE} are accepted.
 */
export function parseAllowedSigners(text: string): Uint8Array[] {
  const keys: Uint8Array[] = [];
  for (const rawLine of text.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith("#")) continue;
    const fields = line.split(/\s+/);
    const principal = fields[0];
    if (principal !== RELEASE_SIGNER_PRINCIPAL) continue;
    let index = 1;
    if (fields[index]?.startsWith("namespaces=")) {
      const nsMatch = /^namespaces="([^"]+)"$/.exec(fields[index]!);
      if (!nsMatch || !nsMatch[1]!.split(",").includes(RELEASE_SIGNER_NAMESPACE)) continue;
      index++;
    }
    if (fields[index] !== "ssh-ed25519" || !fields[index + 1]) continue;
    const blob = decodeBase64(fields[index + 1]!);
    extractEd25519RawPublicKey(blob);
    keys.push(blob);
  }
  if (keys.length === 0) throw new Error("no trusted release signing keys configured");
  return keys;
}

/**
 * Strips canonical 70-column OpenSSH `SSHSIG` PEM armor and decodes the binary signature blob.
 * Matches `crates/infraternal-server/src/release_verify.rs`: refuses leading/trailing whitespace,
 * CRLF line endings, and non-70-column wrapping so mutated armor is never accepted.
 */
function decodeArmoredSshSig(signatureText: string): Uint8Array {
  const prefix = "-----BEGIN SSH SIGNATURE-----\n";
  const suffix = "-----END SSH SIGNATURE-----\n";
  if (!signatureText.startsWith(prefix) || !signatureText.endsWith(suffix)) {
    throw new Error("release signature is malformed");
  }
  const body = signatureText.slice(prefix.length, signatureText.length - suffix.length);
  if (body.length === 0 || body.includes("\r") || !body.endsWith("\n")) {
    throw new Error("release signature is malformed");
  }
  const encoded = body.slice(0, -1).split("\n").join("");
  let canonical = "";
  for (let i = 0; i < encoded.length; i += 70) {
    canonical += `${encoded.slice(i, i + 70)}\n`;
  }
  if (canonical !== body) throw new Error("release signature is malformed");
  return decodeBase64(encoded);
}

/**
 * Verifies an armored OpenSSH `SSHSIG` Ed25519 signature over `message` against `trustedPubBlobs`.
 * Enforces canonical 70-column armor, version 1, namespace `infraternal-release`, empty reserved field,
 * `sha512` hash (matching `crates/infraternal-server/src/release_verify.rs` and the release-signer Worker),
 * exact key match against `trustedPubBlobs`, and a valid Ed25519 signature via WebCrypto.
 */
export async function verifySshSignature(
  message: Uint8Array,
  signatureText: string,
  trustedPubBlobs: readonly Uint8Array[],
): Promise<void> {
  if (trustedPubBlobs.length === 0) throw new Error("no trusted release signing keys configured");
  const blob = decodeArmoredSshSig(signatureText);
  const reader = new SshReader(blob);
  const magic = reader.readBytes(SSHSIG_MAGIC.byteLength);
  if (!bytesEqual(magic, SSHSIG_MAGIC)) throw new Error("release signature is malformed");
  const version = reader.readU32();
  if (version !== 1) throw new Error("unsupported release signature version");

  const pubBlob = reader.readString();
  const namespace = decoder.decode(reader.readString());
  const reserved = reader.readString();
  const hashAlgorithm = decoder.decode(reader.readString());
  const sigBlob = reader.readString();
  if (reader.remaining() !== 0) throw new Error("release signature has trailing data");

  if (namespace !== RELEASE_SIGNER_NAMESPACE) throw new Error("release signature namespace mismatch");
  if (reserved.byteLength !== 0) throw new Error("release signature has unexpected reserved field");
  if (!trustedPubBlobs.some((trusted) => bytesEqual(trusted, pubBlob))) {
    throw new Error("release signing key is not trusted");
  }

  if (hashAlgorithm !== "sha512") {
    throw new Error("unsupported release signature hash algorithm");
  }

  const sigReader = new SshReader(sigBlob);
  const sigType = decoder.decode(sigReader.readString());
  const rawSig = sigReader.readString();
  if (sigType !== "ssh-ed25519" || rawSig.byteLength !== 64 || sigReader.remaining() !== 0) {
    throw new Error("unsupported release signature algorithm");
  }

  const rawPub = extractEd25519RawPublicKey(pubBlob);
  const digestBytes = new Uint8Array(await crypto.subtle.digest("SHA-512", message.slice()));
  const signedPayload = concatBytes(
    SSHSIG_MAGIC,
    encodeSshString(encoder.encode(namespace)),
    encodeSshString(reserved),
    encodeSshString(encoder.encode(hashAlgorithm)),
    encodeSshString(digestBytes),
  );

  const key = await crypto.subtle.importKey("raw", rawPub.slice(), { name: "Ed25519" }, false, ["verify"]);
  const valid = await crypto.subtle.verify("Ed25519", key, rawSig.slice(), signedPayload.slice());
  if (!valid) throw new Error("release signature could not be verified");
}

/**
 * Parses a `SHA256SUMS` file into a map of filename to lowercase 64-character hex digest.
 * Rejects malformed lines, path traversal, and duplicate filenames.
 */
export function parseSha256Sums(text: string): Map<string, string> {
  const entries = new Map<string, string>();
  const lines = text.split(/\r?\n/).filter((line) => line.length > 0);
  if (lines.length === 0) throw new Error("release manifest is empty");
  for (const line of lines) {
    const match = SUMS_LINE_RE.exec(line);
    if (!match) throw new Error("release manifest is malformed");
    const digest = match[1]!;
    const name = match[2]!;
    if (name.includes("..") || name.includes("\\") || entries.has(name)) {
      throw new Error("release manifest is malformed");
    }
    entries.set(name, digest);
  }
  return entries;
}

/** Lowercase hexadecimal encoding of a byte array. */
function toHex(bytes: Uint8Array): string {
  let out = "";
  for (const byte of bytes) out += byte.toString(16).padStart(2, "0");
  return out;
}

/**
 * Verifies a release's signed metadata (`SHA256SUMS`, `SHA256SUMS.sig`, and `VERSION`) against
 * the candidate `expectedVersion` and `channel`.
 * Returns the verified filename-to-SHA-256 map when every check passes.
 */
export async function verifyReleaseMetadata(
  expectedVersion: string,
  channel: ReleaseChannel,
  sumsBytes: Uint8Array,
  signatureText: string,
  versionBytes: Uint8Array,
  trustedPubBlobs: readonly Uint8Array[],
): Promise<Map<string, string>> {
  if (versionChannel(expectedVersion) !== channel) {
    throw new Error("release pointer belongs to another channel");
  }
  if (sumsBytes.byteLength > MAX_MANIFEST_BYTES) throw new Error("release manifest is too large");
  if (signatureText.length > MAX_SIGNATURE_BYTES) throw new Error("release signature is too large");
  if (versionBytes.byteLength > MAX_VERSION_BYTES) throw new Error("release VERSION is too large");

  await verifySshSignature(sumsBytes, signatureText, trustedPubBlobs);
  const sums = parseSha256Sums(decoder.decode(sumsBytes));
  const expectedVersionDigest = sums.get("VERSION");
  if (!expectedVersionDigest || !sums.has(SERVER_IMAGE_NAME)) {
    throw new Error("release manifest is missing required files");
  }

  const actualVersionDigest = toHex(new Uint8Array(await crypto.subtle.digest("SHA-256", versionBytes.slice())));
  if (actualVersionDigest !== expectedVersionDigest) {
    throw new Error("release VERSION digest does not match SHA256SUMS");
  }
  if (decoder.decode(versionBytes) !== `${expectedVersion}\n`) {
    throw new Error("signed VERSION does not match the release pointer");
  }
  return sums;
}

/** Downloads one bounded file over HTTP, returning `null` on 404 when `allowMissing` is set. */
async function fetchBounded(
  fetchFn: typeof fetch,
  url: string,
  maxBytes: number,
  allowMissing = false,
): Promise<Uint8Array | null> {
  const response = await fetchFn(url, { cache: "no-store" });
  if (allowMissing && response.status === 404) return null;
  if (!response.ok) throw new Error(`release fetch failed (${response.status})`);
  const lengthHeader = response.headers.get("content-length");
  if (lengthHeader !== null) {
    const parsedLength = Number(lengthHeader);
    if (Number.isFinite(parsedLength) && parsedLength > maxBytes) {
      throw new Error("release metadata exceeded its size limit");
    }
  }
  const bytes = new Uint8Array(await response.arrayBuffer());
  if (bytes.byteLength > maxBytes) throw new Error("release metadata exceeded its size limit");
  return bytes;
}

/**
 * Resolves the current release for `options.channel` through its channel pointer and verifies
 * its signature, checksums, and signed `VERSION` file before returning download URLs.
 */
export async function resolveChannelRelease(options: ResolveChannelOptions): Promise<ResolvedRelease> {
  const origin = (options.origin ?? DEFAULT_SITE_ORIGIN).replace(/\/+$/, "");
  const fetchFn = options.fetchFn ?? fetch;
  try {
    const trustedKeys = parseAllowedSigners(options.allowedSigners);
    const pointerBytes = await fetchBounded(
      fetchFn,
      `${origin}/releases/channels/${options.channel}.json`,
      MAX_MANIFEST_BYTES,
      true,
    );
    if (pointerBytes === null) {
      return {
        state: "empty",
        channel: options.channel,
        message: options.channel === "stable"
          ? "No stable release is published yet."
          : "No edge release is published yet.",
      };
    }

    const version = parseChannelPointer(pointerBytes, options.channel);
    const baseUrl = `${origin}/releases/${version}`;
    const [sumsBytes, sigBytes, versionBytes] = await Promise.all([
      fetchBounded(fetchFn, `${baseUrl}/SHA256SUMS`, MAX_MANIFEST_BYTES),
      fetchBounded(fetchFn, `${baseUrl}/SHA256SUMS.sig`, MAX_SIGNATURE_BYTES),
      fetchBounded(fetchFn, `${baseUrl}/VERSION`, MAX_VERSION_BYTES),
    ]);
    if (!sumsBytes || !sigBytes || !versionBytes) {
      throw new Error("release metadata is incomplete");
    }

    const sums = await verifyReleaseMetadata(
      version,
      options.channel,
      sumsBytes,
      decoder.decode(sigBytes),
      versionBytes,
      trustedKeys,
    );
    return {
      state: "verified",
      channel: options.channel,
      version,
      baseUrl,
      binaryUrl: `${baseUrl}/${SERVER_IMAGE_NAME}`,
      sumsUrl: `${baseUrl}/SHA256SUMS`,
      signatureUrl: `${baseUrl}/SHA256SUMS.sig`,
      binarySha256: sums.get(SERVER_IMAGE_NAME)!,
    };
  } catch (error) {
    const reason = error instanceof Error ? error.message : "release signature could not be verified";
    return {
      state: "refused",
      channel: options.channel,
      message: reason,
    };
  }
}
