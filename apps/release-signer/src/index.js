// SPDX-License-Identifier: AGPL-3.0-only
/**
 * infraternal release signer (D184, D220, D223, G2).
 *
 * A Cloudflare Worker that signs releases with a key nobody can read back:
 * SIGNING_KEY is a write-only Worker secret (Ed25519, PKCS#8 PEM exported from
 * the owner's 1Password). Agents and the release pipeline can ask it to sign;
 * they can never see the key, and their Cloudflare token cannot change this code.
 *
 * POST /sign {"version":"0.4.2" | "edge-20261011T071500Z"}  (Authorization: Bearer <CALLER_TOKEN>)
 *   Two channels (D226): stable versions are x.y.z; edge versions are edge-<UTC timestamp>.
 *   The channel is read from the version string, which the signed VERSION file carries,
 *   so it is covered by the signature and never a separate unsigned field.
 *   1. Lists releases/<version>/ in the BUILDS R2 bucket and hashes every file
 *      itself (SHA-256) — it never trusts checksums sent by the caller.
 *   2. Writes releases/<version>/SHA256SUMS and an OpenSSH signature of it,
 *      releases/<version>/SHA256SUMS.sig (namespace "infraternal-release"),
 *      verifiable with: ssh-keygen -Y verify -f allowed_signers \
 *        -I release@infraternal.com -n infraternal-release -s SHA256SUMS.sig < SHA256SUMS
 *   3. Appends the release to releases/index.json (public, append-only list) and
 *      points releases/channels/<channel>.json at it (the newest release per channel).
 *   4. Optionally notifies the owner (NOTIFY_URL, an ntfy-style POST endpoint).
 * Refuses: a version already signed, an empty release, more than one signature
 * per minute, a bad caller token.
 *
 * SIGNING_KEY may be pasted in any form a key manager exports: PKCS#8 (v1 or the
 * v2 layout that also carries the public key) or an unencrypted OpenSSH private key.
 * The Worker takes the 32-byte Ed25519 seed from it and rebuilds a v1 PKCS#8 for the
 * runtime, then signs a probe and checks it against PUBLIC_KEY before signing anything,
 * so a mismatched pair is refused instead of publishing signatures nobody can verify.
 * Errors name the problem (format, mismatch, storage) but never key material.
 *
 * Bindings: BUILDS (R2 bucket). Secrets: SIGNING_KEY, CALLER_TOKEN.
 * Variables: PUBLIC_KEY (the "ssh-ed25519 AAAA…" line of the signing key).
 * Optional variable: NOTIFY_URL.
 */

/** SSH signature namespace; a verifier must pass the same `-n` value or the signature is rejected. */
const NAMESPACE = "infraternal-release";
/** Accepted version strings. Stable: x.y.z. Edge: edge-YYYYMMDDTHHMMSSZ (UTC; sorts by time as text). */
const VERSION_RE = /^(?:[0-9]+\.[0-9]+\.[0-9]+|edge-[0-9]{8}T[0-9]{6}Z)$/;
/** The release channel ("edge" or "stable") a validated version string belongs to. */
const channelOf = (version) => (version.startsWith("edge-") ? "edge" : "stable");
/** Readable copyright and permission notices required in every newly signed release. */
const REQUIRED_LICENSE_FILES = new Set([
  "licenses/libghostty-vt/README.md",
  "licenses/libghostty-vt/Unicode-3.0.txt",
  "licenses/libghostty-vt/aro-MIT.txt",
  "licenses/libghostty-vt/highway-Apache-2.0.txt",
  "licenses/libghostty-vt/highway-BSD-3-Clause.txt",
  "licenses/libghostty-vt/libghostty-vt-MIT.txt",
  "licenses/libghostty-vt/simdutf-Apache-2.0.txt",
  "licenses/libghostty-vt/simdutf-MIT.txt",
  "licenses/libghostty-vt/translate_c-MIT.txt",
  "licenses/libghostty-vt/uucode-MIT.txt",
  "licenses/libghostty-vt/wuffs-Apache-2.0.txt",
  "licenses/libghostty-vt/wuffs-MIT.txt",
]);
const enc = new TextEncoder();

export default {
  /**
   * Worker entry point. Routes:
   * - `GET /pubkey`: returns the configured PUBLIC_KEY line (empty text if unset).
   * - `POST /sign`: signs a release (see the module comment). Answers 401 for a bad caller
   *   token, 400 for a malformed body or version, 409 when the request is refused
   *   (already signed, empty release, rate limit) and 500 when signing fails. A 500 body
   *   names the key problem but never contains key material.
   * - anything else: 404.
   */
  async fetch(request, env) {
    const url = new URL(request.url);
    if (request.method === "GET" && url.pathname === "/pubkey") return text(env.PUBLIC_KEY ?? "");
    if (request.method !== "POST" || url.pathname !== "/sign") return text("not found", 404);
    if (!(await authorised(request, env))) return text("unauthorised", 401);
    let body;
    try { body = await request.json(); } catch { return text("bad request", 400); }
    const version = String(body?.version ?? "");
    if (!VERSION_RE.test(version)) return text("bad version", 400);
    try { return json(await signRelease(env, version)); }
    catch (e) {
      if (e instanceof Refusal) return text(e.message, 409);
      if (e instanceof KeyProblem) return text(`signing key: ${e.message}`, 500);
      return text("signing failed", 500);
    }
  },
};

/** A request that is valid but must not be served (already signed, empty release, rate limit); mapped to HTTP 409. */
class Refusal extends Error {}
/** A problem with SIGNING_KEY or PUBLIC_KEY; its message is safe to return (no key bytes). */
class KeyProblem extends Error {}

/**
 * Checks the `Authorization: Bearer` header against CALLER_TOKEN. Both sides are hashed and
 * compared in constant time so the comparison does not leak how much of the token matched.
 * An unset CALLER_TOKEN rejects every request.
 */
async function authorised(request, env) {
  const got = (request.headers.get("authorization") ?? "").replace(/^Bearer /, "");
  const want = env.CALLER_TOKEN ?? "";
  if (!want || got.length !== want.length) return false;
  const [a, b] = await Promise.all([digest(enc.encode(got)), digest(enc.encode(want))]);
  return crypto.subtle.timingSafeEqual(a, b);
}

/**
 * Signs one release and publishes its metadata; returns the index entry that was appended.
 * Throws {@link Refusal} when the version already has a signature, the release folder has no
 * files, any required license notice is missing, or the previous signature was under a minute
 * ago. Files are hashed here from the bucket, never taken from the caller. The signature objects are written before the index,
 * so a release only appears in `index.json` once its `SHA256SUMS.sig` exists. The optional
 * notification is best effort and cannot fail the signing.
 */
async function signRelease(env, version) {
  const prefix = `releases/${version}/`;
  if (await env.BUILDS.head(`${prefix}SHA256SUMS.sig`)) throw new Refusal("already signed");
  const index = await readIndex(env);
  const last = index.at(-1);
  if (last && Date.now() - Date.parse(last.signed_at) < 60_000) throw new Refusal("one signature per minute");

  const names = [];
  let cursor;
  do {
    const page = await env.BUILDS.list({ prefix, cursor });
    for (const o of page.objects) {
      const name = o.key.slice(prefix.length);
      if (name && (!name.includes("/") || REQUIRED_LICENSE_FILES.has(name)) && name !== "SHA256SUMS" && name !== "SHA256SUMS.sig") names.push(name);
    }
    cursor = page.truncated ? page.cursor : undefined;
  } while (cursor);
  if (!names.length) throw new Refusal("no files in this release");
  const found = new Set(names);
  if ([...REQUIRED_LICENSE_FILES].some((name) => !found.has(name))) throw new Refusal("release is missing required license notices");
  const key = await signingKey(env);
  names.sort();

  let sums = "";
  for (const name of names) {
    const obj = await env.BUILDS.get(prefix + name);
    sums += `${hex(await digest(await obj.arrayBuffer()))}  ${name}\n`;
  }
  const signature = await sshsig(key, publicBlob(env.PUBLIC_KEY), enc.encode(sums));
  await env.BUILDS.put(`${prefix}SHA256SUMS`, sums, { httpMetadata: { contentType: "text/plain" } });
  await env.BUILDS.put(`${prefix}SHA256SUMS.sig`, signature, { httpMetadata: { contentType: "text/plain" } });

  const entry = { version, channel: channelOf(version), files: names, sums_sha256: hex(await digest(enc.encode(sums))), signed_at: new Date().toISOString() };
  index.push(entry);
  await env.BUILDS.put("releases/index.json", JSON.stringify(index, null, 2), { httpMetadata: { contentType: "application/json" } });
  await env.BUILDS.put(`releases/channels/${entry.channel}.json`, JSON.stringify(entry, null, 2), { httpMetadata: { contentType: "application/json" } });
  if (env.NOTIFY_URL) {
    try { await fetch(env.NOTIFY_URL, { method: "POST", body: `infraternal ${version} signed (${names.length} files)` }); } catch { /* notification is best effort */ }
  }
  return entry;
}

/** The public append-only release list from `releases/index.json`; empty before the first release. */
async function readIndex(env) {
  const obj = await env.BUILDS.get("releases/index.json");
  return obj ? JSON.parse(await obj.text()) : [];
}

/**
 * The Ed25519 signing key, checked against PUBLIC_KEY: a probe is signed and verified with
 * the public key before any release is, so a mismatched pair never publishes a signature.
 */
async function signingKey(env) {
  const pub = publicBlob(env.PUBLIC_KEY);
  const rawPub = pub.subarray(pub.length - 32);
  let key;
  try {
    key = await crypto.subtle.importKey("pkcs8", pkcs8v1(seedOf(env.SIGNING_KEY)), { name: "Ed25519" }, false, ["sign"]);
  } catch (e) {
    throw e instanceof KeyProblem ? e : new KeyProblem("the runtime rejected the Ed25519 key");
  }
  const probe = enc.encode("infraternal-release key check");
  const sig = await crypto.subtle.sign("Ed25519", key, probe);
  const verifier = await crypto.subtle.importKey("raw", rawPub, { name: "Ed25519" }, false, ["verify"]);
  if (!(await crypto.subtle.verify("Ed25519", verifier, sig, probe))) throw new KeyProblem("SIGNING_KEY does not match PUBLIC_KEY");
  return key;
}

/**
 * An OpenSSH signature (PROTOCOL.sshsig) over `message`, armored, hash sha512.
 * @param key the imported Ed25519 private CryptoKey
 * @param pub the SSH public key blob (see {@link publicBlob}), embedded in the signature
 * @param message the bytes being signed (the SHA256SUMS text)
 * @returns the `-----BEGIN SSH SIGNATURE-----` text that `ssh-keygen -Y verify` reads
 */
async function sshsig(key, pub, message) {
  const h = new Uint8Array(await crypto.subtle.digest("SHA-512", message));
  const signed = concat(enc.encode("SSHSIG"), str(enc.encode(NAMESPACE)), str(new Uint8Array(0)), str(enc.encode("sha512")), str(h));
  const raw = new Uint8Array(await crypto.subtle.sign("Ed25519", key, signed));
  const sigBlob = concat(str(enc.encode("ssh-ed25519")), str(raw));
  const blob = concat(enc.encode("SSHSIG"), u32(1), str(pub), str(enc.encode(NAMESPACE)), str(new Uint8Array(0)), str(enc.encode("sha512")), str(sigBlob));
  const b64 = btoa(String.fromCharCode(...blob)).replace(/(.{70})/g, "$1\n").replace(/\n$/, "");
  return `-----BEGIN SSH SIGNATURE-----\n${b64}\n-----END SSH SIGNATURE-----\n`;
}

/**
 * The 32-byte Ed25519 seed from a pasted private key. PKCS#8 (v1 and v2) wraps the seed as
 * OCTET STRING { OCTET STRING (32) }, i.e. the bytes 04 22 04 20 then the seed; an unencrypted
 * OpenSSH key holds "ssh-ed25519", the public key, then 64 bytes whose first 32 are the seed.
 */
function seedOf(pem) {
  const text = String(pem ?? "");
  const label = /-----BEGIN ([A-Z ]+)-----/.exec(text)?.[1];
  if (!label) throw new KeyProblem("SIGNING_KEY is not a PEM block (expected -----BEGIN PRIVATE KEY-----)");
  let der;
  try { der = pemBytes(text); } catch { throw new KeyProblem("SIGNING_KEY is not valid base64"); }
  if (label === "PRIVATE KEY") {
    for (let i = 0; i + 36 <= der.length; i++) {
      if (der[i] === 0x04 && der[i + 1] === 0x22 && der[i + 2] === 0x04 && der[i + 3] === 0x20) return der.slice(i + 4, i + 36);
    }
    throw new KeyProblem("SIGNING_KEY is PKCS#8 but not an Ed25519 key");
  }
  if (label === "OPENSSH PRIVATE KEY") {
    const magic = enc.encode("openssh-key-v1\0");
    if (!magic.every((b, i) => der[i] === b)) throw new KeyProblem("SIGNING_KEY is not an OpenSSH key");
    let at = magic.length;
    const next = () => { const n = (der[at] << 24 | der[at + 1] << 16 | der[at + 2] << 8 | der[at + 3]) >>> 0; at += 4; const v = der.slice(at, at + n); at += n; return v; };
    const cipher = new TextDecoder().decode(next());
    if (cipher !== "none") throw new KeyProblem("SIGNING_KEY is passphrase-protected; export it without a passphrase");
    next(); next(); at += 4; next(); // kdf name, kdf options, key count, public key
    const priv = next();
    at = 0; const view = priv; const read = () => { const n = (view[at] << 24 | view[at + 1] << 16 | view[at + 2] << 8 | view[at + 3]) >>> 0; at += 4; const v = view.slice(at, at + n); at += n; return v; };
    at = 8; // two check integers
    if (new TextDecoder().decode(read()) !== "ssh-ed25519") throw new KeyProblem("SIGNING_KEY is an OpenSSH key but not Ed25519");
    read(); // public key
    const both = read();
    if (both.length !== 64) throw new KeyProblem("SIGNING_KEY has an unexpected OpenSSH layout");
    return both.slice(0, 32);
  }
  throw new KeyProblem(`SIGNING_KEY is a "${label}" block; expected PRIVATE KEY (PKCS#8) or OPENSSH PRIVATE KEY`);
}

/** A version-1 PKCS#8 wrapping of an Ed25519 seed (RFC 8410), the form every runtime imports. */
const pkcs8v1 = (seed) => concat(new Uint8Array([0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20]), seed);

/**
 * Decodes an `ssh-ed25519 AAAA…` public key line into its 51-byte SSH blob (4-byte length,
 * "ssh-ed25519", 4-byte length, 32-byte key). The last 32 bytes are the raw public key.
 * Throws {@link KeyProblem} for any other key type or a malformed line.
 */
function publicBlob(line) {
  const parts = String(line ?? "").trim().split(/\s+/);
  if (parts[0] !== "ssh-ed25519" || !parts[1]) throw new KeyProblem("PUBLIC_KEY must be an ssh-ed25519 line");
  let blob;
  try { blob = Uint8Array.from(atob(parts[1]), (c) => c.charCodeAt(0)); } catch { throw new KeyProblem("PUBLIC_KEY is not valid base64"); }
  if (blob.length !== 51) throw new KeyProblem("PUBLIC_KEY is not an Ed25519 public key");
  return blob;
}
/** The decoded base64 body of a PEM block, with the BEGIN/END lines and whitespace removed. Throws on invalid base64. */
function pemBytes(pem) {
  const b64 = String(pem ?? "").replace(/-----[^-]+-----/g, "").replace(/\s+/g, "");
  return Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
}
/** A big-endian 32-bit integer, as the SSH wire format writes it. */
const u32 = (n) => new Uint8Array([(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255]);
/** An SSH "string": a big-endian length followed by the bytes. */
const str = (bytes) => concat(u32(bytes.length), bytes);
/** Joins byte arrays into one new array. */
function concat(...parts) {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let i = 0; for (const p of parts) { out.set(p, i); i += p.length; }
  return out;
}
/** SHA-256 of `data` as bytes. */
const digest = async (data) => new Uint8Array(await crypto.subtle.digest("SHA-256", data));
/** Lowercase hexadecimal text of `bytes`, as `sha256sum` prints it. */
const hex = (bytes) => [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
/** A plain-text response with the given status (200 by default). */
const text = (body, status = 200) => new Response(body, { status, headers: { "content-type": "text/plain" } });
/** A 200 JSON response. */
const json = (body) => new Response(JSON.stringify(body), { headers: { "content-type": "application/json" } });
