// SPDX-License-Identifier: AGPL-3.0-only
/**
 * infraternal release signer (D184, D220, D223, G2).
 *
 * A Cloudflare Worker that signs releases with a key nobody can read back:
 * SIGNING_KEY is a write-only Worker secret (Ed25519, PKCS#8 PEM exported from
 * the owner's 1Password). Agents and the release pipeline can ask it to sign;
 * they can never see the key, and their Cloudflare token cannot change this code.
 *
 * POST /sign {"version":"0.4.2"}  (Authorization: Bearer <CALLER_TOKEN>)
 *   1. Lists releases/<version>/ in the BUILDS R2 bucket and hashes every file
 *      itself (SHA-256) — it never trusts checksums sent by the caller.
 *   2. Writes releases/<version>/SHA256SUMS and an OpenSSH signature of it,
 *      releases/<version>/SHA256SUMS.sig (namespace "infraternal-release"),
 *      verifiable with: ssh-keygen -Y verify -f allowed_signers \
 *        -I release@infraternal.com -n infraternal-release -s SHA256SUMS.sig < SHA256SUMS
 *   3. Appends the release to releases/index.json (public, append-only list).
 *   4. Optionally notifies the owner (NOTIFY_URL, an ntfy-style POST endpoint).
 * Refuses: a version already signed, an empty release, more than one signature
 * per minute, a bad caller token.
 *
 * Bindings: BUILDS (R2 bucket). Secrets: SIGNING_KEY, CALLER_TOKEN.
 * Variables: PUBLIC_KEY (the "ssh-ed25519 AAAA…" line of the signing key).
 * Optional variable: NOTIFY_URL.
 */

const NAMESPACE = "infraternal-release";
const VERSION_RE = /^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$/;
const enc = new TextEncoder();

export default {
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
    catch (e) { return text(e instanceof Refusal ? e.message : "signing failed", e instanceof Refusal ? 409 : 500); }
  },
};

class Refusal extends Error {}

async function authorised(request, env) {
  const got = (request.headers.get("authorization") ?? "").replace(/^Bearer /, "");
  const want = env.CALLER_TOKEN ?? "";
  if (!want || got.length !== want.length) return false;
  const [a, b] = await Promise.all([digest(enc.encode(got)), digest(enc.encode(want))]);
  return crypto.subtle.timingSafeEqual(a, b);
}

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
      if (name && !name.includes("/") && name !== "SHA256SUMS" && name !== "SHA256SUMS.sig") names.push(name);
    }
    cursor = page.truncated ? page.cursor : undefined;
  } while (cursor);
  if (!names.length) throw new Refusal("no files in this release");
  names.sort();

  let sums = "";
  for (const name of names) {
    const obj = await env.BUILDS.get(prefix + name);
    sums += `${hex(await digest(await obj.arrayBuffer()))}  ${name}\n`;
  }
  const signature = await sshsig(env, enc.encode(sums));
  await env.BUILDS.put(`${prefix}SHA256SUMS`, sums, { httpMetadata: { contentType: "text/plain" } });
  await env.BUILDS.put(`${prefix}SHA256SUMS.sig`, signature, { httpMetadata: { contentType: "text/plain" } });

  const entry = { version, files: names, sums_sha256: hex(await digest(enc.encode(sums))), signed_at: new Date().toISOString() };
  index.push(entry);
  await env.BUILDS.put("releases/index.json", JSON.stringify(index, null, 2), { httpMetadata: { contentType: "application/json" } });
  if (env.NOTIFY_URL) {
    try { await fetch(env.NOTIFY_URL, { method: "POST", body: `infraternal ${version} signed (${names.length} files)` }); } catch { /* notification is best effort */ }
  }
  return entry;
}

async function readIndex(env) {
  const obj = await env.BUILDS.get("releases/index.json");
  return obj ? JSON.parse(await obj.text()) : [];
}

/** An OpenSSH signature (PROTOCOL.sshsig) over `message`, armored, hash sha512. */
async function sshsig(env, message) {
  const key = await crypto.subtle.importKey("pkcs8", pemBytes(env.SIGNING_KEY), { name: "Ed25519" }, false, ["sign"]);
  const pub = publicBlob(env.PUBLIC_KEY);
  const h = new Uint8Array(await crypto.subtle.digest("SHA-512", message));
  const signed = concat(enc.encode("SSHSIG"), str(enc.encode(NAMESPACE)), str(new Uint8Array(0)), str(enc.encode("sha512")), str(h));
  const raw = new Uint8Array(await crypto.subtle.sign("Ed25519", key, signed));
  const sigBlob = concat(str(enc.encode("ssh-ed25519")), str(raw));
  const blob = concat(enc.encode("SSHSIG"), u32(1), str(pub), str(enc.encode(NAMESPACE)), str(new Uint8Array(0)), str(enc.encode("sha512")), str(sigBlob));
  const b64 = btoa(String.fromCharCode(...blob)).replace(/(.{70})/g, "$1\n").replace(/\n$/, "");
  return `-----BEGIN SSH SIGNATURE-----\n${b64}\n-----END SSH SIGNATURE-----\n`;
}

function publicBlob(line) {
  const parts = String(line ?? "").trim().split(/\s+/);
  if (parts[0] !== "ssh-ed25519" || !parts[1]) throw new Error("PUBLIC_KEY must be an ssh-ed25519 line");
  return Uint8Array.from(atob(parts[1]), (c) => c.charCodeAt(0));
}
function pemBytes(pem) {
  const b64 = String(pem ?? "").replace(/-----[^-]+-----/g, "").replace(/\s+/g, "");
  return Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
}
const u32 = (n) => new Uint8Array([(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255]);
const str = (bytes) => concat(u32(bytes.length), bytes);
function concat(...parts) {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let i = 0; for (const p of parts) { out.set(p, i); i += p.length; }
  return out;
}
const digest = async (data) => new Uint8Array(await crypto.subtle.digest("SHA-256", data));
const hex = (bytes) => [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
const text = (body, status = 200) => new Response(body, { status, headers: { "content-type": "text/plain" } });
const json = (body) => new Response(JSON.stringify(body), { headers: { "content-type": "application/json" } });
