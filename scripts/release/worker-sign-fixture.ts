// SPDX-License-Identifier: AGPL-3.0-only
/**
 * Signs a local release bundle with the real release-signer Worker code and a throwaway
 * Ed25519 key, so tests check exactly what the release pipeline signs [224,226], #211.
 *
 * Usage: `bun scripts/release/worker-sign-fixture.ts <bundle-directory> <version>`
 *
 * Every regular file under the bundle directory goes into an in-memory bucket under
 * `releases/<version>/`, the way `scripts/release/publish` uploads a built bundle. The
 * script then calls the Worker's own `POST /sign` handler and writes the Worker's
 * `SHA256SUMS` and `SHA256SUMS.sig` back into the bundle directory. It prints one
 * `allowed_signers` line that trusts the throwaway key, for the caller's verifier.
 *
 * Test use only. The key is generated in this process, never written to disk, and gone
 * when the process exits. It is not one of the D224 release keys and nothing trusts it
 * unless a test passes the printed line explicitly.
 */
import worker from "../../apps/release-signer/src/index.js";
import { readdirSync, readFileSync, writeFileSync } from "node:fs";
import { join, relative } from "node:path";

const [directory, version] = process.argv.slice(2);
if (!directory || !version) {
  console.error("usage: bun scripts/release/worker-sign-fixture.ts <bundle-directory> <version>");
  process.exit(2);
}
/** UTF-8 encoder for the SSH key blob and the bucket objects the Worker writes. */
const enc = new TextEncoder();
// The Workers runtime provides this method and Bun does not. The stand-in only compares
// the two digests the Worker passes it; the timing property does not matter in a test.
Object.defineProperty(crypto.subtle, "timingSafeEqual", {
  value: (a: ArrayBuffer, b: ArrayBuffer) => {
    const x = new Uint8Array(a);
    const y = new Uint8Array(b);
    return x.length === y.length && x.every((value, index) => value === y[index]);
  },
});

/** Every regular file below `root`, as bundle-relative names with `/` separators. */
function files(root: string, current = root): string[] {
  return readdirSync(current, { withFileTypes: true }).flatMap((entry) => {
    const path = join(current, entry.name);
    if (entry.isDirectory()) return files(root, path);
    return entry.isFile() ? [relative(root, path)] : [];
  });
}

/** The bucket folder the publisher uploads this release to. */
const prefix = `releases/${version}/`;
/** The in-memory stand-in for the R2 bucket, keyed by object name. */
const store = new Map<string, Uint8Array>();
for (const name of files(directory)) {
  // Copy into a fresh buffer: a pooled Buffer's `.buffer` can hold unrelated bytes.
  store.set(prefix + name, new Uint8Array(readFileSync(join(directory, name))));
}
/** The throwaway Ed25519 key pair; it exists only in this process. */
const pair = (await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"])) as CryptoKeyPair;
/** The raw 32-byte public key. */
const raw = new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey));
/** The private key as PKCS#8 DER, the form the Worker reads from SIGNING_KEY. */
const pkcs8 = new Uint8Array(await crypto.subtle.exportKey("pkcs8", pair.privateKey));
/** SSH wire form of the public key: string "ssh-ed25519", then the 32 raw key bytes. */
const blob = new Uint8Array(51);
blob.set([0, 0, 0, 11]);
blob.set(enc.encode("ssh-ed25519"), 4);
blob.set([0, 0, 0, 32], 15);
blob.set(raw, 19);
/** The `ssh-ed25519 AAAA…` line the Worker gets as PUBLIC_KEY and the verifier trusts. */
const publicKey = `ssh-ed25519 ${Buffer.from(blob).toString("base64")}`;
/** Wraps stored bytes in the subset of the R2 object interface the Worker reads. */
const object = (bytes: Uint8Array) => ({
  arrayBuffer: async () => bytes.buffer,
  text: async () => new TextDecoder().decode(bytes),
});
/** The Worker bindings: test caller token, throwaway key, and the in-memory bucket. */
const env = {
  CALLER_TOKEN: "fixture",
  SIGNING_KEY: `-----BEGIN PRIVATE KEY-----\n${Buffer.from(pkcs8).toString("base64")}\n-----END PRIVATE KEY-----`,
  PUBLIC_KEY: publicKey,
  BUILDS: {
    head: async (name: string) => store.has(name),
    get: async (name: string) => (store.has(name) ? object(store.get(name)!) : null),
    list: async ({ prefix: wanted }: { prefix: string }) => ({
      objects: [...store.keys()].filter((key) => key.startsWith(wanted)).map((key) => ({ key })),
      truncated: false,
    }),
    put: async (name: string, body: string) => {
      store.set(name, enc.encode(body));
    },
  },
};
/** The Worker's answer to the same `POST /sign` request `scripts/release/publish` sends. */
const response = await worker.fetch(
  new Request("http://127.0.0.1/sign", {
    method: "POST",
    headers: { authorization: "Bearer fixture" },
    body: JSON.stringify({ version }),
  }),
  env,
);
if (response.status !== 200) {
  console.error(`the release signer refused: ${response.status} ${await response.text()}`);
  process.exit(1);
}
for (const name of ["SHA256SUMS", "SHA256SUMS.sig"]) {
  writeFileSync(join(directory, name), store.get(prefix + name)!);
}
console.log(`release@infraternal.com namespaces="infraternal-release" ${publicKey} worker-fixture`);
