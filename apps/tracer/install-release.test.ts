// SPDX-License-Identifier: AGPL-3.0-only
/**
 * Unit tests for release channel pointer resolution and OpenSSH `SSHSIG` Ed25519 verification (#211, D184, D224, D226).
 *
 * Covers default-stable channel selection, explicit `?channel=edge`, real `release/allowed_signers` parsing,
 * verified pointer resolution, empty-channel handling with no fallback to edge, cross-channel refusal,
 * tampered signature / untrusted key / wrong namespace refusal, and tampered `VERSION` / manifest refusal.
 */
import { expect, test } from "bun:test";
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import {
  DEFAULT_RELEASE_ORIGIN,
  installCommandFor,
  parseAllowedSigners,
  parseChannelPointer,
  RELEASE_SIGNER_NAMESPACE,
  RELEASE_SIGNER_PRINCIPAL,
  resolveChannelRelease,
  selectChannel,
  versionChannel,
} from "./install-release";

/** Shared UTF-8 encoder for test fixtures. */
const enc = new TextEncoder();

/** Encodes a big-endian 32-bit unsigned integer for OpenSSH wire framing. */
const u32 = (n: number): Uint8Array => new Uint8Array([(n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff]);

/** Concatenates byte slices into one buffer. */
function concat(...parts: readonly Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((sum, p) => sum + p.byteLength, 0));
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.byteLength;
  }
  return out;
}

/** Encodes a length-prefixed OpenSSH wire string. */
const sshStr = (bytes: Uint8Array): Uint8Array => concat(u32(bytes.byteLength), bytes);

/** Lowercase hex digest of `bytes` using SHA-256. */
async function sha256Hex(bytes: Uint8Array): Promise<string> {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", bytes.slice()));
  return [...digest].map((b) => b.toString(16).padStart(2, "0")).join("");
}

/** Base64-encodes `bytes`. */
const toBase64 = (bytes: Uint8Array): string => Buffer.from(bytes).toString("base64");

/** Ephemeral Ed25519 signing keypair formatted as an OpenSSH `allowed_signers` entry and signer helper. */
interface TestSigner {
  allowedSigners: string;
  pubBlob: Uint8Array;
  sign(message: Uint8Array, namespace?: string): Promise<string>;
}

/** Generates an ephemeral Ed25519 keypair and `SSHSIG` signer matching `apps/release-signer/src/index.js`. */
async function createTestSigner(): Promise<TestSigner> {
  const pair = (await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"])) as CryptoKeyPair;
  const rawPub = new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey));
  const pubBlob = concat(sshStr(enc.encode("ssh-ed25519")), sshStr(rawPub));
  const allowedSigners = `${RELEASE_SIGNER_PRINCIPAL} namespaces="${RELEASE_SIGNER_NAMESPACE}" ssh-ed25519 ${toBase64(pubBlob)} test-key\n`;

  return {
    allowedSigners,
    pubBlob,
    async sign(message: Uint8Array, namespace = RELEASE_SIGNER_NAMESPACE): Promise<string> {
      const hash = new Uint8Array(await crypto.subtle.digest("SHA-512", message.slice()));
      const signed = concat(
        enc.encode("SSHSIG"),
        sshStr(enc.encode(namespace)),
        sshStr(new Uint8Array(0)),
        sshStr(enc.encode("sha512")),
        sshStr(hash),
      );
      const rawSig = new Uint8Array(await crypto.subtle.sign("Ed25519", pair.privateKey, signed.slice()));
      const sigBlob = concat(sshStr(enc.encode("ssh-ed25519")), sshStr(rawSig));
      const armorBody = concat(
        enc.encode("SSHSIG"),
        u32(1),
        sshStr(pubBlob),
        sshStr(enc.encode(namespace)),
        sshStr(new Uint8Array(0)),
        sshStr(enc.encode("sha512")),
        sshStr(sigBlob),
      );
      const b64 = toBase64(armorBody).replace(/(.{70})/g, "$1\n").replace(/\n$/, "");
      return `-----BEGIN SSH SIGNATURE-----\n${b64}\n-----END SSH SIGNATURE-----\n`;
    },
  };
}

/** Builds a complete in-memory release fixture signed by `signer`. */
async function signedReleaseFiles(
  signer: TestSigner,
  version: string,
  channel: "stable" | "edge",
  binaryText = "fake-server-binary",
): Promise<Map<string, string>> {
  const versionText = `${version}\n`;
  const sumsText = `${await sha256Hex(enc.encode(versionText))}  VERSION\n${await sha256Hex(enc.encode(binaryText))}  infraternal\n`;
  const sigText = await signer.sign(enc.encode(sumsText));
  const pointer = JSON.stringify({ version, channel, files: ["VERSION", "infraternal"] });
  return new Map<string, string>([
    [`/releases/channels/${channel}.json`, pointer],
    [`/releases/${version}/SHA256SUMS`, sumsText],
    [`/releases/${version}/SHA256SUMS.sig`, sigText],
    [`/releases/${version}/VERSION`, versionText],
  ]);
}

/** Creates a mock `fetch` serving `files` by URL pathname and recording requested paths. */
function mockFetch(files: Map<string, string>): { fetchFn: typeof fetch; requested: string[] } {
  const requested: string[] = [];
  const fetchFn = (async (input: RequestInfo | URL): Promise<Response> => {
    const pathname = new URL(String(input)).pathname;
    requested.push(pathname);
    const body = files.get(pathname);
    if (body === undefined) return new Response("not found", { status: 404 });
    return new Response(body, { status: 200 });
  }) as typeof fetch;
  return { fetchFn, requested };
}

test("channel selection defaults to stable and only opts into edge when explicitly asked", () => {
  expect(selectChannel("")).toBe("stable");
  expect(selectChannel("?channel=stable")).toBe("stable");
  expect(selectChannel("?channel=beta")).toBe("stable");
  expect(selectChannel("?foo=edge")).toBe("stable");
  expect(selectChannel("?channel=edge")).toBe("edge");
  expect(installCommandFor(DEFAULT_RELEASE_ORIGIN, "stable")).toBe(
    "curl -fsSL https://builds.infraternal.com/install.sh | sh",
  );
  expect(installCommandFor(DEFAULT_RELEASE_ORIGIN, "edge")).toBe(
    "curl -fsSL https://builds.infraternal.com/install.sh | sh -s -- --channel edge",
  );
});

test("release/allowed_signers parses both production Ed25519 trust anchors", async () => {
  const text = await readFile(resolve(import.meta.dirname, "../../release/allowed_signers"), "utf8");
  const keys = parseAllowedSigners(text);
  expect(keys.length).toBe(2);
  for (const key of keys) expect(key.byteLength).toBe(51);
});

test("version classification and pointer grammar match the updater", () => {
  expect(versionChannel("0.10.2")).toBe("stable");
  expect(versionChannel("edge-20261125T050000Z")).toBe("edge");
  expect(versionChannel("latest")).toBeNull();
  expect(() => parseChannelPointer(enc.encode('{"version":"0.1.0","extra":1}'), "stable")).toThrow(/invalid release pointer/);
  expect(() => parseChannelPointer(enc.encode('{"version":"edge-20261125T050000Z"}'), "stable")).toThrow(/another channel/);
  expect(() => parseChannelPointer(enc.encode('{"version":"0.1.0"}'), "edge")).toThrow(/another channel/);
});

test("resolves and verifies a signed stable channel pointer", async () => {
  const signer = await createTestSigner();
  const files = await signedReleaseFiles(signer, "1.2.3", "stable");
  const { fetchFn, requested } = mockFetch(files);

  const resolved = await resolveChannelRelease({
    channel: "stable",
    allowedSigners: signer.allowedSigners,
    fetchFn,
  });

  expect(resolved.state).toBe("verified");
  if (resolved.state !== "verified") return;
  expect(resolved.version).toBe("1.2.3");
  expect(resolved.binaryUrl).toBe("https://builds.infraternal.com/releases/1.2.3/infraternal");
  expect(resolved.sumsUrl).toBe("https://builds.infraternal.com/releases/1.2.3/SHA256SUMS");
  expect(resolved.signatureUrl).toBe("https://builds.infraternal.com/releases/1.2.3/SHA256SUMS.sig");
  expect(requested).not.toContain("/releases/channels/edge.json");
});

test("resolves and verifies a signed edge channel pointer when explicitly requested", async () => {
  const signer = await createTestSigner();
  const version = "edge-20261125T050000Z";
  const files = await signedReleaseFiles(signer, version, "edge");
  const { fetchFn } = mockFetch(files);

  const resolved = await resolveChannelRelease({
    channel: "edge",
    allowedSigners: signer.allowedSigners,
    fetchFn,
  });

  expect(resolved.state).toBe("verified");
  if (resolved.state !== "verified") return;
  expect(resolved.version).toBe(version);
  expect(resolved.binaryUrl).toBe(`https://builds.infraternal.com/releases/${version}/infraternal`);
});

test("empty stable channel reports empty and never falls back to edge", async () => {
  const signer = await createTestSigner();
  const files = await signedReleaseFiles(signer, "edge-20261125T050000Z", "edge");
  const { fetchFn, requested } = mockFetch(files);

  const resolved = await resolveChannelRelease({
    channel: "stable",
    allowedSigners: signer.allowedSigners,
    fetchFn,
  });

  expect(resolved).toEqual({
    state: "empty",
    channel: "stable",
    message: "No stable release is published yet.",
  });
  expect(requested).toEqual(["/releases/channels/stable.json"]);
});

test("refuses a tampered signature, untrusted signing key, and wrong namespace", async () => {
  const trusted = await createTestSigner();
  const untrusted = await createTestSigner();
  const version = "edge-20261125T050000Z";

  // 1. Tampered SHA256SUMS after signing (invalid Ed25519 signature).
  const tamperedFiles = await signedReleaseFiles(trusted, version, "edge");
  tamperedFiles.set(
    `/releases/${version}/SHA256SUMS`,
    tamperedFiles.get(`/releases/${version}/SHA256SUMS`)!.replace("infraternal", "infraternal-tampered"),
  );
  const tampered = await resolveChannelRelease({
    channel: "edge",
    allowedSigners: trusted.allowedSigners,
    fetchFn: mockFetch(tamperedFiles).fetchFn,
  });
  expect(tampered.state).toBe("refused");

  // 2. Signed by an untrusted key.
  const wrongKeyFiles = await signedReleaseFiles(untrusted, version, "edge");
  const wrongKey = await resolveChannelRelease({
    channel: "edge",
    allowedSigners: trusted.allowedSigners,
    fetchFn: mockFetch(wrongKeyFiles).fetchFn,
  });
  expect(wrongKey.state).toBe("refused");

  // 3. Signed by the trusted key under the wrong SSHSIG namespace.
  const wrongNsFiles = await signedReleaseFiles(trusted, version, "edge");
  const sums = enc.encode(wrongNsFiles.get(`/releases/${version}/SHA256SUMS`)!);
  wrongNsFiles.set(`/releases/${version}/SHA256SUMS.sig`, await trusted.sign(sums, "wrong-namespace"));
  const wrongNs = await resolveChannelRelease({
    channel: "edge",
    allowedSigners: trusted.allowedSigners,
    fetchFn: mockFetch(wrongNsFiles).fetchFn,
  });
  expect(wrongNs.state).toBe("refused");
});

test("refuses a signed VERSION mismatch or a manifest missing the server binary", async () => {
  const signer = await createTestSigner();
  const version = "edge-20261125T050000Z";

  // 1. Signed release whose VERSION is a different version (replay under another pointer).
  const replayFiles = await signedReleaseFiles(signer, "edge-20261124T010000Z", "edge");
  replayFiles.set("/releases/channels/edge.json", JSON.stringify({ version, channel: "edge" }));
  replayFiles.set(`/releases/${version}/SHA256SUMS`, replayFiles.get("/releases/edge-20261124T010000Z/SHA256SUMS")!);
  replayFiles.set(`/releases/${version}/SHA256SUMS.sig`, replayFiles.get("/releases/edge-20261124T010000Z/SHA256SUMS.sig")!);
  replayFiles.set(`/releases/${version}/VERSION`, replayFiles.get("/releases/edge-20261124T010000Z/VERSION")!);
  const replay = await resolveChannelRelease({
    channel: "edge",
    allowedSigners: signer.allowedSigners,
    fetchFn: mockFetch(replayFiles).fetchFn,
  });
  expect(replay.state).toBe("refused");

  // 2. Signed manifest missing the `infraternal` server binary.
  const versionText = `${version}\n`;
  const sumsText = `${await sha256Hex(enc.encode(versionText))}  VERSION\n`;
  const missingServerFiles = new Map<string, string>([
    ["/releases/channels/edge.json", JSON.stringify({ version, channel: "edge" })],
    [`/releases/${version}/SHA256SUMS`, sumsText],
    [`/releases/${version}/SHA256SUMS.sig`, await signer.sign(enc.encode(sumsText))],
    [`/releases/${version}/VERSION`, versionText],
  ]);
  const missingServer = await resolveChannelRelease({
    channel: "edge",
    allowedSigners: signer.allowedSigners,
    fetchFn: mockFetch(missingServerFiles).fetchFn,
  });
  expect(missingServer.state).toBe("refused");
});
