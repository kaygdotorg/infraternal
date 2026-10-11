/** Defensive tests of the real signer Worker with ephemeral in-memory keys and R2 fixtures, #154 [224][226]. */
import { readFileSync, writeFileSync, mkdtempSync, rmSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { join } from 'node:path';
import { createHash, generateKeyPairSync, timingSafeEqual } from 'node:crypto';
import { pathToFileURL } from 'node:url';

const [workerPath, testCase = 'coverage'] = process.argv.slice(2);
if (!workerPath) throw new Error('usage: node signer-audit.mjs WORKER.mjs [coverage|missing-version|mismatched-version|unsafe-name]');
const expected = 'f55fbc9a5f3df4d6b88e7395f68b7afbbbc65094752d11e803a412b73539c746';
if (createHash('sha256').update(readFileSync(workerPath)).digest('hex') !== expected) throw new Error('Worker snapshot differs from recorded audit source');
// Cloudflare exposes this constant-time operation on SubtleCrypto. Reuse the
// native constant-time comparison locally; all signing/digests use real WebCrypto.
Object.defineProperty(crypto.subtle, 'timingSafeEqual', { value: (a, b) => timingSafeEqual(Buffer.from(a), Buffer.from(b)) });
const worker = (await import(pathToFileURL(workerPath))).default;
const enc = new TextEncoder();
const dec = new TextDecoder();
const pair = generateKeyPairSync('ed25519');
const spare = generateKeyPairSync('ed25519');
const rawPublic = Buffer.from(pair.publicKey.export({ format: 'jwk' }).x, 'base64url');
const str = (bytes) => { const length = Buffer.alloc(4); length.writeUInt32BE(bytes.length); return Buffer.concat([length, Buffer.from(bytes)]); };
const blob = Buffer.concat([str(Buffer.from('ssh-ed25519')), str(rawPublic)]);
const publicLine = `ssh-ed25519 ${blob.toString('base64')}`;
const version = '1.2.3';
const prefix = `releases/${version}/`;
const objects = new Map([[`${prefix}infraternal`, enc.encode('synthetic executable bytes')]]);
if (testCase !== 'missing-version') objects.set(`${prefix}VERSION`, enc.encode(testCase === 'mismatched-version' ? 'edge-20261011T071500Z\n' : `${version}\n`));
if (testCase === 'unsafe-name') objects.set(`${prefix}artifact\noutside`, enc.encode('synthetic data'));
const env = {
  // Generated only in this process. Never print, persist or pass these values in argv.
  SIGNING_KEY: pair.privateKey.export({ type: 'pkcs8', format: 'pem' }),
  PUBLIC_KEY: publicLine,
  CALLER_TOKEN: createHash('sha256').update(rawPublic).digest('hex'),
  BUILDS: {
    async head(key) { return objects.has(key) ? {} : null; },
    async list({ prefix: start }) { return { objects: [...objects.keys()].filter(key => key.startsWith(start)).map(key => ({ key })), truncated: false }; },
    async get(key) {
      const value = objects.get(key);
      return value === undefined ? null : { async arrayBuffer() { return value; }, async text() { return typeof value === 'string' ? value : dec.decode(value); } };
    },
    async put(key, value) { objects.set(key, value); },
  },
};
const response = await worker.fetch(new Request('https://signer.invalid/sign', {
  method: 'POST', headers: { authorization: `Bearer ${env.CALLER_TOKEN}`, 'content-type': 'application/json' }, body: JSON.stringify({ version }),
}), env);
if (testCase !== 'coverage') {
  console.log(`TEST signer_${testCase} status=${response.status} expected=409`);
  if (response.status !== 409) throw new Error('signer must refuse missing/mismatched VERSION or unsafe checksum names');
} else {
  if (response.status !== 200) throw new Error('valid fixture refused');
  const sums = String(objects.get(`${prefix}SHA256SUMS`));
  const armored = String(objects.get(`${prefix}SHA256SUMS.sig`));
  const signature = Buffer.from(armored.split('\n').slice(1, -2).join(''), 'base64');
  let offset = 10; // SSHSIG magic and uint32 version.
  const take = () => { const length = signature.readUInt32BE(offset); offset += 4; const value = signature.subarray(offset, offset + length); offset += length; return value; };
  const publicBlob = take(); const namespace = take(); const reserved = take(); const algorithm = take(); const signatureBlob = take();
  if (!publicBlob.equals(blob) || namespace.toString() !== 'infraternal-release' || algorithm.toString() !== 'sha512' || reserved.length !== 0) throw new Error('SSHSIG metadata differs');
  const verify = async (message, publicKey = rawPublic) => {
    const hash = await crypto.subtle.digest('SHA-512', enc.encode(message));
    const signed = Buffer.concat([Buffer.from('SSHSIG'), str(namespace), str(reserved), str(algorithm), str(new Uint8Array(hash))]);
    const key = await crypto.subtle.importKey('raw', publicKey, { name: 'Ed25519' }, false, ['verify']);
    const signatureOffset = 4 + signatureBlob.readUInt32BE(0);
    const rawSignature = signatureBlob.subarray(signatureOffset + 4);
    return crypto.subtle.verify('Ed25519', key, rawSignature, signed);
  };
  if (!await verify(sums)) throw new Error('real signature rejected');
  if (await verify(sums + 'changed')) throw new Error('tampered sums accepted');
  if (await verify(sums, Buffer.from(spare.publicKey.export({ format: 'jwk' }).x, 'base64url'))) throw new Error('other key accepted');
  const expectedVersionHash = createHash('sha256').update(objects.get(`${prefix}VERSION`)).digest('hex');
  if (!sums.includes(`${expectedVersionHash}  VERSION\n`)) throw new Error('VERSION bytes not covered');
  const pointer = JSON.parse(String(objects.get('releases/channels/stable.json')));
  if (pointer.channel !== 'stable' || pointer.version !== version) throw new Error('pointer mismatch');
  const directory = mkdtempSync(join(process.env.HOME, '.cache/codex-scratch/audit-ca-update/ssh-verify-'));
  try {
    const allowed = join(directory, 'allowed_signers');
    const signaturePath = join(directory, 'SHA256SUMS.sig');
    writeFileSync(allowed, `release@infraternal.com ${publicLine}\n`, { mode: 0o600 });
    writeFileSync(signaturePath, armored, { mode: 0o600 });
    const sshVerify = (message) => spawnSync('ssh-keygen', ['-Y', 'verify', '-f', allowed, '-I', 'release@infraternal.com', '-n', 'infraternal-release', '-s', signaturePath], { input: message, encoding: 'utf8' }).status;
    if (sshVerify(sums) !== 0) throw new Error('real ssh-keygen rejects Worker SSHSIG');
    if (sshVerify(sums + 'changed') === 0) throw new Error('real ssh-keygen accepts altered SUMS');
    const otherRaw = Buffer.from(spare.publicKey.export({ format: 'jwk' }).x, 'base64url');
    const otherBlob = Buffer.concat([str(Buffer.from('ssh-ed25519')), str(otherRaw)]);
    writeFileSync(allowed, `release@infraternal.com ssh-ed25519 ${otherBlob.toString('base64')}\n`, { mode: 0o600 });
    if (sshVerify(sums) === 0) throw new Error('real ssh-keygen accepts another pinned public key');
  } finally { rmSync(directory, { recursive: true, force: true }); }
  console.log('TEST signer_coverage PASS ssh_keygen_verified=true real_SSHSIG=true tampered_sums_refused=true other_key_refused=true VERSION_hash_covered=true unsigned_pointer_requires_client_validation=true');
}
