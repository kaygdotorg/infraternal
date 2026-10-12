/** Measures actual Worker signing at 12/1002 files using ephemeral keys and in-memory R2; run isolated under CPUWeight=10000, #154. */
import assert from 'node:assert/strict';
import { generateKeyPairSync, createHash, timingSafeEqual } from 'node:crypto';
import { pathToFileURL } from 'node:url';
const worker = (await import(pathToFileURL(process.argv[2]))).default;

Object.defineProperty(crypto.subtle, 'timingSafeEqual', {
  value: (a, b) => timingSafeEqual(Buffer.from(a), Buffer.from(b)),
});
const enc = new TextEncoder();
const str = (bytes) => {
  const size = Buffer.alloc(4); size.writeUInt32BE(bytes.length);
  return Buffer.concat([size, Buffer.from(bytes)]);
};
function fixture(version = '1.2.3', content = `${version}\n`) {
  const pair = generateKeyPairSync('ed25519');
  const raw = Buffer.from(pair.publicKey.export({ format: 'jwk' }).x, 'base64url');
  const publicKey = `ssh-ed25519 ${Buffer.concat([str(Buffer.from('ssh-ed25519')), str(raw)]).toString('base64')}`;
  const prefix = `releases/${version}/`;
  const objects = new Map([[`${prefix}infraternal`, enc.encode('synthetic executable')]]);
  if (content !== null) objects.set(`${prefix}VERSION`, enc.encode(content));
  const writes = [];
  const env = {
    SIGNING_KEY: pair.privateKey.export({ type: 'pkcs8', format: 'pem' }),
    PUBLIC_KEY: publicKey, CALLER_TOKEN: createHash('sha256').update(raw).digest('hex'),
    BUILDS: {
      async head(key) { return objects.has(key) ? {} : null; },
      async list({ prefix: start }) {
        return { objects: [...objects.keys()].filter(key => key.startsWith(start)).map(key => ({ key })), truncated: false };
      },
      async get(key) {
        const value = objects.get(key);
        return value === undefined ? null : {
          async arrayBuffer() { return typeof value === 'string' ? enc.encode(value) : value; },
          async text() { return typeof value === 'string' ? value : new TextDecoder().decode(value); },
        };
      },
      async put(key, value) { writes.push(key); objects.set(key, value); },
    },
  };
  const sign = () => worker.fetch(new Request('https://signer.invalid/sign', {
    method: 'POST', headers: { authorization: `Bearer ${env.CALLER_TOKEN}`, 'content-type': 'application/json' },
    body: JSON.stringify({ version }),
  }), env);
  return { env, objects, writes, prefix, sign, publicKey };
}

console.log(`machine=${process.env.HOSTNAME || 'infraternal-dev'} mode=${process.argv[3]} samples=30 artifact_bytes=1024 load_before=${(await import('node:fs')).readFileSync('/proc/loadavg','utf8').trim()}`);
for (const count of [10, 1000]) {
  const samples=[]; let published=0;
  for(let i=0;i<30;i++) {
    const f=fixture();
    for(let j=0;j<count;j++) f.objects.set(`${f.prefix}artifact-${j}`,new Uint8Array(1024));
    const start=performance.now();
    assert.equal((await f.sign()).status,200);
    samples.push(performance.now()-start);
    published=f.writes.reduce((n,k)=>n+new TextEncoder().encode(f.objects.get(k)).length,0);
  }
  samples.sort((a,b)=>a-b);
  console.log(`METRIC signer_artifacts=${count+2} wall_p50_ms=${samples[15].toFixed(3)} wall_p99_ms=${samples[29].toFixed(3)} published_bytes=${published}`);
}
console.log(`load_after=${(await import('node:fs')).readFileSync('/proc/loadavg','utf8').trim()}`);
