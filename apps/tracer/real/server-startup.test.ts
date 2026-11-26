/** Role: prove private server fixture startup cleanup and HTTP/2 header translation (#146, #573). */
import { expect, test } from 'bun:test';
import { resolve } from 'node:path';
import {
  forwardRequestHeaders,
  forwardResponseHeaders,
  resolveServerProtocol,
  type RealServerProtocol,
} from './server';

/**
 * Runs a failed `startRealServer` attempt in a subprocess so even a buggy baseline cannot leave a TLS listener open
 * in the test runner.
 */
async function probeFailedStartup(protocol: RealServerProtocol): Promise<{ reason: string; released: boolean; remaining: number }> {
  const worker = `
import { startRealServer } from ${JSON.stringify(resolve(import.meta.dirname, 'server.ts'))};
import { createServer } from 'node:net';
import { mkdir, mkdtemp, symlink, unlink, rm, readdir, writeFile } from 'node:fs/promises';
import { homedir } from 'node:os';
import { dirname } from 'node:path';
const target=process.env.CARGO_TARGET_DIR;
const parent=target?.startsWith(homedir()+'/.cache/codex-scratch/')?dirname(target):homedir()+'/.cache/codex-scratch/fixture-server-startup';
await mkdir(parent,{recursive:true});
const root=await mkdtemp(parent+'/startup-test-');
// The backend exits before serving a page; this input must not require a prior frontend build.
const dist=await mkdtemp(parent+'/startup-web-');
await writeFile(dist+'/index.html','<!-- Role: inert web input for the failed-startup cleanup fixture. -->');
process.env.TRACER_DIST=dist;
const alias=homedir()+'/.cache/codex-scratch/u'+process.pid.toString(36);
await symlink(root,alias);
process.env.INFRATERNAL_BIN='/bin/false';
process.env.INFRATERNAL_TEST_STATE_ROOT=alias;
process.env.REAL_SERVER_LOG='0';
const reserve=createServer();await new Promise(r=>reserve.listen(0,'127.0.0.1',r));
const port=reserve.address().port;await new Promise(r=>reserve.close(r));
let reason='';let fixture;
try{fixture=await startRealServer({port,address:'127.0.0.1',stateRoot:root,protocol:${JSON.stringify(protocol)}});}
catch(e){reason=e.message==='server startup failed'?'startup_failed':'other';}
const probe=createServer();
const released=await new Promise(r=>{probe.once('error',()=>r(false));probe.listen(port,'127.0.0.1',()=>probe.close(()=>r(true)));});
const remaining=(await readdir(root)).length;
await fixture?.dispose();
await unlink(alias);await rm(root,{recursive:true,force:true});await rm(dist,{recursive:true,force:true});
console.log(JSON.stringify({reason,released,remaining}));
process.exit(0);
`;
  const child = Bun.spawn([process.execPath, '--eval', worker], {
    cwd: resolve(import.meta.dirname, '../../..'),
    stdout: 'pipe', stderr: 'ignore',
  });
  const deadline = setTimeout(() => child.kill(), 30_000);
  let code: number; let output: string;
  try { [code, output] = await Promise.all([child.exited, new Response(child.stdout).text()]); }
  finally { clearTimeout(deadline); if (child.exitCode === null) child.kill(); }
  expect(code).toBe(0);
  return JSON.parse(output.trim()) as { reason: string; released: boolean; remaining: number };
}

test('an exited backend releases its HTTP/1.1 listener and private directories', async () => {
  const result = await probeFailedStartup('http1');
  expect(result.reason).toBe('startup_failed');
  expect(result.released).toBe(true);
  expect(result.remaining).toBe(0);
}, 35_000);

test('an exited backend releases its HTTP/2 listener and private directories', async () => {
  const result = await probeFailedStartup('http2');
  expect(result.reason).toBe('startup_failed');
  expect(result.released).toBe(true);
  expect(result.remaining).toBe(0);
}, 35_000);

test('forwardRequestHeaders strips HTTP/2 pseudo-headers and promotes :authority to host', () => {
  const forwarded = forwardRequestHeaders({
    ':method': 'GET',
    ':scheme': 'https',
    ':authority': 'localhost:8443',
    ':path': '/index.html',
    'accept-encoding': 'gzip, deflate, br',
    cookie: 'session=abc',
  });
  expect(forwarded).toEqual({
    host: 'localhost:8443',
    'accept-encoding': 'gzip, deflate, br',
    cookie: 'session=abc',
  });

  const explicitHost = forwardRequestHeaders({
    ':authority': 'ignored:8443',
    host: 'explicit.local:8443',
  });
  expect(explicitHost).toEqual({ host: 'explicit.local:8443' });
});

test('forwardResponseHeaders drops hop-by-hop headers only for HTTP/2 responses', () => {
  const upstream = {
    'content-type': 'application/javascript',
    'content-encoding': 'br',
    connection: 'keep-alive, x-hop',
    'keep-alive': 'timeout=5',
    'transfer-encoding': 'chunked',
    'x-hop': 'strip-me',
    'cache-control': 'public, max-age=31536000, immutable',
  };
  expect(forwardResponseHeaders(upstream, false)).toEqual(upstream);
  expect(forwardResponseHeaders(upstream, true)).toEqual({
    'content-type': 'application/javascript',
    'content-encoding': 'br',
    'cache-control': 'public, max-age=31536000, immutable',
  });
});

test('resolveServerProtocol defaults to http1 and validates REAL_SERVER_PROTOCOL', () => {
  const previous = process.env.REAL_SERVER_PROTOCOL;
  try {
    delete process.env.REAL_SERVER_PROTOCOL;
    expect(resolveServerProtocol()).toBe('http1');
    expect(resolveServerProtocol('http2')).toBe('http2');
    process.env.REAL_SERVER_PROTOCOL = 'http2';
    expect(resolveServerProtocol()).toBe('http2');
    expect(resolveServerProtocol('http1')).toBe('http1');
    process.env.REAL_SERVER_PROTOCOL = 'http3';
    expect(() => resolveServerProtocol()).toThrow('REAL_SERVER_PROTOCOL');
  } finally {
    if (previous === undefined) delete process.env.REAL_SERVER_PROTOCOL;
    else process.env.REAL_SERVER_PROTOCOL = previous;
  }
});
