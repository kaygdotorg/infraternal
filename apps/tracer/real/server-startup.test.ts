/** Role: prove a failed private server startup releases its listener and scratch state (#146). */
import { expect, test } from 'bun:test';
import { resolve } from 'node:path';

// The worker exits after reporting the probe, so even the failing baseline
// cannot leave its TLS listener running in the test process.
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
try{fixture=await startRealServer({port,address:'127.0.0.1',stateRoot:root});}
catch(e){reason=e.message==='server startup failed'?'startup_failed':'other';}
const probe=createServer();
const released=await new Promise(r=>{probe.once('error',()=>r(false));probe.listen(port,'127.0.0.1',()=>probe.close(()=>r(true)));});
const remaining=(await readdir(root)).length;
await fixture?.dispose();
await unlink(alias);await rm(root,{recursive:true,force:true});await rm(dist,{recursive:true,force:true});
console.log(JSON.stringify({reason,released,remaining}));
process.exit(0);
`;

test('an exited backend releases its listener and private directories', async () => {
  const child = Bun.spawn([process.execPath, '--eval', worker], {
    cwd: resolve(import.meta.dirname, '../../..'),
    stdout: 'pipe', stderr: 'ignore',
  });
  const deadline = setTimeout(() => child.kill(), 30_000);
  let code: number; let output: string;
  try { [code, output] = await Promise.all([child.exited, new Response(child.stdout).text()]); }
  finally { clearTimeout(deadline); if (child.exitCode === null) child.kill(); }
  expect(code).toBe(0);
  const result = JSON.parse(output.trim()) as { reason: string; released: boolean; remaining: number };
  expect(result.reason).toBe('startup_failed');
  expect(result.released).toBe(true);
  expect(result.remaining).toBe(0);
}, 35_000);
