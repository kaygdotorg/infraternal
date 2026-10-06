/** Crash/restart the actual server binary, retrieve its private CLI capability and complete
 * production-browser owner setup [24,26,40]. Secrets remain in process/pipe/browser memory.
 * Only this fixture's process groups and private worktree directory are created or removed.
 */
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { createServer } from 'node:net';
import { randomUUID } from 'node:crypto';
import { mkdir, rm, stat } from 'node:fs/promises';
import { resolve } from 'node:path';

const root = resolve(import.meta.dirname, '../..');
if (!process.argv[2]) throw new Error('provide the production tracer dist directory');
const dist = resolve(process.argv[2]);
const binary = resolve(root, 'target/debug/infraternal');
// Keep the pathname below Unix SUN_LEN while every file remains inside the worktree.
const relativeData = 'target/r-' + randomUUID();
const data = resolve(root, relativeData);
await mkdir(data, { recursive: true, mode: 0o700 });
const reservation = createServer();
await new Promise((accept) => reservation.listen(0, '127.0.0.1', accept));
const port = reservation.address().port;
await new Promise((accept) => reservation.close(accept));
const origin = `http://127.0.0.1:${port}`;
const check = (condition, message) => { if (!condition) throw new Error(message); };
const delay = () => new Promise((accept) => setTimeout(accept, 25));
let server;

async function start() {
  server = spawn(binary, ['server', '--data', relativeData, '--listen', `127.0.0.1:${port}`,
    '--public-origin', 'https://auth.example.test', '--behind-proxy', '--trusted-proxy', '127.0.0.1/32'],
  { cwd: root, detached: true, stdio: 'ignore' });
  server.on('error', () => {});
  for (let attempt = 0; attempt < 200; attempt++) {
    check(server.exitCode === null && server.signalCode === null, 'server exited during startup');
    try { if ((await fetch(origin + '/healthz')).ok) return; } catch { /* listener not ready */ }
    await delay();
  }
  throw new Error('server did not become healthy');
}
async function crash() {
  if (!server || server.exitCode !== null || server.signalCode !== null) return;
  const exited = once(server, 'exit');
  // The detached group belongs only to this server and its embedded infraternal agent.
  process.kill(-server.pid, 'SIGKILL');
  await exited;
  server = undefined;
}
async function cliToken() {
  const cli = spawn(binary, ['server', 'setup-token', '--data', relativeData],
    { cwd: root, stdio: ['ignore', 'pipe', 'ignore'] });
  let output = '';
  cli.stdout.on('data', (bytes) => { output += bytes; });
  const [code] = await once(cli, 'exit');
  return { code, token: output.trim() };
}
async function post(action, body) {
  const result = await fetch(origin + '/auth/' + action, { method: 'POST',
    headers: { Origin: 'https://auth.example.test', 'Content-Type': 'application/json' },
    body: JSON.stringify(body) });
  let value;
  try { value = await result.json(); } catch { throw new Error('unreadable server response'); }
  return { status: result.status, value };
}
try {
  await start();
  const first = await cliToken();
  check(first.code === 0 && /^[A-Za-z0-9_-]{43}$/.test(first.token), 'initial CLI capability missing');
  check(((await stat(resolve(data, 'setup-token.sock'))).mode & 0o777) === 0o600, 'control socket is not private');
  await crash();
  check((await stat(resolve(data, 'setup-token.sock'))).isSocket(), 'crash did not leave the stale socket fixture');
  await start();
  const next = await cliToken();
  check(next.code === 0 && next.token !== first.token, 'restart did not rotate the CLI capability');
  check((await post('setup-start', { token: first.token, name: 'old capability' })).status === 401, 'older setup capability survived restart');
  const ui = spawn(process.execPath, [resolve(root, 'scripts/browser-auth/check-tracer.mjs'), dist],
    { cwd: root, env: { ...process.env, TRACER_AUTH_URL: origin }, stdio: ['pipe', 'pipe', 'pipe'] });
  // The only capability transfer to the production-browser fixture is this private pipe.
  ui.stdin.end(JSON.stringify({ setup_token: next.token }) + '\n');
  let result = '';
  ui.stdout.on('data', (bytes) => { result += bytes; });
  ui.stderr.resume();
  const [code] = await once(ui, 'exit');
  check(code === 0 && result.includes('tracer + Rust auth: PASS'), 'production browser setup/sign-in failed');
  check((await post('setup-start', { token: next.token, name: 'spent capability' })).status === 401, 'completed setup capability was reusable');
  check((await post('status', {})).value.setup_required === false, 'completed setup still required');
  await crash();
  await start();
  check((await post('status', {})).value.setup_required === false, 'owner disappeared after restart');
  check((await cliToken()).code !== 0, 'owner restart minted a new setup capability');
  console.log('server process restart: PASS (SIGKILL, stale socket, fresh CLI token, old/spent token denial, production resident setup/sign-in, owner persists without token)');
} finally {
  await crash();
  await rm(data, { recursive: true });
}
