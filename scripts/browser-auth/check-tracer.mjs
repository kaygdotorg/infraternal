/** Production tracer passkey UI against the real Rust auth router over private IPC [23,24,40].
 * The supplied dist directory is read-only. Capabilities/recovery words remain in pipe/browser
 * memory; no network trace, arbitrary screenshot, body logging or secret argv is produced.
 * TRACER_BROWSER_AUTH_BIN selects a prebuilt fixture binary, keeping temporary Rust targets
 * outside the source worktree when a job supplies its own scratch target directory.
 */
import { chromium } from 'playwright';
import { spawn } from 'node:child_process';
import { createInterface } from 'node:readline';
import { readFile } from 'node:fs/promises';
import { resolve, extname, sep } from 'node:path';

const root = resolve(import.meta.dirname, '../..');
if (!process.argv[2]) throw new Error('provide the production tracer dist directory');
const dist = resolve(process.argv[2]);
const browser = await chromium.launch({ headless: true });
// An optional loopback reverse-proxy fixture receives its setup capability only
// through private stdin. The default fixture keeps both capability and API in IPC.
const transport = process.env.TRACER_AUTH_URL ? new URL(process.env.TRACER_AUTH_URL) : undefined;
if (transport && (transport.protocol !== 'http:' || transport.hostname !== '127.0.0.1'
    || transport.pathname !== '/' || transport.username || transport.password || transport.search || transport.hash)) {
  throw new Error('HTTP auth fixture must be an uncredentialed loopback origin');
}
const binary = process.env.TRACER_BROWSER_AUTH_BIN ?? resolve(root, 'target/debug/examples/browser_auth');
const child = transport ? undefined : spawn(binary, [], {
  stdio: ['pipe', 'pipe', 'inherit'],
});
const lines = createInterface({ input: child ? child.stdout : process.stdin })[Symbol.asyncIterator]();
const initial = JSON.parse((await lines.next()).value);
const context = await browser.newContext();
const check = (condition, message) => { if (!condition) throw new Error(message); };
try {
  const page = await context.newPage();
  const cdp = await context.newCDPSession(page);
  await cdp.send('WebAuthn.enable');
  await cdp.send('WebAuthn.addVirtualAuthenticator', { options: {
    protocol: 'ctap2', ctap2Version: 'ctap2_1', transport: 'internal',
    hasResidentKey: true, hasUserVerification: true, isUserVerified: true,
    automaticPresenceSimulation: true, hasPrf: true,
  } });
  await page.route('https://auth.example.test/**', async (route) => {
    const request = route.request();
    if (request.method() === 'GET') {
      const pathname = new URL(request.url()).pathname;
      const path = resolve(dist, pathname === '/' ? 'index.html' : pathname.slice(1));
      if (!path.startsWith(dist + sep)) throw new Error('asset path escaped dist');
      const types = { '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css',
        '.woff2': 'font/woff2', '.wasm': 'application/wasm' };
      await route.fulfill({ contentType: types[extname(path)] ?? 'application/octet-stream', body: await readFile(path) });
      return;
    }
    const path = new URL(request.url()).pathname;
    let response;
    if (transport) {
      const result = await fetch(new URL(path, transport), { method: 'POST',
        headers: request.headers(), body: request.postData() });
      let body;
      try { body = await result.json(); } catch { throw new Error('unreadable auth fixture response'); }
      response = { status: result.status, headers: [...result.headers], body };
    } else {
      child.stdin.write(JSON.stringify({ path, headers: request.headers(), body: request.postDataJSON() }) + '\n');
      response = JSON.parse((await lines.next()).value);
    }
    await route.fulfill({ status: response.status, headers: Object.fromEntries(response.headers),
      body: JSON.stringify(response.body) });
  });
  // This fixture verifies auth only. Close terminal sockets locally rather than dialing a host.
  await page.routeWebSocket('**/v1/ws*', (socket) => socket.close({ code: 1000, reason: 'auth-only fixture' }));
  await page.goto('https://auth.example.test/');
  await page.locator('#setup-card').waitFor();
  check(await page.locator('#login-passkey').count() === 0, 'unconfigured server showed login');
  await page.locator('#setup-token').fill(initial.setup_token);
  await page.getByRole('button', { name: 'Continue' }).click();
  await page.locator('#setup-username').fill('production_integration');
  await page.locator('#setup-display-name').fill('Production integration');
  await page.getByRole('button', { name: 'Continue' }).click();
  await page.getByRole('button', { name: 'Create passkey' }).click();
  await page.getByRole('heading', { name: 'Save your recovery key' }).waitFor();
  check(await page.locator('#recovery-words li').count() === 24, 'recovery display shape');
  await page.locator('.auth-check').click();
  await page.getByRole('button', { name: 'Open infraternal' }).click();
  await page.locator('#terminal-host').waitFor();
  const enrolledSession = await page.evaluate(async () => (await fetch('/auth/session', {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}',
  })).json());
  check(enrolledSession.username === 'production_integration'
    && enrolledSession.display_name === 'Production integration', 'session labels absent after enrollment');
  await context.clearCookies();
  await page.evaluate(() => localStorage.clear());
  await page.reload();
  await page.locator('#login-passkey').waitFor();
  check(await page.locator('#setup-card, #account-id, #device-name').count() === 0, 'configured server showed setup or identity fields');
  await page.getByRole('button', { name: 'Continue with passkey' }).click();
  await page.locator('#terminal-host').waitFor();
  const status = await page.evaluate(async () => {
    const post = async (action) => (await fetch('/auth/' + action, {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}',
    })).json();
    return { status: await post('status'), session: await post('session') };
  });
  check(status.status.setup_required === false && typeof status.session.user_id === 'string', 'authenticated resident session absent');
  console.log(`tracer + Rust auth: PASS (production UI, resident PRF setup, empty-storage discoverable login, DEK unwrap; Chromium ${browser.version()})`);
} finally {
  await context.close();
  child?.stdin.end();
  child?.kill();
  await browser.close();
}
