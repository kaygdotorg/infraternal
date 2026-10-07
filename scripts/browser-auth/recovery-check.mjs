/** Exercises production recovery crypto in native Chromium against the Rust verifier and SQLite [D113,40]. */
import { chromium } from 'playwright';
import { spawn } from 'node:child_process';
import { createInterface } from 'node:readline';
import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';

const root = resolve(import.meta.dirname, '../..');
const browser = await chromium.launch({ headless: true });
try {
  for (const live of [true, false]) {
    const child = spawn(resolve(root, 'target/debug/examples/browser_auth'), [], { stdio: ['pipe', 'pipe', 'inherit'] });
    const lines = createInterface({ input: child.stdout })[Symbol.asyncIterator]();
    const initial = JSON.parse((await lines.next()).value);
    const context = await browser.newContext();
    try {
      const page = await context.newPage();
      const cdp = await context.newCDPSession(page);
      await cdp.send('WebAuthn.enable');
      const authenticatorOptions = {
        protocol: 'ctap2', ctap2Version: 'ctap2_1', transport: 'internal',
        hasResidentKey: true, hasUserVerification: true, isUserVerified: true,
        automaticPresenceSimulation: true, hasPrf: true,
      };
      const { authenticatorId } = await cdp.send('WebAuthn.addVirtualAuthenticator', { options: authenticatorOptions });
      await page.route('https://auth.example.test/**', async route => {
        const request = route.request();
        if (request.method() === 'GET') {
          await route.fulfill({ contentType: 'text/html', body: '<!doctype html><title>Native recovery verification</title>' });
          return;
        }
        child.stdin.write(JSON.stringify({ path: new URL(request.url()).pathname, headers: request.headers(), body: request.postDataJSON() }) + '\n');
        const response = JSON.parse((await lines.next()).value);
        await route.fulfill({ status: response.status, headers: Object.fromEntries(response.headers), body: JSON.stringify(response.body) });
      });
      await page.goto('https://auth.example.test/');
      await page.addScriptTag({ content: await readFile(resolve(root, 'target/auth-rework/recovery.js'), 'utf8') });
      await page.evaluate(async token => {
        const api = globalThis.recoveryBrowser;
        globalThis.recoveryUser = await api.registerOwner(token, 'recovery_owner', 'Recovery owner', async (words, finish) => {
          globalThis.recoveryWords = words;
          await finish();
        });
        const wraps = await api.recoveryAuth.post('wraps', {});
        const entropy = api.entropy(globalThis.recoveryWords);
        globalThis.originalDek = await api.recoveryAuth.unwrapRecoveryDek(globalThis.recoveryWords, wraps.find(w => w.kind === 'recovery').wrap, globalThis.recoveryUser, 2);
        entropy.fill(0);
      }, initial.setup_token);
      if (!live) await context.clearCookies();
      await page.evaluate(async live => {
        const api = globalThis.recoveryBrowser;
        globalThis.recoveryRequest = await api.startRecovery('recovery_owner', globalThis.recoveryWords);
        if (globalThis.recoveryRequest.delay_seconds !== (live ? 0 : 86400)) throw new Error('incorrect session-dependent recovery delay');
        if (!live) {
          let denied = false;
          try { await api.replacePasskey(globalThis.recoveryRequest.token, globalThis.recoveryWords, async () => {}); }
          catch (error) { denied = error.status === 401; }
          if (!denied) throw new Error('recovery bypassed 24-hour delay');
          // Only the private fixture advances stored ready time; production has no such route.
          const response = await fetch('/__test/recovery-elapse', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' });
          if (!response.ok) throw new Error('fixture could not advance recovery time');
        }
      }, live);
      // Model the replacement authenticator: the old credential remains excluded on the server.
      await cdp.send('WebAuthn.removeVirtualAuthenticator', { authenticatorId });
      await cdp.send('WebAuthn.addVirtualAuthenticator', { options: authenticatorOptions });
      await page.evaluate(async () => {
        const api = globalThis.recoveryBrowser;
        const recovered = await api.replacePasskey(globalThis.recoveryRequest.token, globalThis.recoveryWords, async (words, finish) => {
          globalThis.nextRecoveryWords = words;
          await finish();
        });
        if (recovered.userId !== globalThis.recoveryUser) throw new Error('replacement changed account');
        const wraps = await api.recoveryAuth.post('wraps', {});
        const entropy = api.entropy(globalThis.nextRecoveryWords);
        const dek = await api.recoveryAuth.unwrapRecoveryDek(globalThis.nextRecoveryWords, wraps.find(w => w.kind === 'recovery').wrap, globalThis.recoveryUser, 2);
        if (!dek.every((value, i) => value === globalThis.originalDek[i])) throw new Error('replacement changed original DEK');
        entropy.fill(0); dek.fill(0); globalThis.originalDek.fill(0);
        const replay = await fetch('/auth/recovery-ready', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ token: globalThis.recoveryRequest.token }) });
        if (replay.status !== 401) throw new Error('consumed recovery capability survived');
        if (await api.loginWithPasskey('Recovered native browser') !== globalThis.recoveryUser) throw new Error('new passkey login failed');
        globalThis.recoveryWords = globalThis.nextRecoveryWords = '';
      });
      console.log(`native recovery ${live ? 'same-account live session' : 'no session, enforced delay then elapsed'}: PASS (original DEK preserved, capability consumed, replacement passkey signs in)`);
    } finally {
      await context.close(); child.stdin.end();
      await new Promise(resolve => child.on('exit', resolve));
    }
  }
  console.log(`native recovery: PASS (2 real-verifier scenarios; Chromium ${browser.version()})`);
} finally { await browser.close(); }
