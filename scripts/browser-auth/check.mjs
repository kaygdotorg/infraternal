/** Real Chromium WebAuthn/PRF and WebCrypto against the Rust HTTP router [23,24,40]. */
import { chromium } from 'playwright';
import { spawn } from 'node:child_process';
import { createInterface } from 'node:readline';
import { resolve } from 'node:path';
import { readFile } from 'node:fs/promises';
import { routeWithLatency } from './latency-route.mjs';

const root = resolve(import.meta.dirname, '../..');
const targetRoot = process.env.CARGO_TARGET_DIR ?? resolve(root, 'target');
const browser = await chromium.launch({ headless: true });
let checks = 0;
try {
  // Each scenario owns an isolated in-memory database and authenticator.
  for (const mode of ['supported', 'unsupported-prf', 'nonresident', 'no-uv']) {
    const child = spawn(resolve(targetRoot, 'debug/examples/browser_auth'), [], { stdio: ['pipe', 'pipe', 'inherit'] });
    const lines = createInterface({ input: child.stdout })[Symbol.asyncIterator]();
    const initial = JSON.parse((await lines.next()).value);
    const context = await browser.newContext();
    try {
      const page = await context.newPage();
      const cdp = await context.newCDPSession(page);
      await cdp.send('WebAuthn.enable');
      const { authenticatorId } = await cdp.send('WebAuthn.addVirtualAuthenticator', {
        options: { protocol: 'ctap2', ctap2Version: 'ctap2_1', transport: 'internal',
          hasResidentKey: mode !== 'nonresident', hasUserVerification: true,
          isUserVerified: mode !== 'no-uv', automaticPresenceSimulation: true,
          hasPrf: mode !== 'unsupported-prf' }
      });
      await routeWithLatency(page, 'https://auth.example.test/**', async (route) => {
        const request = route.request();
        if (request.method() === 'GET') {
          await route.fulfill({ contentType: 'text/html', body: '<!doctype html><title>Auth browser verification</title>' });
          return;
        }
        child.stdin.write(JSON.stringify({ path: new URL(request.url()).pathname, headers: request.headers(), body: request.postDataJSON() }) + '\n');
        const response = JSON.parse((await lines.next()).value);
        await route.fulfill({ status: response.status, headers: Object.fromEntries(response.headers), body: JSON.stringify(response.body) });
      });
      await page.goto('https://auth.example.test/');
      await page.addScriptTag({ content: await readFile(resolve(targetRoot, 'auth-rework/entropy.js'), 'utf8') });
      const result = await page.evaluate(async ({ mode, token }) => {
        const check = (condition, name) => { if (!condition) throw new Error(name); };
        const enc = new TextEncoder();
        const decode = (s) => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));
        const encode = (b) => btoa(String.fromCharCode(...new Uint8Array(b))).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
        const post = async (action, body) => {
          const response = await fetch('/auth/' + action, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
          return { status: response.status, body: await response.json() };
        };
        const options = (start, registration) => {
          const p = structuredClone(start.options.publicKey);
          p.challenge = decode(p.challenge);
          if (registration) p.user.id = decode(p.user.id);
          for (const field of ['allowCredentials', 'excludeCredentials']) {
            if (p[field]) p[field] = p[field].map(c => ({ ...c, id: decode(c.id) }));
          }
          if (p.extensions?.prf) p.extensions.prf.eval.first = decode(p.extensions.prf.eval.first);
          return p;
        };
        const proof = (credential) => {
          const response = {};
          for (const field of ['clientDataJSON', 'attestationObject', 'authenticatorData', 'signature', 'userHandle']) {
            if (field in credential.response) response[field] = credential.response[field] === null ? null : encode(credential.response[field]);
          }
          // PRF output remains in browser memory. Only non-secret hints are submitted.
          const extensions = credential.getClientExtensionResults();
          delete extensions.prf;
          return { id: credential.id, rawId: encode(credential.rawId), type: credential.type, response, extensions };
        };
        check(JSON.stringify((await post('status', {})).body) === JSON.stringify({setup_required:true}), 'initial public status');
        const start = await post('setup-start', { token, username: 'browser_owner', display_name: 'Browser owner' });
        check(start.status === 200, 'setup options');
        let credential;
        try {
          credential = await navigator.credentials.create({ publicKey: options(start.body, true) });
        } catch {
          check(mode === 'nonresident' || mode === 'no-uv', 'unexpected registration failure');
          // Failed ceremonies never consume the setup authority or create an owner.
          check((await post('setup-start', { token, name: 'retry' })).status === 200, 'failed create consumed setup');
          return mode + ': browser refused registration; owner not created';
        }
        const extension = credential.getClientExtensionResults();
        if (mode === 'unsupported-prf') {
          check(extension.prf?.enabled !== true, 'unsupported PRF accepted');
          check((await post('setup-start', { token, name: 'retry' })).status === 200, 'unsupported PRF created owner');
          return 'unsupported-prf: abort before finish; owner not created';
        }
        check(mode === 'supported', 'required residence/UV bypassed');
        check(extension.prf?.enabled === true, 'PRF not enabled');
        check(extension.credProps?.rk === true, 'credential not resident');
        // Creation commonly omits results. Exercise fallback get even if it returns them.
        const registrationOptions = options(start.body, true);
        const get = await navigator.credentials.get({ publicKey: {
          challenge: registrationOptions.challenge, rpId: registrationOptions.rp.id,
          allowCredentials: [{ type: 'public-key', id: credential.rawId }], userVerification: 'required',
          extensions: { prf: registrationOptions.extensions.prf }
        } });
        const prf = get.getClientExtensionResults().prf?.results?.first;
        check(prf?.byteLength === 32, 'fallback get missing PRF');
        const user = start.body.user_id;
        const dek = crypto.getRandomValues(new Uint8Array(32));
        const aad = enc.encode('infraternal/keywrap/v1|' + user + '|passkey');
        const salt = crypto.getRandomValues(new Uint8Array(32));
        const nonce = crypto.getRandomValues(new Uint8Array(12));
        const derive = async (ikm) => crypto.subtle.deriveKey({ name: 'HKDF', hash: 'SHA-256', salt, info: aad },
          await crypto.subtle.importKey('raw', ikm, 'HKDF', false, ['deriveKey']), { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
        const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce, additionalData: aad }, await derive(prf), dek);
        const wrap = { salt: encode(salt), nonce: encode(nonce), ciphertext: encode(ciphertext) };
        const recoveryEntropy = crypto.getRandomValues(new Uint8Array(32));
        const recoveryMaterial = await crypto.subtle.importKey('raw', recoveryEntropy, 'HKDF', false, ['deriveBits']);
        const recoveryDerive = async kind => crypto.subtle.deriveBits({ name:'HKDF', hash:'SHA-256', salt:new ArrayBuffer(0), info:enc.encode('infraternal/recovery/'+kind+'/v2') }, recoveryMaterial, 256);
        const recoveryVerifier = encode(await recoveryDerive('auth'));
        const recoveryIkm = await recoveryDerive('wrap');
        const recoveryAad = enc.encode('infraternal/keywrap/v1|' + user + '|recovery');
        const recoverySalt = crypto.getRandomValues(new Uint8Array(32));
        const recoveryNonce = crypto.getRandomValues(new Uint8Array(12));
        const recoveryKey = await crypto.subtle.deriveKey({ name: 'HKDF', hash: 'SHA-256', salt: recoverySalt, info: recoveryAad },
          await crypto.subtle.importKey('raw', recoveryIkm, 'HKDF', false, ['deriveKey']),
          { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
        const recoveryCiphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: recoveryNonce, additionalData: recoveryAad }, recoveryKey, dek);
        const recoveryWrap = { salt: encode(recoverySalt), nonce: encode(recoveryNonce), ciphertext: encode(recoveryCiphertext) };
        const finish = await post('registration-finish', { ceremony: start.body.ceremony, proof: proof(credential), passkey_wrap: wrap, recovery_wrap: recoveryWrap, recovery_verifier: recoveryVerifier });
        check(finish.status === 200, 'registration finish');
        check(JSON.stringify((await post('status', {})).body) === JSON.stringify({setup_required:false}), 'completed public status');
        check((await post('wraps', {})).status === 200, 'secure cookie unavailable');
        const login = await post('login-start', {});
        check(login.status === 200, 'login options');
        const assertion = await navigator.credentials.get({ publicKey: options(login.body, false) });
        const logged = await post('login-finish', { ceremony: login.body.ceremony, proof: proof(assertion), device: 'Chromium virtual passkey' });
        check(logged.status === 200, 'login finish');
        check(login.body.options.publicKey.allowCredentials.length === 0, 'discoverable allow-list not empty');
        check((await post('session', {})).status === 401, 'pending unlock granted authority');
        check((await post('unlock-session', {})).body.user_id === user, 'resident handle resolved wrong user');
        const entry = (await post('wraps', {})).body.find(w => w.kind === 'passkey');
        const local = await navigator.credentials.get({ publicKey: {
          challenge: crypto.getRandomValues(new Uint8Array(32)), rpId: 'auth.example.test',
          allowCredentials: [{ type: 'public-key', id: assertion.rawId }], userVerification: 'required',
          extensions: { prf: { eval: { first: decode(entry.prf_input) } } }
        } });
        const loginPrf = local.getClientExtensionResults().prf?.results?.first;
        check(loginPrf?.byteLength === 32, 'authenticated PRF unavailable');
        const stored = entry.wrap;
        const clear = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: decode(stored.nonce), additionalData: aad }, await derive(loginPrf), decode(stored.ciphertext));
        check(encode(clear) === encode(dek), 'DEK changed across login');
        check((await post('unlock-finish', { pending_transaction: logged.body.pending_transaction })).status === 200, 'unlock completion rejected');
        // A real browser response with a tampered origin/UV must fail server verification.
        const wrongOrigin = await post('login-start', {});
        const fresh = await navigator.credentials.get({ publicKey: options(wrongOrigin.body, false) });
        const bad = proof(fresh);
        const client = JSON.parse(new TextDecoder().decode(decode(bad.response.clientDataJSON)));
        client.origin = 'https://evil.example.test';
        bad.response.clientDataJSON = encode(enc.encode(JSON.stringify(client)));
        check((await post('login-finish', { ceremony: wrongOrigin.body.ceremony, proof: bad, device: 'tampered' })).status === 401, 'wrong origin accepted');
        globalThis.authCredentialId = credential.id;
        globalThis.authHandle = start.body.options.publicKey.user.id;
        return 'supported: discoverable resident UV passkey, PRF fallback get, stripped proofs, native HKDF/AES-GCM, login DEK roundtrip, wrong origin rejected';
      }, { mode, token: initial.setup_token });
      if (mode === 'supported') {
        await cdp.send('WebAuthn.setUserVerified', { authenticatorId, isUserVerified: false });
        await page.evaluate(async () => {
          const decode = s => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));
          const encode = b => btoa(String.fromCharCode(...new Uint8Array(b))).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
          const post = async (action, body) => fetch('/auth/' + action, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
          const start = await (await post('login-start', {})).json();
          const p = start.options.publicKey;
          p.challenge = decode(p.challenge);
          // A hostile client may add a known credential allow-list to obtain a non-UV
          // assertion; the server must retain its original discoverable UV policy.
          p.allowCredentials = [{type: 'public-key', id: decode(globalThis.authCredentialId)}];
          delete p.extensions;
          // The client weakens the request but the server's stored UV policy remains required.
          p.userVerification = 'discouraged';
          const credential = await navigator.credentials.get({ publicKey: p });
          const r = credential.response;
          const proof = { id: credential.id, rawId: encode(credential.rawId), type: 'public-key', extensions: {},
            response: { clientDataJSON: encode(r.clientDataJSON), authenticatorData: encode(r.authenticatorData), signature: encode(r.signature), userHandle: globalThis.authHandle } };
          if ((await post('login-finish', { ceremony: start.ceremony, proof, device: 'UV bypass' })).status !== 401) throw new Error('server accepted browser assertion without UV');
        });
        console.log('supported: server rejected native browser assertion without UV');
      }
      console.log(result);
      checks++;
    } finally {
      await context.close();
      child.stdin.end();
      await new Promise(resolve => child.on('exit', resolve));
    }
  }
  console.log(`auth browser: PASS (${checks} isolated scenarios; Chromium ${browser.version()})`);
} finally {
  await browser.close();
}
