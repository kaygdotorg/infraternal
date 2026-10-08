/** Independent checks of production browser crypto using public fixture entropy. */
import { test, expect } from 'bun:test';
import { hkdfSync } from 'node:crypto';
import { recoveryAuth as auth } from '../src/auth';
const words = Array(23).fill('abandon').concat('art').join(' ');
const user = '00000000-0000-0000-0000-000000000001';
const other = '00000000-0000-0000-0000-000000000002';
test('HKDF siblings match independent implementation and bind unwrap to domain, account, kind and version', async () => {
  const derived = await auth.recoverySecrets(words);
  const expectedAuth = Buffer.from(hkdfSync('sha256', new Uint8Array(32), new Uint8Array(0), 'infraternal/recovery/auth/v2', 32));
  const expectedWrap = Buffer.from(hkdfSync('sha256', new Uint8Array(32), new Uint8Array(0), 'infraternal/recovery/wrap/v2', 32));
  expect(derived.verifier === expectedAuth.toString('base64url')).toBe(true);
  expect(Buffer.from(derived.wrap).equals(expectedWrap)).toBe(true);
  expect(expectedAuth.equals(expectedWrap)).toBe(false);
  const dek = new Uint8Array(32).fill(9);
  const wrap = await auth.wrapDek(derived.wrap, dek, user, 'recovery');
  expect(Buffer.from(await auth.unwrapRecoveryDek(words, wrap, user, 2)).equals(Buffer.from(dek))).toBe(true);
  for (const action of [
    () => auth.unwrapDek(expectedAuth, wrap, user, 'recovery'),
    () => auth.unwrapDek(derived.wrap, wrap, other, 'recovery'),
    () => auth.unwrapDek(derived.wrap, wrap, user, 'passkey'),
    () => auth.unwrapRecoveryDek(words, wrap, user, 1),
    () => auth.unwrapRecoveryDek(words, wrap, user, 3),
    () => auth.unwrapDek(derived.wrap, {...wrap, ciphertext: Buffer.alloc(48).toString('base64url')}, user, 'recovery'),
  ]) {
    let rejected = false;
    try { await action(); } catch { rejected = true; }
    expect(rejected).toBe(true);
  }
  derived.wrap.fill(0);
});
test('100 repeated wrapping operations generate independent salts and nonces', async () => {
  const derived = await auth.recoverySecrets(words);
  const salts = new Set<string>(), nonces = new Set<string>();
  for (let n = 0; n < 100; n++) {
    const wrap = await auth.wrapDek(derived.wrap, new Uint8Array(32), user, 'recovery');
    salts.add(wrap.salt); nonces.add(wrap.nonce);
    expect(Buffer.from(wrap.salt, 'base64url').length).toBe(32);
    expect(Buffer.from(wrap.nonce, 'base64url').length).toBe(12);
    expect(Buffer.from(wrap.ciphertext, 'base64url').length).toBe(48);
  }
  expect(salts.size).toBe(100); expect(nonces.size).toBe(100);
  derived.wrap.fill(0);
});
