/** Check repeated cookie framing before browser-auth fixtures forward native replies. */
import { expect, test } from 'bun:test';
import { responseHeaders } from './response-headers.mjs';

/** A fresh cookie and an expired predecessor must both reach the browser, in order. */
test('keeps repeated cookie rows without splitting an Expires date', () => {
  const rows = [
    ['set-cookie', 'current=public-fixture; Expires=Wed, 18 Nov 2026 14:00:00 GMT; Secure; Path=/'],
    ['Set-Cookie', 'previous=; Max-Age=0; Secure; Path=/'],
  ];
  expect(Object.fromEntries(rows.map(([name, value]) => [name.toLowerCase(), value]))['set-cookie'])
    .toBe(rows[1][1]);
  expect(responseHeaders(rows)['set-cookie']).toBe(rows.map(([, value]) => value).join('\n'));
});

/** Ordinary repeated headers retain their values and literal header names stay harmless. */
test('combines ordinary fields and preserves literal property names', () => {
  const headers = responseHeaders([
    ['Content-Type', 'application/json'], ['Vary', 'Origin'], ['vary', 'Cookie'],
    ['__proto__', 'public-fixture'],
  ]);
  expect(headers['content-type']).toBe('application/json');
  expect(headers.vary).toBe('Origin, Cookie');
  expect(Object.hasOwn(headers, '__proto__')).toBe(true);
  expect(Object.getPrototypeOf(headers)).toBe(Object.prototype);
});
