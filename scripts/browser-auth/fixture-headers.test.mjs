/** Unit checks for `fulfillHeaders`: a repeated Set-Cookie must survive, as must ordinary headers [#447]. */
import { expect, test } from 'bun:test';
import { fulfillHeaders } from './fixture-headers.mjs';

test('keeps both cookies of a sign-in that replaces the session', () => {
  const headers = fulfillHeaders([
    ['content-type', 'application/json'],
    ['set-cookie', '__Host-infraternal-session-2-9=new; Secure'],
    ['set-cookie', '__Host-infraternal-session-1-9=; Max-Age=0; Secure'],
  ]);
  expect(headers['set-cookie'].split('\n')).toEqual([
    '__Host-infraternal-session-2-9=new; Secure',
    '__Host-infraternal-session-1-9=; Max-Age=0; Secure',
  ]);
  expect(headers['content-type']).toBe('application/json');
});

test('joins other repeated headers with a comma and keeps single ones as they are', () => {
  expect(fulfillHeaders([['Vary', 'Cookie'], ['vary', 'Origin'], ['x-one', '1']])).toEqual({ vary: 'Cookie, Origin', 'x-one': '1' });
  expect(fulfillHeaders([])).toEqual({});
});
