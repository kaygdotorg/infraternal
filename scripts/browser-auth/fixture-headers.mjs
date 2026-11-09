/** Header handling shared by the auth checks' Playwright proxies to the `browser_auth` fixture [#447]. */

/**
 * Turns the auth fixture's response headers into the object Playwright's `route.fulfill()` takes, keeping every
 * `Set-Cookie`.
 *
 * The `browser_auth` example returns headers as `[name, value]` pairs, and a name can repeat: since sessions got
 * per-login cookie names, a sign-in answers with two `Set-Cookie` headers, the new `__Host-infraternal-session-2-…`
 * and an expiry for the old one. `Object.fromEntries(pairs)` keeps only the last value of a repeated name, so the
 * browser received only the expiry, lost its session, and the next request was refused with 401 (the auth checks
 * then failed with "The request could not be accepted" or "resident handle resolved wrong user").
 *
 * Playwright splits a fulfilled `set-cookie` value on newlines into separate headers, so those values are joined
 * with `\n`; other repeated headers are joined with `, `, as HTTP allows.
 *
 * @param {Array<[string, string]>} pairs the fixture's headers, in order
 * @returns {Record<string, string>} headers for `route.fulfill({ headers })`
 */
export function fulfillHeaders(pairs) {
  const headers = {};
  for (const [name, value] of pairs) {
    const key = name.toLowerCase();
    const separator = key === 'set-cookie' ? '\n' : ', ';
    headers[key] = key in headers ? `${headers[key]}${separator}${value}` : value;
  }
  return headers;
}
