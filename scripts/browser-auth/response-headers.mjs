/** Preserve native response headers when the pipe fixture fulfills a browser request. */

/**
 * Convert native `[name, value]` rows into the header object accepted by `route.fulfill`.
 * Newline framing keeps cookie publication and retirement distinct; other repeated fields use commas.
 */
export function responseHeaders(rows) {
  // Header names remain data, including names that match object prototype properties.
  const grouped = new Map();
  for (const [name, value] of rows) {
    const key = name.toLowerCase();
    const values = grouped.get(key);
    if (values) values.push(value);
    else grouped.set(key, [value]);
  }
  return Object.fromEntries([...grouped].map(([name, values]) => [
    name, values.join(name === 'set-cookie' ? '\n' : ', '),
  ]));
}
