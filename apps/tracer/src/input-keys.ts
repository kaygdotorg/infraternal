/**
 * How many keys a chunk of typed input stands for (the connection indicator counts the ones kept while the link is down).
 * A control sequence (an arrow, a function key, a bracketed paste) is one key; text is one key per character.
 */
export function keysIn(data: string): number {
  return data.startsWith("\u001b") && data.length > 1 ? 1 : Math.max(1, [...data].length);
}
