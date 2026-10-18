/** Checks canonical wire identities before they can select a host or retained terminal, and mints new ones. */
export const isCanonicalUuid = (value: unknown): value is string => typeof value === "string" && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(value);

/**
 * A random version-4 UUID that works on every origin. Browsers expose `crypto.randomUUID` only in secure contexts
 * (HTTPS or localhost), so a server reached over plain http on a LAN address would throw on the first window it
 * opened. `crypto.getRandomValues` is available everywhere and gives the same 122 random bits.
 */
export function randomUuid(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  bytes[6] = (bytes[6]! & 0x0f) | 0x40;
  bytes[8] = (bytes[8]! & 0x3f) | 0x80;
  const hex = Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}
