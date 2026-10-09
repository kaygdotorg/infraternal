/**
 * Browser-local preferences (theme, font, background): small string values that survive a
 * reload on this device. Storage can be missing or throw (private mode, blocked site data), so
 * every access is guarded and the product keeps working without it: a failed read is "nothing
 * saved" and a failed write is dropped.
 */

export function readLocal(key: string): string | null {
  try { return localStorage.getItem(key); } catch { return null; }
}

export function writeLocal(key: string, value: string): void {
  try { localStorage.setItem(key, value); } catch { /* preferences are optional in private mode */ }
}
