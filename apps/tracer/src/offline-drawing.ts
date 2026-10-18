/** Cache public drawing identity and already-used static assets; authority always comes from the server (D245). */
import { canvasKey, drawingIdentityKey, lastAccountKey, readStoredJson, writeStoredJson } from "./account-storage";
import { isCanonicalUuid } from "./identifiers";
import { whenIdle } from "./on-demand";
export interface DrawingIdentity { user_id: string; username?: string; display_name?: string; hostname?: unknown; recovery_pending?: { ready_at: number } | null }

export function cachedDrawingIdentity(): DrawingIdentity | undefined {
  try {
    const account = localStorage.getItem(lastAccountKey);
    if (!isCanonicalUuid(account) || !localStorage.getItem(canvasKey(account))) return undefined;
    const value = readStoredJson(drawingIdentityKey(account));
    if (!value || typeof value !== "object") return undefined;
    const row = value as Record<string, unknown>;
    if (row.user_id !== account || typeof row.hostname !== "string" || !row.hostname.trim() || row.hostname.length > 200) return undefined;
    return { user_id: account, hostname: row.hostname, ...(typeof row.username === "string" ? { username: row.username } : {}), ...(typeof row.display_name === "string" ? { display_name: row.display_name } : {}) };
  } catch { return undefined; }
}

export function cacheDrawingIdentity(identity: DrawingIdentity): void {
  if (!isCanonicalUuid(identity.user_id) || typeof identity.hostname !== "string") return;
  try {
    localStorage.setItem(lastAccountKey, identity.user_id);
    // Never cache cookies, fresh-auth state, device capabilities or account keys.
    writeStoredJson(drawingIdentityKey(identity.user_id), { user_id: identity.user_id, hostname: identity.hostname, username: identity.username, display_name: identity.display_name });
  } catch { /* unavailable storage cannot hold a drawing cache */ }
  if (typeof navigator === "undefined" || !("serviceWorker" in navigator)) return;
  whenIdle(() => {
    void navigator.serviceWorker.register("/offline.worker.js").then(async () => {
      const registration = await navigator.serviceWorker.ready;
      const paths = performance.getEntriesByType("resource").map((entry) => entry.name);
      registration.active?.postMessage({ type: "cache-drawing-assets", paths });
    }).catch(() => { /* offline drawing is optional when worker registration is unavailable */ });
  });
}
