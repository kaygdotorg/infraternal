/** Stores public drawing labels immediately and warms the offline decoder after the signed-in screen is idle (D245). */
import { drawingIdentityKey, lastAccountKey, writeStoredJson } from "./account-storage";
import { isCanonicalUuid } from "./identifiers";
import type { DrawingIdentity } from "./offline-drawing";
import { whenIdle } from "./on-demand";

export function cacheDrawingIdentity(identity: DrawingIdentity): void {
  if (!isCanonicalUuid(identity.user_id) || typeof identity.hostname !== "string") return;
  try {
    localStorage.setItem(lastAccountKey, identity.user_id);
    // Never cache cookies, fresh-auth state, device capabilities or account keys.
    writeStoredJson(drawingIdentityKey(identity.user_id), { user_id: identity.user_id, hostname: identity.hostname, username: identity.username, display_name: identity.display_name });
  } catch { /* unavailable storage cannot hold a drawing cache */ }
  if (typeof navigator === "undefined" || !("serviceWorker" in navigator)) return;
  whenIdle(() => {
    void import("./offline-drawing").then(async () => {
      await navigator.serviceWorker.register("/offline.worker.js");
      const registration = await navigator.serviceWorker.ready;
      const paths = performance.getEntriesByType("resource").map((entry) => entry.name);
      registration.active?.postMessage({ type: "cache-drawing-assets", paths });
    }).catch(() => { /* offline drawing is optional when worker registration is unavailable */ });
  });
}
