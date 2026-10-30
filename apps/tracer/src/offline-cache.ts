/** Warms public app-shell assets only; no account identity or drawing is persisted (D312). */
import { whenIdle } from "./on-demand";
export function warmOfflineShell(): void {
  if (typeof navigator === "undefined" || !("serviceWorker" in navigator)) return;
  whenIdle(() => {
    void (async () => {
      await navigator.serviceWorker.register("/offline.worker.js");
      const registration = await navigator.serviceWorker.ready;
      const paths = performance.getEntriesByType("resource").map((entry) => entry.name);
      registration.active?.postMessage({ type: "cache-drawing-assets", paths });
    })().catch(() => { /* offline drawing is optional when worker registration is unavailable */ });
  });
}
