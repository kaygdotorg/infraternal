/** Warms public app-shell assets only; no account identity or drawing is persisted (D312). */
import { whenIdle } from "./on-demand";

/** Populate the public shell for the first uncontrolled visit and trim it after controlled reloads. */
export function warmOfflineShell(): void {
  if (typeof navigator === "undefined" || !("serviceWorker" in navigator)) return;
  whenIdle(() => {
    void (async () => {
      const { serviceWorker } = navigator;
      const [navigation] = performance.getEntriesByType("navigation") as PerformanceNavigationTiming[];
      if (serviceWorker.controller && navigation?.workerStart) {
        // The worker already fetched and stored the shell as this navigation used it.
        serviceWorker.controller.postMessage({ type: "cache-drawing-assets", paths: [], warmNavigation: false });
        return;
      }
      await serviceWorker.register("/offline.worker.js");
      const registration = await serviceWorker.ready;
      const paths = performance.getEntriesByType("resource").map((entry) => entry.name);
      registration.active?.postMessage({ type: "cache-drawing-assets", paths });
    })().catch(() => { /* offline drawing is optional when worker registration is unavailable */ });
  });
}
