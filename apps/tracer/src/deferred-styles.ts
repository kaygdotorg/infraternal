/**
 * The guard for the style sheets that `index.html` loads without blocking the first paint (J1100, #573).
 *
 * The sign-in screen needs only the sheets in the page's render-blocking set. The five canvas sheets (`canvas`, `clusters`,
 * `mesh`, `sessions`, `addhost`) are fetched in the background; the page's inline script collects them in
 * `window.__deferredStyles`. The signed-in screen calls {@link deferredStylesReady} before it mounts, so the canvas is never
 * drawn without its styles: on a slow link the sign-in screen appears sooner, and the canvas appears when its styles are there.
 */

declare global {
  interface Window {
    /** Settles when every deferred sheet has loaded or failed. Absent in a page that does not defer any (a test harness page). */
    __deferredStyles?: Promise<unknown>;
  }
}

/**
 * Resolves when the deferred style sheets are in. Never rejects: a sheet that fails to load must not stop the app from starting.
 * @returns a promise that is already settled when the page defers nothing or the sheets arrived during sign-in
 */
export async function deferredStylesReady(): Promise<void> {
  await window.__deferredStyles?.catch(() => undefined);
}
