/** Renders a still theme mesh off the UI thread and returns its encoded image. */
import { renderBackdropBlob } from "./backdrop";
import type { Theme } from "./themes";

/** A render job sent to the worker; `id` comes back unchanged in the {@link RenderResponse}. */
interface RenderRequest { id: number; theme: Theme; width: number; height: number }
/** The result for one request: the encoded image, or `blob: null` when the render failed (the caller then renders on the main thread). */
interface RenderResponse { id: number; blob: Blob | null }

/** The small part of the worker global scope this file uses, so it type-checks without the WebWorker lib. */
interface WorkerScope {
  addEventListener(type: "message", listener: (event: MessageEvent<RenderRequest>) => void): void;
  postMessage(response: RenderResponse): void;
}

/** The worker's own global scope. */
const scope = globalThis as unknown as WorkerScope;
/** The tail of the render chain; each request waits for the one before it. */
let queue = Promise.resolve();

scope.addEventListener("message", (event) => {
  const { id, theme, width, height } = event.data;
  // Keep WebGL context allocation serial even while an image encoder is pending.
  queue = queue.then(async () => {
    let blob: Blob | null = null;
    try { blob = await renderBackdropBlob(theme, width, height); }
    catch { /* A failed worker render is retried on the main-thread fallback. */ }
    scope.postMessage({ id, blob });
  });
});
