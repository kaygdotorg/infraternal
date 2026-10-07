/** Renders a still theme mesh off the UI thread and returns its encoded image. */
import { renderBackdropBlob } from "./backdrop";
import type { Theme } from "./themes";

interface RenderRequest { id: number; theme: Theme; width: number; height: number }
interface RenderResponse { id: number; blob: Blob | null }

interface WorkerScope {
  addEventListener(type: "message", listener: (event: MessageEvent<RenderRequest>) => void): void;
  postMessage(response: RenderResponse): void;
}

const scope = globalThis as unknown as WorkerScope;
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
