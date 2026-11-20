/**
 * The last known screen of recently shown sessions (#128, TASTE "Switching sessions is instant"). When a window
 * leaves a session, a picture of its terminal is kept here; when a window shows that session again, the picture is
 * on screen in the same frame as the action, and the live screen replaces it when the server's snapshot has been
 * painted (a round trip later, at worst). Without it the switch shows an empty terminal for that whole round trip.
 *
 * Memory (iOS ends a page that holds too much): pictures live in memory only, never on disk (a terminal's screen can
 * hold secrets); at most 4 on a desktop and 2 on a phone, never more than about 12 million pixels together, the
 * oldest dropped first; all of them go when the page is hidden. On demand (D188): loaded at idle after the first
 * terminal paints, so the first switch already has it.
 */
import { coarse } from "../dom";

export interface ScreenCache {
  /** Keeps a picture of `canvas` as session `key`'s last screen (asynchronous; the pixels are read at the call). */
  capture(key: string, canvas: HTMLCanvasElement): void;
  /** Puts the picture of `key` over `host` at once; returns a function that removes it, or undefined when there is none. */
  ghost(key: string, host: HTMLElement): (() => void) | undefined;
  clear(): void;
}

const MAX_PIXELS = 12_000_000;

/** Creates the cache of session pictures, which keeps at most two on a touch screen and four elsewhere. */
export function createScreenCache(): ScreenCache {
  const pictures = new Map<string, ImageBitmap>();
  const limit = (): number => (coarse.matches ? 2 : 4);
  const drop = (key: string): void => { pictures.get(key)?.close(); pictures.delete(key); };
  const trim = (): void => {
    let pixels = 0;
    for (const b of pictures.values()) pixels += b.width * b.height;
    for (const key of [...pictures.keys()]) {
      if (pictures.size <= limit() && pixels <= MAX_PIXELS) break;
      const b = pictures.get(key)!;
      pixels -= b.width * b.height;
      drop(key);
    }
  };
  const clear = (): void => { for (const key of [...pictures.keys()]) drop(key); };
  document.addEventListener("visibilitychange", () => { if (document.hidden) clear(); });
  window.addEventListener("pagehide", clear);
  return {
    capture(key, canvas) {
      if (!canvas.width || !canvas.height) return;
      void createImageBitmap(canvas).then((bitmap) => { drop(key); pictures.set(key, bitmap); trim(); }, () => undefined);
    },
    ghost(key, host) {
      const bitmap = pictures.get(key);
      if (!bitmap) return undefined;
      // Most recently used last, so the oldest goes first when the budget is tight.
      pictures.delete(key); pictures.set(key, bitmap);
      const canvas = document.createElement("canvas");
      canvas.className = "cl-ghost";
      canvas.setAttribute("aria-hidden", "true");
      canvas.width = bitmap.width;
      canvas.height = bitmap.height;
      // Drawn at the pixel size it was taken at, from the corner the terminal's own canvas starts at.
      const dpr = window.devicePixelRatio || 1;
      canvas.style.cssText = `position:absolute;left:0;top:0;width:${bitmap.width / dpr}px;height:${bitmap.height / dpr}px;pointer-events:none;z-index:var(--z-content)`;
      canvas.getContext("2d")?.drawImage(bitmap, 0, 0);
      host.append(canvas);
      return () => canvas.remove();
    },
    clear,
  };
}
