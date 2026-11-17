/**
 * End-of-frame canvas sampler shared by the real-server specs that prove a repaint never shows an empty terminal
 * (#528). It samples the terminal canvas once per frame, after every animation-frame callback has run (the renderer's
 * loop and the tracer's write callbacks alike) and before the browser paints, by watching a 1 px probe whose width
 * flips on every frame with a resize observer.
 */
import type { Page } from "playwright/test";

/** One sampled frame: when it was taken and how many ink pixels its scaled copy held. */
export interface FrameSample { at: number; ink: number }

declare global {
  interface Window {
    /** Present only while this spec's frame sampler runs. */
    __repaintFrames?: {
      samples: FrameSample[];
      /** A PNG data URL of the first frame with ink below the threshold set by `arm`, for the issue's evidence. */
      firstBlank?: string;
      /** Starts recording and sets the ink count below which a frame is saved as the first blank one. */
      arm(threshold: number): void;
      stop(): void;
    };
  }
}


/**
 * Installs the end-of-frame sampler on the terminal canvas of `page`. It records nothing until `arm`, so the sign-in
 * screens and the program's start do not count. `scale` is the integer shrink factor of the sampled copy: 4 reads a
 * regular grid of a full screen cheaply, 1 reads every pixel and so also sees the thin glyphs of a nearly empty screen.
 */
export async function installFrameSampler(page: Page, scale = 4): Promise<void> {
  await page.evaluate((scale) => {
    const canvas = document.querySelector<HTMLCanvasElement>(".terminal-host canvas");
    if (!canvas) throw new Error("terminal canvas is missing");
    // A nearest-neighbour copy at 1/`scale` reads a regular grid of the canvas's own pixels in one small readback.
    const copy = new OffscreenCanvas(1, 1);
    const context = copy.getContext("2d", { willReadFrequently: true });
    if (!context) throw new Error("sampler canvas is unavailable");
    const probe = document.createElement("div");
    probe.style.cssText = "position:fixed;left:0;top:0;width:1px;height:1px;pointer-events:none;opacity:0";
    document.body.append(probe);
    const samples: FrameSample[] = [];
    let threshold = -1;
    let running = false;
    let wide = false;
    const state: NonNullable<Window["__repaintFrames"]> = {
      samples,
      arm(value: number) { threshold = value; running = true; },
      stop() { running = false; observer.disconnect(); probe.remove(); },
    };
    window.__repaintFrames = state;
    // Ink is any pixel far from the frame's most common colour (the background), so the theme does not matter.
    const sample = (): void => {
      if (!running || canvas.width === 0) return;
      const width = Math.max(1, Math.floor(canvas.width / scale));
      const height = Math.max(1, Math.floor(canvas.height / scale));
      if (copy.width !== width || copy.height !== height) { copy.width = width; copy.height = height; }
      context.imageSmoothingEnabled = false;
      context.drawImage(canvas, 0, 0, width, height);
      const { data } = context.getImageData(0, 0, width, height);
      const counts = new Map<number, number>();
      for (let i = 0; i < data.length; i += 4) {
        const key = (data[i]! << 16) | (data[i + 1]! << 8) | data[i + 2]!;
        counts.set(key, (counts.get(key) ?? 0) + 1);
      }
      let background = 0;
      let most = -1;
      for (const [key, count] of counts) if (count > most) { most = count; background = key; }
      const [r, g, b] = [(background >> 16) & 255, (background >> 8) & 255, background & 255];
      let ink = 0;
      for (let i = 0; i < data.length; i += 4) {
        if (Math.abs(data[i]! - r) + Math.abs(data[i + 1]! - g) + Math.abs(data[i + 2]! - b) > 90) ink += 1;
      }
      samples.push({ at: performance.now(), ink });
      if (ink < threshold && state.firstBlank === undefined) state.firstBlank = canvas.toDataURL("image/png");
    };
    // Resize observations are delivered after all animation-frame callbacks and layout, just before paint.
    const observer = new ResizeObserver(sample);
    observer.observe(probe);
    const flip = (): void => {
      if (!probe.isConnected) return;
      wide = !wide;
      probe.style.width = wide ? "2px" : "1px";
      requestAnimationFrame(flip);
    };
    requestAnimationFrame(flip);
  }, scale);
}
