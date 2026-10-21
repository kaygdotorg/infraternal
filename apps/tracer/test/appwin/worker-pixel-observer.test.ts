/** Role: require fresh fixture content as well as the expected palette colour (#146). */
import { expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { runInNewContext } from "node:vm";

const script = readFileSync(new URL("worker-pixel-observer.js", import.meta.url), "utf8");

function observe(cursor: boolean, background: number[], expectedColour = 1, expectedSequence = 1, contentSequence = expectedSequence, letterboxed = false, projected = false, flood = false, arm = true): Array<{ t: string }> {
  const rows: Array<{ t: string }> = [];
  const handlers: Array<(event: { data: unknown }) => void> = [];
  const picture = letterboxed ? { x: 0, y: 60, width: 640, height: 280 } : { x: 0, y: 0, width: 640, height: 400 };
  const cell = picture.width * .2 / 40;
  function pixelAt(x: number, y: number): number[] {
    if (cursor && x === 320 && y === 200) return [0, 0, 0, 255];
    const bit = Math.floor((x - picture.x - picture.width * .8) / cell);
    const bottom = picture.y + picture.height * .7;
    if (bit >= 0 && bit < 40 && y >= bottom - cell && y < bottom) {
      const set = bit < 8 ? (0xa5 & (1 << bit)) !== 0 : (contentSequence & (1 << (bit - 8))) !== 0;
      return set ? [255, 255, 255, 255] : [0, 0, 0, 255];
    }
    return [...background, 255];
  }
  class Context {
    samples = new Map<number, number[]>();
    drawImage(_image: unknown, ...coordinates: number[]): void {
      const [x = 0, y = 0, width = 1, , destination = 0] = coordinates;
      for (let index = 0; index < width; index++) this.samples.set(destination + index, pixelAt(x + index, y));
    }
    getImageData(): { data: Uint8ClampedArray } {
      const result = new Uint8ClampedArray(42 * 4);
      for (const [index, pixel] of this.samples) result.set(pixel, index * 4);
      return { data: result };
    }
    getContextAttributes(): object { return {}; }
  }
  class Canvas { getContext(): Context { return new Context(); } }
  const worker = {
    __benchFlood: flood,
    postMessage: (row: { t: string }): void => { rows.push(row); },
    addEventListener: (_name: string, handler: (event: { data: unknown }) => void): void => { handlers.push(handler); },
  };
  runInNewContext(script, { self: worker, OffscreenCanvas: Canvas,
    OffscreenCanvasRenderingContext2D: Context, performance: { timeOrigin: 1000, now: () => 1 } });
  if (arm) {
    for (const handler of handlers) handler({ data: { t: "bench-arm", id: 1, crop: { colour: expectedColour, sequence: expectedSequence, ...(projected ? { projection: { width: 640, height: 400, colourX: .75, colourY: .675, markerX: .8, markerY: .636, cell: .005 } } : {}) } } });
    new Context().drawImage({ displayWidth: 640, displayHeight: 400 }, 0, 0);
  }
  worker.postMessage({ t: "trace", frame: { outcome: "painted", sequence: 17, captureNs: "9000" } } as { t: string });
  return rows;
}

test("an unchanged wrong-colour picture never acknowledges the stimulus", () => {
  expect(observe(true, [38, 89, 204]).some(row => row.t === "bench-effect")).toBe(false);
});

test("a trace without an armed fixture passes through without a worker error", () => {
  expect(observe(false, [38, 89, 204], 1, 1, 1, false, false, false, false).map(row => row.t)).toEqual(["trace"]);
});

test("a painted fixture colour is acknowledged with a centre cursor", () => {
  expect(observe(true, [38, 191, 89]).filter(row => row.t === "bench-effect")).toHaveLength(1);
});

test("a palette-alias frame from eight fixture changes ago cannot acknowledge new content", () => {
  // The transport frame is newer, but its embedded fixture marker is stale.
  expect(observe(false, [38, 89, 204], 0, 8, 0).some(row => row.t === "bench-effect")).toBe(false);
});

test("animated matching accepts a newer content sequence only in flood mode", () => {
  // A higher-rate fixture can advance again between input and presentation;
  // retain marker validation while allowing the newest visible sequence.
  expect(observe(false, [102, 64, 204], 5, 5, 6).some(row => row.t === "bench-effect")).toBe(false);
  expect(observe(false, [102, 64, 204], 5, 5, 6, false, false, true).some(row => row.t === "bench-effect")).toBe(true);
});

// The bitmap model samples coordinates, so fixed full-frame fractions cannot
// accidentally pass when capture adds space around the selected window.
test("letterboxed content needs the selected window projection", () => {
  expect(observe(false, [38, 191, 89], 1, 257, 257, true).some(row => row.t === "bench-effect")).toBe(false);
  expect(observe(false, [38, 191, 89], 1, 257, 257, true, true).some(row => row.t === "bench-effect")).toBe(true);
  expect(observe(false, [38, 89, 204], 0, 8, 0, true, true).some(row => row.t === "bench-effect")).toBe(false);
});
