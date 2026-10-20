/** Role: require fresh fixture content as well as the expected palette colour (#146). */
import { expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { runInNewContext } from "node:vm";

const script = readFileSync(new URL("worker-pixel-observer.js", import.meta.url), "utf8");

function observe(cursor: boolean, background: number[], expectedColour = 1, expectedSequence = 1, contentSequence = expectedSequence): Array<{ t: string }> {
  const rows: Array<{ t: string }> = [];
  const handlers: Array<(event: { data: unknown }) => void> = [];
  const pixels = new Uint8ClampedArray(42 * 4);
  pixels.set([...background, 255], 0);
  for (let bit = 0; bit < 8; bit++) {
    const set = (0xa5 & (1 << bit)) !== 0;
    pixels.set(set ? [255, 255, 255, 255] : [0, 0, 0, 255], (bit + 2) * 4);
  }
  for (let bit = 0; bit < 32; bit++) {
    const set = (contentSequence & (1 << bit)) !== 0;
    pixels.set(set ? [255, 255, 255, 255] : [0, 0, 0, 255], (bit + 10) * 4);
  }
  class Context {
    x = 0; y = 0;
    drawImage(_image: unknown, ...coordinates: number[]): void { this.x = coordinates[0] ?? 0; this.y = coordinates[1] ?? 0; }
    getImageData(): { data: Uint8ClampedArray } {
      // The fixture's click activates remote control at the picture centre.
      const covered = cursor && this.x === 320 && this.y === 200;
      const result = pixels.slice();
      if (covered) result.set([0, 0, 0, 255], 0);
      return { data: result };
    }
    getContextAttributes(): object { return {}; }
  }
  class Canvas { getContext(): Context { return new Context(); } }
  const worker = {
    postMessage: (row: { t: string }): void => { rows.push(row); },
    addEventListener: (_name: string, handler: (event: { data: unknown }) => void): void => { handlers.push(handler); },
  };
  runInNewContext(script, { self: worker, OffscreenCanvas: Canvas,
    OffscreenCanvasRenderingContext2D: Context, performance: { timeOrigin: 1000, now: () => 1 } });
  for (const handler of handlers) handler({ data: { t: "bench-arm", id: 1, crop: { colour: expectedColour, sequence: expectedSequence } } });
  new Context().drawImage({ displayWidth: 640, displayHeight: 400 }, 0, 0);
  worker.postMessage({ t: "trace", frame: { outcome: "painted", sequence: 17, captureNs: "9000" } } as { t: string });
  return rows;
}

test("an unchanged wrong-colour picture never acknowledges the stimulus", () => {
  expect(observe(true, [38, 89, 204]).some(row => row.t === "bench-effect")).toBe(false);
});

test("a painted fixture colour is acknowledged with a centre cursor", () => {
  expect(observe(true, [38, 191, 89]).filter(row => row.t === "bench-effect")).toHaveLength(1);
});

test("a palette-alias frame from eight fixture changes ago cannot acknowledge new content", () => {
  // The transport frame is newer, but its embedded fixture marker is stale.
  expect(observe(false, [38, 89, 204], 0, 8, 0).some(row => row.t === "bench-effect")).toBe(false);
});
