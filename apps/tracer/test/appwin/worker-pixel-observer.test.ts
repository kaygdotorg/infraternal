/** Role: keep a captured centre cursor from hiding a real fixture colour change (#146). */
import { expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { runInNewContext } from "node:vm";

const script = readFileSync(new URL("worker-pixel-observer.js", import.meta.url), "utf8");

function observe(cursor: boolean, background: number[]): Array<{ t: string }> {
  const rows: Array<{ t: string }> = [];
  const handlers: Array<(event: { data: unknown }) => void> = [];
  class Context {
    x = 0; y = 0;
    drawImage(_image: unknown, x: number, y: number): void { this.x = x; this.y = y; }
    getImageData(): { data: Uint8ClampedArray } {
      // The fixture's click activates remote control at the picture centre.
      const covered = cursor && this.x === 320 && this.y === 200;
      return { data: new Uint8ClampedArray([...(covered ? [0, 0, 0] : background), 255]) };
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
  for (const handler of handlers) handler({ data: { t: "bench-arm", id: 1, crop: { colour: 1 } } });
  new Context().drawImage({ displayWidth: 640, displayHeight: 400 }, 0, 0);
  worker.postMessage({ t: "trace", frame: { outcome: "painted" } } as { t: string });
  return rows;
}

test("an unchanged wrong-colour picture never acknowledges the stimulus", () => {
  expect(observe(true, [38, 89, 204]).some(row => row.t === "bench-effect")).toBe(false);
});

test("a painted fixture colour is acknowledged with a centre cursor", () => {
  expect(observe(true, [38, 191, 89]).filter(row => row.t === "bench-effect")).toHaveLength(1);
});
