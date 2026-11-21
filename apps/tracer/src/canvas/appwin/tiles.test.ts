/** Checks the tile lane's format checks and the ordering rules that keep tiles and video from ever showing older pixels (#146 proposal C). */
import { expect, test } from "bun:test";
import { deflateRawSync } from "node:zlib";
import { isTileUpdate, MAX_WAITING_TILES, parseTileUpdate, TileLayer, type TilePiece } from "./tiles";

/** Bun has no ImageData; the layer only stores and hands it to `draw`. */
globalThis.ImageData ??= class {
  constructor(readonly data: Uint8ClampedArray, readonly width: number, readonly height: number) {}
} as unknown as typeof ImageData;

/** Builds a tile update the way the Mac does: one rectangle filled with `value`, optionally deflated. */
function tile(rect: { x: number; y: number; w: number; h: number }, value: number, deflate = false, size = { width: 64, height: 48 }): Uint8Array<ArrayBuffer> {
  const raw = new Uint8Array(rect.w * rect.h * 4).fill(value);
  const data = deflate ? new Uint8Array(deflateRawSync(raw)) : raw;
  const out = new Uint8Array(9 + 8 + 4 + data.length);
  const view = new DataView(out.buffer);
  out.set([0xf7, 0x54, 1, deflate ? 1 : 0]);
  view.setUint16(4, size.width); view.setUint16(6, size.height); out[8] = 1;
  view.setUint16(9, rect.x); view.setUint16(11, rect.y); view.setUint16(13, rect.w); view.setUint16(15, rect.h);
  view.setUint32(17, raw.length);
  out.set(data, 21);
  return out;
}

/** A fake canvas: records every rectangle drawn (with its fill value) and every repair request. */
function surface(size: { width: number; height: number } | null = { width: 64, height: 48 }) {
  const drawn: number[] = [];
  let repairs = 0;
  const current: { size: { width: number; height: number } | undefined } = { size: size ?? undefined };
  return {
    drawn, current,
    repairs: () => repairs,
    surface: { size: () => current.size, draw: (piece: TilePiece) => drawn.push(piece.image.data[0]!), repair: () => { repairs++; } },
  };
}

test("tile updates are told apart from Annex B and every malformed field is refused", () => {
  const good = tile({ x: 2, y: 3, w: 4, h: 5 }, 9);
  expect(isTileUpdate(good)).toBe(true);
  expect(isTileUpdate(new Uint8Array([0, 0, 0, 1, 0x65]))).toBe(false);
  expect(parseTileUpdate(good)).toMatchObject({ width: 64, height: 48, rects: [{ x: 2, y: 3, w: 4, h: 5 }], deflated: false, pixelBytes: 80 });
  const broken = (index: number, value: number) => { const copy = good.slice(); copy[index] = value; return parseTileUpdate(copy); };
  expect(broken(2, 2)).toBeUndefined(); // unknown version
  expect(broken(3, 7)).toBeUndefined(); // unknown encoding
  expect(broken(8, 0)).toBeUndefined(); // no rectangles
  expect(broken(8, 9)).toBeUndefined(); // too many rectangles (and truncated)
  expect(broken(14, 61)).toBeUndefined(); // x + w past the picture width
  expect(broken(20, 81)).toBeUndefined(); // pixel length disagrees with the rectangles
  expect(parseTileUpdate(good.slice(0, good.length - 1))).toBeUndefined(); // raw data truncated
  expect(parseTileUpdate(tile({ x: 0, y: 0, w: 64, h: 48 }, 1, false, { width: 64, height: 48 }))).toBeDefined();
});

test("a tile waits for an older video picture still in the decoder and is drawn in the same turn it comes out", async () => {
  const s = surface(); const layer = new TileLayer(s.surface);
  layer.videoAccepted(1); layer.videoRetired(1);
  layer.videoAccepted(2); // a delta still inside the decoder
  layer.accept(3, tile({ x: 1, y: 1, w: 2, h: 2 }, 50, true));
  await layer.settled();
  expect(s.drawn).toEqual([]); // drawing it now would show the tile ahead of the delta's changes
  layer.videoRetired(2);
  expect(s.drawn).toEqual([50]);
  expect(layer.stats).toMatchObject({ painted: 1, waited: 1, superseded: 0 });
});

test("with nothing older in flight a tile is drawn as soon as it is inflated", async () => {
  const s = surface(); const layer = new TileLayer(s.surface);
  layer.videoAccepted(1); layer.videoRetired(1);
  layer.accept(2, tile({ x: 0, y: 0, w: 2, h: 2 }, 21));
  await layer.settled();
  expect(s.drawn).toEqual([21]);
  expect(layer.stats.waited).toBe(0);
});

test("a video picture accepted after a tile supersedes it, even when the tile finishes inflating later", async () => {
  const s = surface(); const layer = new TileLayer(s.surface);
  layer.videoAccepted(1); layer.videoRetired(1);
  layer.accept(2, tile({ x: 0, y: 0, w: 8, h: 8 }, 70, true));
  layer.videoAccepted(3); // arrives before the tile's async inflate resolves
  await layer.settled();
  layer.videoRetired(3);
  expect(s.drawn).toEqual([]);
  expect(layer.stats.superseded).toBe(1);
});

test("a waiting tile is superseded when the older picture is skipped for a newer one", async () => {
  const s = surface(); const layer = new TileLayer(s.surface);
  layer.videoAccepted(2);
  layer.accept(3, tile({ x: 0, y: 0, w: 2, h: 2 }, 60));
  await layer.settled();
  layer.videoAccepted(4);
  layer.videoRetired(2); // not drawn: the decoder already holds 4
  layer.videoRetired(4);
  expect(s.drawn).toEqual([]);
  expect(layer.stats.superseded).toBe(1);
});

test("tiles are drawn strictly in arrival order whatever their encoding", async () => {
  const s = surface(); const layer = new TileLayer(s.surface);
  layer.videoAccepted(1); layer.videoRetired(1);
  layer.accept(2, tile({ x: 0, y: 0, w: 30, h: 30 }, 11, true)); // slower: inflated
  layer.accept(3, tile({ x: 0, y: 0, w: 2, h: 2 }, 12, false)); // faster: raw
  layer.accept(4, tile({ x: 0, y: 0, w: 2, h: 2 }, 13, true));
  await layer.settled();
  expect(s.drawn).toEqual([11, 12, 13]);
});

test("tiles after a dropped video unit, or a closed decoder, are dropped with it", async () => {
  const s = surface(); const layer = new TileLayer(s.surface);
  layer.videoAccepted(1); layer.videoRetired(1);
  layer.videoAccepted(2);
  layer.accept(3, tile({ x: 0, y: 0, w: 2, h: 2 }, 22));
  await layer.settled();
  layer.videoDropped(2); // a gap: a repair keyframe follows, and 3 belongs after 2's changes
  expect(s.drawn).toEqual([]);
  layer.videoAccepted(4);
  layer.accept(5, tile({ x: 0, y: 0, w: 2, h: 2 }, 23));
  await layer.settled();
  layer.videoForgotten();
  layer.videoRetired(4);
  expect(s.drawn).toEqual([]);
  expect(layer.stats.dropped).toBe(2);
});

test("a tile for a picture size the canvas does not have yet waits for the older picture that resizes it", async () => {
  const s = surface(null); const layer = new TileLayer(s.surface);
  layer.videoAccepted(1); // the stream's first keyframe, still decoding
  layer.accept(2, tile({ x: 0, y: 0, w: 2, h: 2 }, 31));
  await layer.settled();
  expect(s.drawn).toEqual([]);
  s.current.size = { width: 64, height: 48 };
  layer.videoRetired(1);
  expect(s.drawn).toEqual([31]);
  // A tile for another geometry is ignored.
  layer.accept(3, tile({ x: 0, y: 0, w: 2, h: 2 }, 32, false, { width: 32, height: 24 }));
  await layer.settled();
  expect(s.drawn).toEqual([31]);
  expect(layer.stats.dropped).toBe(1);
});

test("too many waiting tiles and unreadable updates ask for a keyframe instead of growing", async () => {
  const s = surface(); const layer = new TileLayer(s.surface);
  layer.videoAccepted(1);
  for (let order = 2; order <= MAX_WAITING_TILES + 2; order++) layer.accept(order, tile({ x: 0, y: 0, w: 1, h: 1 }, order % 200));
  await layer.settled();
  expect(s.repairs()).toBe(1);
  layer.videoRetired(1);
  expect(s.drawn).toEqual([]);
  const corrupt = tile({ x: 0, y: 0, w: 4, h: 4 }, 1, true);
  corrupt[corrupt.length - 1] = corrupt[corrupt.length - 1]! ^ 0xff; corrupt[22] = corrupt[22]! ^ 0xff;
  layer.accept(100, corrupt);
  await layer.settled();
  layer.accept(101, new Uint8Array([0xf7, 0x54, 9]));
  expect(s.repairs()).toBe(3);
  // The byte cap: sixteen of the largest legal tiles (65,536 px, 256 KiB of pixels each) fill 4 MiB; the seventeenth
  // asks for a keyframe, long before the count cap.
  const before = s.repairs();
  const huge = new TileLayer({ ...s.surface, size: () => ({ width: 1024, height: 64 }) });
  huge.videoAccepted(1);
  for (let order = 2; order <= 18; order++) huge.accept(order, tile({ x: 0, y: 0, w: 1024, h: 64 }, 2, true, { width: 1024, height: 64 }));
  await huge.settled();
  expect(s.repairs() - before).toBe(1);
});

test("reset discards tiles that are still inflating", async () => {
  const s = surface(); const layer = new TileLayer(s.surface);
  layer.videoAccepted(1); layer.videoRetired(1);
  layer.accept(2, tile({ x: 0, y: 0, w: 4, h: 4 }, 41, true));
  layer.reset();
  // sleep: the discarded inflate resolves on its own; give it time to (not) draw.
  await new Promise((resolve) => setTimeout(resolve, 20));
  expect(s.drawn).toEqual([]);
});
