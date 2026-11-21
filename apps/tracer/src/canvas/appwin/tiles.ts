/**
 * The tile lane of an app window: exact pixels for small changes, painted over the video (#146 proposal C).
 *
 * When only a small part of a window changes (a typed letter, a caret blink, a checkbox), the Mac skips its video encoder
 * and sends the changed rectangles' exact pixels as a **tile update**, in the same ordered stream and sequence as the video.
 * The layout is described in `contracts/desktop-helper.md`; `parseTileUpdate` checks every field.
 *
 * Ordering is what keeps this flicker-free. Every accepted unit, video or tile, gets the next number in one arrival order
 * (the decode worker's decoder timestamps). Capture order equals arrival order, so:
 * - a video picture that arrives after a tile was encoded from a newer capture, which already holds the tile's pixels:
 *   once it is drawn, the tile is superseded and forgotten;
 * - a video picture that arrived before a tile can still be inside the decoder when the tile is drawn. When it comes out
 *   and is drawn over the whole canvas, every newer tile is drawn again on top of it, so the canvas never goes back to the
 *   older picture in that rectangle;
 * - tiles are inflated and drawn strictly one after another, so a later tile never lands under an earlier one.
 * A tile is kept for redrawing only while some older video picture is still in flight; otherwise it is already final on
 * the canvas. That bound is small (the decoder holds a few units), and a hard cap asks for a keyframe instead of growing.
 */

/** First byte of a tile update. Annex B video always starts with a zero byte, so this one byte tells them apart. */
export const TILE_MAGIC = 0xf7;
/** Second byte of a tile update ("T"). */
export const TILE_MAGIC2 = 0x54;
/** The only tile format version this viewer reads. */
export const TILE_VERSION = 1;
/** The most rectangles in one update; matches the Mac's limit. */
export const MAX_TILE_RECTS = 8;
/** The most tiles kept for redrawing at once. Past it the layer asks for a keyframe, which supersedes them all. */
export const MAX_LIVE_TILES = 64;
/** The most pixel bytes kept for redrawing at once (4 MiB). */
export const MAX_LIVE_TILE_BYTES = 4 * 1024 * 1024;
/** The most raw pixel bytes one update may expand to: 65,536 pixels of RGBA, the Mac's area cap. */
export const MAX_TILE_PIXEL_BYTES = 65_536 * 4;

/** One changed rectangle, in picture pixels. */
export interface TileRect { x: number; y: number; w: number; h: number }

/** A parsed tile update, before its pixels are inflated. */
export interface TileUpdate {
  /** Size of the picture the rectangles belong to. A canvas of another size ignores the update. */
  width: number;
  height: number;
  rects: TileRect[];
  /** True when `data` is raw DEFLATE; otherwise it is the RGBA bytes themselves. */
  deflated: boolean;
  /** Length of the RGBA bytes after inflating: the sum of every rectangle's `w * h * 4`. */
  pixelBytes: number;
  data: Uint8Array<ArrayBuffer>;
}

/** True when an access unit is a tile update rather than Annex B video. */
export function isTileUpdate(bytes: Uint8Array): boolean {
  return bytes.length >= 2 && bytes[0] === TILE_MAGIC && bytes[1] === TILE_MAGIC2;
}

/** Reads a tile update, or returns `undefined` when any field is malformed, out of range or inconsistent. */
export function parseTileUpdate(bytes: Uint8Array<ArrayBuffer>): TileUpdate | undefined {
  if (!isTileUpdate(bytes) || bytes.length < 9) return undefined;
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  if (bytes[2] !== TILE_VERSION || (bytes[3] !== 0 && bytes[3] !== 1)) return undefined;
  const width = view.getUint16(4), height = view.getUint16(6), count = bytes[8]!;
  if (!width || !height || width > 4096 || height > 4096 || count < 1 || count > MAX_TILE_RECTS) return undefined;
  const header = 9 + count * 8 + 4;
  if (bytes.length < header) return undefined;
  const rects: TileRect[] = [];
  let total = 0;
  for (let i = 0; i < count; i++) {
    const at = 9 + i * 8;
    const rect = { x: view.getUint16(at), y: view.getUint16(at + 2), w: view.getUint16(at + 4), h: view.getUint16(at + 6) };
    if (!rect.w || !rect.h || rect.x + rect.w > width || rect.y + rect.h > height) return undefined;
    total += rect.w * rect.h * 4;
    rects.push(rect);
  }
  const pixelBytes = view.getUint32(9 + count * 8);
  if (pixelBytes !== total || total > MAX_TILE_PIXEL_BYTES) return undefined;
  const data = bytes.subarray(header);
  const deflated = bytes[3] === 1;
  if (!deflated && data.length !== pixelBytes) return undefined;
  if (deflated && !data.length) return undefined;
  return { width, height, rects, deflated, pixelBytes, data };
}

/** The RGBA bytes of an update, inflated when needed. `undefined` when inflating fails or gives the wrong length. */
export async function tilePixels(update: TileUpdate): Promise<Uint8ClampedArray | undefined> {
  if (!update.deflated) return new Uint8ClampedArray(update.data.buffer, update.data.byteOffset, update.data.byteLength);
  try {
    // The browser's own DEFLATE decoder (no library). It is asynchronous, which is why tiles are drawn through one chain.
    const stream = new Blob([update.data]).stream().pipeThrough(new DecompressionStream("deflate-raw"));
    const inflated = await new Response(stream).arrayBuffer();
    return inflated.byteLength === update.pixelBytes ? new Uint8ClampedArray(inflated) : undefined;
  } catch {
    return undefined;
  }
}

/** One rectangle ready to draw. */
export interface TilePiece { x: number; y: number; image: ImageData }

/** What the layer needs from the decode worker: the canvas size, a way to draw, and a way to ask for a keyframe. */
export interface TileSurface {
  /** The canvas's current size; `undefined` before the first picture. */
  size(): { width: number; height: number } | undefined;
  /** Draws one rectangle's exact pixels. */
  draw(piece: TilePiece): void;
  /** Asks for a keyframe (the live-tile cap was reached or an update could not be read). */
  repair(): void;
  /** Called once per tile that reached the canvas, with when it was inflated and drawn (measurement only). */
  painted?(order: number, inflatedAt: number, drawnAt: number): void;
}

/** Counters of the tile lane, for measurement only. */
export interface TileStats {
  /** Tile updates accepted. */
  received: number;
  /** Updates drawn on the canvas. */
  painted: number;
  /** Updates not drawn because a newer video picture was already drawn. */
  superseded: number;
  /** Times a kept tile was drawn again over an older video picture that decoded late. */
  redrawn: number;
  /** Updates that could not be read or did not match the canvas. */
  dropped: number;
}

/** A tile drawn on the canvas and kept because an older video picture is still in flight. */
interface LiveTile { order: number; width: number; height: number; pieces: TilePiece[]; bytes: number }

/**
 * The ordering state of one window's tile lane. The decode worker reports each video unit it accepts, retires and draws,
 * and hands over each tile update with its order number; this class decides what to draw and when.
 */
export class TileLayer {
  /** Video units accepted and not yet out of the decoder, by order number. */
  private readonly inFlight = new Set<number>();
  /** Tiles that must be drawn again if an older video picture is drawn, oldest first. */
  private live: LiveTile[] = [];
  /** Bytes held by `live`. */
  private liveBytes = 0;
  /** Order number of the newest video picture drawn. A tile older than it is superseded. */
  private paintedVideo = 0;
  /** The serial inflate-and-draw chain. */
  private chain: Promise<void> = Promise.resolve();
  /** Bumped by `reset`, so work queued before it is discarded. */
  private generation = 0;
  readonly stats: TileStats = { received: 0, painted: 0, superseded: 0, redrawn: 0, dropped: 0 };

  constructor(private readonly surface: TileSurface) {}

  /** A video unit with this order number was accepted and will come out of the decoder later. */
  videoAccepted(order: number): void { this.inFlight.add(order); }

  /** The video unit `order` came out of the decoder (drawn or superseded). Older ones are gone too: output keeps order. */
  videoRetired(order: number): void {
    for (const value of this.inFlight) if (value <= order) this.inFlight.delete(value);
    this.prune();
  }

  /** The video unit `order` was dropped before reaching the decoder; it will never come out. */
  videoDropped(order: number): void { this.inFlight.delete(order); this.prune(); }

  /** Every in-flight video unit except those in `keep` will never come out (its decoder was closed). */
  videoForgotten(keep: Iterable<number> = []): void {
    const kept = new Set(keep);
    for (const value of this.inFlight) if (!kept.has(value)) this.inFlight.delete(value);
    this.prune();
  }

  /** The video picture `order` was just drawn over the whole canvas: forget older tiles, draw newer ones again on top. */
  videoPainted(order: number): void {
    // Redraw before retiring `order`: retiring it can make the kept tiles look final and prune them.
    this.paintedVideo = Math.max(this.paintedVideo, order);
    const kept: LiveTile[] = [];
    for (const tile of this.live) {
      if (tile.order < order) continue;
      if (!this.fits(tile)) { this.stats.dropped++; continue; }
      for (const piece of tile.pieces) this.surface.draw(piece);
      this.stats.redrawn++;
      kept.push(tile);
    }
    this.live = kept;
    this.liveBytes = kept.reduce((sum, tile) => sum + tile.bytes, 0);
    this.videoRetired(order);
  }

  /** Accepts one tile update with its order number. It is drawn after every earlier tile, never before. */
  accept(order: number, bytes: Uint8Array<ArrayBuffer>): void {
    this.stats.received++;
    const update = parseTileUpdate(bytes);
    if (!update) { this.stats.dropped++; this.surface.repair(); return; }
    const generation = this.generation;
    this.chain = this.chain.then(async () => {
      const pixels = await tilePixels(update);
      if (generation !== this.generation) return;
      if (!pixels) { this.stats.dropped++; this.surface.repair(); return; }
      this.apply(order, update, pixels);
    });
  }

  /** Resolves once every accepted tile has been handled (tests and measurement). */
  settled(): Promise<void> { return this.chain; }

  /** Forgets everything: a pause, a re-attach or a closed window. Tiles still inflating are discarded. */
  reset(): void {
    this.generation++;
    this.inFlight.clear();
    this.live = []; this.liveBytes = 0; this.paintedVideo = 0;
    this.chain = Promise.resolve();
  }

  /** Draws one inflated update unless a newer video picture already covers it, and keeps it while it may need redrawing. */
  private apply(order: number, update: TileUpdate, pixels: Uint8ClampedArray): void {
    const inflatedAt = performance.now();
    if (order < this.paintedVideo) { this.stats.superseded++; return; }
    const pieces: TilePiece[] = [];
    let offset = 0;
    for (const rect of update.rects) {
      const length = rect.w * rect.h * 4;
      pieces.push({ x: rect.x, y: rect.y, image: new ImageData(pixels.slice(offset, offset + length), rect.w, rect.h) });
      offset += length;
    }
    const tile: LiveTile = { order, width: update.width, height: update.height, pieces, bytes: update.pixelBytes };
    const older = this.olderVideoInFlight(order);
    if (this.fits(tile)) {
      for (const piece of pieces) this.surface.draw(piece);
      this.stats.painted++;
      this.surface.painted?.(order, inflatedAt, performance.now());
    } else if (!older) {
      // Nothing in flight will bring the canvas to this picture's size: the update is for another geometry.
      this.stats.dropped++; return;
    }
    // A size mismatch while an older picture is still decoding (the start of a stream, a resize) is kept undrawn: that
    // picture resizes the canvas, and the tile is drawn right after it, so its rectangle never shows the older content.
    if (older) {
      this.live.push(tile);
      this.liveBytes += update.pixelBytes;
      if (this.live.length > MAX_LIVE_TILES || this.liveBytes > MAX_LIVE_TILE_BYTES) {
        // A keyframe supersedes every kept tile; until it arrives the canvas still shows the newest pixels drawn.
        this.live = []; this.liveBytes = 0;
        this.surface.repair();
      }
    }
  }

  /** True when the canvas has the size of the picture the tile belongs to. */
  private fits(tile: LiveTile): boolean {
    const size = this.surface.size();
    return !!size && size.width === tile.width && size.height === tile.height;
  }

  /** True when a video unit accepted before `order` has not come out of the decoder yet. */
  private olderVideoInFlight(order: number): boolean {
    for (const value of this.inFlight) if (value < order) return true;
    return false;
  }

  /** Drops kept tiles that no older video picture can draw over any more: they are final on the canvas. */
  private prune(): void {
    if (!this.live.length) return;
    const kept = this.live.filter((tile) => this.olderVideoInFlight(tile.order));
    if (kept.length === this.live.length) return;
    this.live = kept;
    this.liveBytes = kept.reduce((sum, tile) => sum + tile.bytes, 0);
  }
}
