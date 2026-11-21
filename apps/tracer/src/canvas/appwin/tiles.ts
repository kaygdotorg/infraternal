/**
 * The tile lane of an app window: exact pixels for small changes, painted over the video (#146 proposal C).
 *
 * When only a small part of a window changes (a typed letter, a caret blink, a checkbox), the Mac skips its video encoder
 * and sends the changed rectangles' exact pixels as a **tile update**, in the same ordered stream and sequence as the video.
 * The layout is described in `contracts/desktop-helper.md`; `parseTileUpdate` checks every field.
 *
 * A tile's rectangles are the changes since the picture that came just before it in the stream. So the canvas is correct
 * after drawing a tile only if everything before it is already on the canvas. Every accepted unit, video or tile, gets the
 * next number in one arrival order (the decode worker's decoder timestamps), and capture order equals arrival order. Then:
 * - a tile waits while any video picture that arrived before it is still inside the decoder, and is drawn right after it;
 * - a tile that arrived before the newest accepted video picture is never drawn: that picture was encoded from a newer
 *   capture, which already holds the tile's pixels;
 * - tiles are inflated and drawn strictly in order, so a later tile never lands under an earlier one;
 * - when a video unit is dropped (a gap, an overflow, a closed decoder), every tile after it is dropped too: a repair
 *   keyframe is on its way, and drawing those tiles over the older picture would mix two moments.
 * So every picture the canvas shows is exactly one moment of the source: the newest video picture plus the tiles after it.
 * Nothing goes back to older content and no rectangle runs ahead of the rest. Waiting tiles are bounded by the decoder's
 * own queue; a hard cap asks for a keyframe instead of growing.
 */

/** First byte of a tile update. Annex B video always starts with a zero byte, so this one byte tells them apart. */
export const TILE_MAGIC = 0xf7;
/** Second byte of a tile update ("T"). */
export const TILE_MAGIC2 = 0x54;
/** The only tile format version this viewer reads. */
export const TILE_VERSION = 1;
/** The most rectangles in one update; matches the Mac's limit. */
export const MAX_TILE_RECTS = 8;
/** The most tiles waiting at once. Past it the layer drops them and asks for a keyframe, which supersedes them all. */
export const MAX_WAITING_TILES = 64;
/** The most inflated pixel bytes waiting at once (4 MiB); past it, the same as `MAX_WAITING_TILES`. */
export const MAX_WAITING_TILE_BYTES = 4 * 1024 * 1024;
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
    // Writing and reading the stream directly skips the Blob and Response wrappers and their extra task hops.
    const inflate = new DecompressionStream("deflate-raw");
    const writer = inflate.writable.getWriter();
    writer.write(update.data).catch(() => {});
    writer.close().catch(() => {});
    const reader = inflate.readable.getReader();
    const pixels = new Uint8ClampedArray(update.pixelBytes);
    let filled = 0;
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      if (filled + value.byteLength > pixels.length) { reader.cancel().catch(() => {}); return undefined; }
      pixels.set(value, filled);
      filled += value.byteLength;
    }
    return filled === update.pixelBytes ? pixels : undefined;
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
  /** Updates not drawn because a newer video picture was accepted. */
  superseded: number;
  /** Updates that had to wait for an older video picture to come out of the decoder first. */
  waited: number;
  /** Updates that could not be read, did not match the canvas, or followed a dropped video unit. */
  dropped: number;
}

/** One accepted tile update, in arrival order. `pixels` is set once it is inflated. */
interface WaitingTile { order: number; update: TileUpdate; pixels?: Uint8ClampedArray; inflatedAt?: number; waited?: boolean }

/**
 * The ordering state of one window's tile lane. The decode worker reports each video unit it accepts, each one that comes
 * out of the decoder (drawn or superseded) and each one it drops, and hands over each tile update with its order number;
 * this class decides when each tile is drawn, or that it never is.
 */
export class TileLayer {
  /** Video units accepted and not yet out of the decoder, by order number. */
  private readonly inFlight = new Set<number>();
  /** Order number of the newest accepted video unit. A tile older than it is superseded. */
  private newestVideo = 0;
  /** Accepted tiles not yet drawn or dropped, oldest first. */
  private waiting: WaitingTile[] = [];
  /** The serial inflate chain. */
  private chain: Promise<void> = Promise.resolve();
  /** Bumped by `reset`, so work queued before it is discarded. */
  private generation = 0;
  readonly stats: TileStats = { received: 0, painted: 0, superseded: 0, waited: 0, dropped: 0 };

  constructor(private readonly surface: TileSurface) {}

  /** A video unit with this order number was accepted and will come out of the decoder later. */
  videoAccepted(order: number): void {
    this.inFlight.add(order);
    this.newestVideo = Math.max(this.newestVideo, order);
  }

  /**
   * The video unit `order` came out of the decoder, drawn or superseded. Older ones are gone too: decoders keep output
   * order. Tiles that were waiting for it are drawn now, in the same task, so no frame shows the picture without them.
   */
  videoRetired(order: number): void {
    for (const value of this.inFlight) if (value <= order) this.inFlight.delete(value);
    this.flush();
  }

  /** The video unit `order` will never come out (dropped before or inside the decoder). Tiles after it are dropped too. */
  videoDropped(order: number): void {
    this.inFlight.delete(order);
    this.dropAfter(order);
  }

  /** Every in-flight video unit will never come out (the decoder was closed). Every waiting tile is dropped. */
  videoForgotten(): void {
    const oldest = Math.min(...this.inFlight);
    this.inFlight.clear();
    if (Number.isFinite(oldest)) this.dropAfter(oldest);
  }

  /** Accepts one tile update with its order number. It is drawn after every earlier unit, never before. */
  accept(order: number, bytes: Uint8Array<ArrayBuffer>): void {
    this.stats.received++;
    const update = parseTileUpdate(bytes);
    if (!update) { this.stats.dropped++; this.surface.repair(); return; }
    const waitingBytes = this.waiting.reduce((sum, tile) => sum + tile.update.pixelBytes, 0);
    if (this.waiting.length >= MAX_WAITING_TILES || waitingBytes + update.pixelBytes > MAX_WAITING_TILE_BYTES) {
      // A keyframe supersedes every waiting tile; until it arrives the canvas keeps a correct older picture.
      this.stats.dropped += this.waiting.length + 1;
      this.waiting = [];
      this.surface.repair();
      return;
    }
    const tile: WaitingTile = { order, update };
    this.waiting.push(tile);
    const generation = this.generation;
    this.chain = this.chain.then(async () => {
      const pixels = await tilePixels(update);
      if (generation !== this.generation) return;
      if (!pixels) { this.stats.dropped++; this.dropAfter(order - 1); this.surface.repair(); return; }
      tile.pixels = pixels;
      tile.inflatedAt = performance.now();
      this.flush();
    });
  }

  /** Resolves once every accepted tile has been inflated (tests and measurement). */
  settled(): Promise<void> { return this.chain; }

  /** Forgets everything: a pause, a re-attach or a closed window. Tiles still inflating are discarded. */
  reset(): void {
    this.generation++;
    this.inFlight.clear();
    this.waiting = [];
    this.newestVideo = 0;
    this.chain = Promise.resolve();
  }

  /** Draws the waiting tiles from the oldest, until one is not inflated yet or an older video unit is still in flight. */
  private flush(): void {
    while (this.waiting.length) {
      const tile = this.waiting[0]!;
      if (tile.order < this.newestVideo) { this.waiting.shift(); this.stats.superseded++; continue; }
      if (!tile.pixels) return;
      if (this.olderVideoInFlight(tile.order)) {
        if (!tile.waited) { tile.waited = true; this.stats.waited++; }
        return;
      }
      this.waiting.shift();
      const size = this.surface.size();
      if (!size || size.width !== tile.update.width || size.height !== tile.update.height) {
        // A picture of another size: this tile cannot belong to what the canvas shows. A keyframe follows any resize.
        this.stats.dropped++;
        continue;
      }
      let offset = 0;
      for (const rect of tile.update.rects) {
        const length = rect.w * rect.h * 4;
        this.surface.draw({ x: rect.x, y: rect.y, image: new ImageData(tile.pixels.slice(offset, offset + length), rect.w, rect.h) });
        offset += length;
      }
      this.stats.painted++;
      this.surface.painted?.(tile.order, tile.inflatedAt!, performance.now());
    }
  }

  /** Drops every waiting tile that arrived after `order`. */
  private dropAfter(order: number): void {
    const kept = this.waiting.filter((tile) => tile.order <= order);
    this.stats.dropped += this.waiting.length - kept.length;
    this.waiting = kept;
    this.flush();
  }

  /** True when a video unit accepted before `order` has not come out of the decoder yet. */
  private olderVideoInFlight(order: number): boolean {
    for (const value of this.inFlight) if (value < order) return true;
    return false;
  }
}
