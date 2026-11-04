/**
 * The frame-interval detector behind the frame meter (issue #116). Pure: no DOM, no timers, so it is unit-tested and
 * so the per-frame path is exactly what is written here.
 *
 * Per frame, `frame(t)` does three things and nothing else: it writes the interval into a preallocated ring,
 * advances a counter and compares the interval with one number. It never allocates and never reads or writes the
 * DOM. Everything that costs something (the display-rate estimate, the readout, the sparkline, the "why") runs off
 * this path: at four hertz from a timer, or only when a frame was actually late.
 *
 * Definitions (the owner's words, #116): a *drop* is a frame interval longer than 1.5 times the display's refresh
 * interval; a *freeze* is one longer than 100 ms. The refresh rate is not asked of the browser (which cannot tell a
 * 120 Hz panel from a 60 Hz one that is being slow): it is the median recent interval, snapped to a common rate,
 * and it only ever goes up within a session, so a page that gets slow is not mistaken for a slower display.
 */

/** Intervals kept: about 8 s at 120 Hz. A power of two so the index wraps with a mask. */
export const RING = 1024;
/** Wraps a counter into the ring. */
const MASK = RING - 1;
/** Common display rates the median interval is snapped to. 30 is the iOS low-power cap. */
const RATES = [30, 60, 90, 120, 144, 165, 240];
/** Frames to see before a rate is trusted (nothing is called a drop before it). */
const WARMUP = 30;

/** An interval longer than this is a freeze. */
export const FREEZE_MS = 100;
/**
 * A browser throttles the frames of a page it considers hidden to about one a second (Chrome does it for a window
 * another window covers, while `visibilityState` still says "visible"). Those intervals are not stalls, so an interval
 * this long that is part of a run of two or more is a throttled page: it is neither a drop nor a freeze.
 */
export const THROTTLE_MS = 400;
/** An interval longer than this multiple of the refresh interval is a drop. */
export const DROP_FACTOR = 1.5;

/** The verdict of one frame: {@link OK}, {@link DROP} or {@link FREEZE}. */
export type FrameVerdict = 0 | 1 | 2;
/** The three verdict values. */
export const OK = 0, DROP = 1, FREEZE = 2;

/**
 * Classifies frame intervals as on time, dropped or frozen. Feed it the timestamp of every animation frame with
 * `frame(t)`; call `estimate()` a few times a second so it knows the display rate; read the rest for the readout.
 */
export class FrameDetector {
  /** The last 1024 frame intervals in milliseconds. */
  readonly ring = new Float32Array(RING);
  /** Intervals written so far (the ring index of the next one is `n & MASK`). */
  n = 0;
  /** Estimated display refresh in Hz; 0 until warm. */
  refresh = 0;
  /** The previous frame's timestamp; 0 when there is none yet. */
  private last = 0;
  /** Consecutive intervals of at least THROTTLE_MS. */
  private longRun = 0;
  /** The interval (ms) above which a frame is a drop; infinity until the display rate is known. */
  private dropAt = Infinity;
  /** Reused buffer for sorting, so the median and percentile calls allocate nothing. */
  private readonly scratch = new Float32Array(RING);

  /** One frame callback's timestamp. Returns 0 when on time, 1 for a drop, 2 for a freeze. */
  frame(t: number): FrameVerdict {
    const prev = this.last;
    this.last = t;
    if (prev === 0) return OK;
    const dt = t - prev;
    this.ring[this.n & MASK] = dt;
    this.n++;
    // Throttle handling costs one compare per frame on the normal path (dt is short).
    if (dt >= THROTTLE_MS) this.longRun++;
    else if (this.longRun > 0) {
      const wasThrottled = this.longRun >= 2;
      this.longRun = 0;
      // The first frame after a throttled run is the page coming back, not a late frame.
      if (wasThrottled) return OK;
    }
    if (this.longRun >= 2) return OK;
    return dt > FREEZE_MS ? FREEZE : dt > this.dropAt ? DROP : OK;
  }

  /**
   * Whether the interval at ring index `index` belongs to a run of two or more throttled-length intervals. The first
   * long interval of a run is reported by `frame` before the run is known; the recorder asks this afterwards.
   */
  inLongRun(index: number): boolean {
    const long = (i: number): boolean => i >= 0 && i >= this.n - RING && i < this.n && this.ring[i & MASK]! >= THROTTLE_MS;
    return long(index) && (long(index - 1) || long(index + 1));
  }

  /** Forget the previous timestamp (the page was hidden: the next interval would be the time away, not a frame). */
  resume(): void { this.last = 0; this.longRun = 0; }

  /** The interval written `back` frames ago (0 is the newest); NaN when there is none. */
  at(back: number): number {
    return back < this.n && back < RING ? this.ring[(this.n - 1 - back) & MASK]! : NaN;
  }

  /** Re-estimates the display refresh from the recent median. Call at a few hertz, not per frame. */
  estimate(): void {
    const count = Math.min(this.n, 240);
    if (count < WARMUP) return;
    const s = this.scratch.subarray(0, count);
    for (let i = 0; i < count; i++) s[i] = this.at(i);
    s.sort();
    const median = s[count >> 1]!;
    if (!(median > 0)) return;
    const hz = 1000 / median;
    let best = RATES[0]!, bestError = Infinity;
    for (const rate of RATES) {
      const error = Math.abs(Math.log(hz / rate));
      if (error < bestError) { bestError = error; best = rate; }
    }
    if (best > this.refresh) { this.refresh = best; this.dropAt = (1000 / best) * DROP_FACTOR; }
  }

  /** Frames per second over the last `windowMs` of frames (the readout). */
  fps(windowMs = 1000): number {
    let total = 0, frames = 0;
    for (let i = 0; i < RING && i < this.n && total < windowMs; i++) { total += this.at(i); frames++; }
    return total > 0 ? (frames * 1000) / total : 0;
  }

  /** The 95th percentile interval over the last `count` frames (ms). */
  p95(count = 600): number {
    const m = Math.min(this.n, count, RING);
    if (m < 2) return 0;
    const s = this.scratch.subarray(0, m);
    for (let i = 0; i < m; i++) s[i] = this.at(i);
    s.sort();
    return s[Math.min(m - 1, Math.floor(m * 0.95))]!;
  }

  /** Intervals `from` frames before index `index` up to `to` frames after it (a copy; used when an incident is recorded). */
  window(index: number, before: number, after: number): number[] {
    const out: number[] = [];
    for (let i = Math.max(this.n - RING, index - before); i <= Math.min(this.n - 1, index + after); i++) out.push(Math.round(this.ring[i & MASK]! * 10) / 10);
    return out;
  }
}
