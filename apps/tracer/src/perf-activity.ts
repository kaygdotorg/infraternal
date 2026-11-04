/**
 * What the app is doing right now, as one cheap tag (issue #116). The frame meter (`perf-hud.on-demand.ts`) reads it
 * when a frame drops, to say what the person was doing; nothing else uses it.
 *
 * Existing gesture, animation and output code sets the tag. A setter costs a string compare and, only when the tag
 * changes, a write into a 16-entry history; it never allocates, never touches the DOM and never reads layout. The
 * history is what makes the answer right after the fact: a camera that came to rest 140 ms after a pan has already
 * moved the tag back to "none" by the time the meter looks, so the meter asks what was active *during the slow
 * frame* (`activityIn`), not what is active now.
 *
 * Two kinds of tag:
 * - sustained (`setActivity`, ended by `endActivity`): a pan, a zoom, a flight, a drag; they have a clear start
 *   and end in the code that sets them;
 * - pulsed (`pulseActivity`): typing, terminal output, a split, the sidebar sliding; the tag lasts `ms` after the
 *   last pulse, so the caller never needs an end hook.
 *
 * This module sits in the app's own chunk and must stay tiny: it is loaded by the first screen. The meter itself is
 * an on-demand chunk (preview builds only).
 */

/** What the app was doing: one tag per kind of work. `none` means idle. */
export type ActivityTag = "none" | "pan" | "zoom" | "flight" | "drag" | "scroll" | "typing" | "output" | "split" | "sidebar";

/** How many tag changes are remembered. */
const HISTORY = 16;
/** The history as a ring: the tag of each entry. `starts` and `untils` hold when it began and when it ends (`Infinity` while open). */
const tags: ActivityTag[] = new Array<ActivityTag>(HISTORY).fill("none");
const starts = new Float64Array(HISTORY);
const untils = new Float64Array(HISTORY);
/** The ring index of the newest entry. */
let head = 0;
/** How many entries of the ring are in use. */
let count = 1;
untils[0] = Infinity;

/** Adds a history entry for `tag` beginning now and ending at `until` (a `performance.now` time). */
function push(tag: ActivityTag, until: number): void {
  head = (head + 1) % HISTORY;
  tags[head] = tag;
  starts[head] = performance.now();
  untils[head] = until;
  if (count < HISTORY) count++;
}

/** Starts a sustained activity (ends with `endActivity`). Setting the tag that is already set costs one compare. */
export function setActivity(tag: ActivityTag): void {
  if (tags[head] === tag && untils[head] === Infinity) return;
  push(tag, Infinity);
}

/** Ends a sustained activity, unless another one has replaced it meanwhile. */
export function endActivity(tag: ActivityTag): void {
  if (tags[head] === tag) push("none", Infinity);
}

/** Marks `tag` active for `ms` after now; repeated pulses of the same tag extend one entry. */
export function pulseActivity(tag: ActivityTag, ms: number): void {
  const now = performance.now();
  if (tags[head] === tag && untils[head]! >= now) { untils[head] = now + ms; return; }
  push(tag, now + ms);
}

/** The newest activity that overlapped `[t0, t1]` (performance.now times), or "none". */
export function activityIn(t0: number, t1: number): ActivityTag {
  for (let n = 0; n < count; n++) {
    const i = (head - n + HISTORY) % HISTORY;
    if (tags[i] === "none") continue;
    const end = Math.min(untils[i]!, n === 0 ? Infinity : starts[(i + 1) % HISTORY]!);
    if (starts[i]! <= t1 && end >= t0) return tags[i]!;
  }
  return "none";
}

/** Facts about the canvas only it knows (view, zoom, window counts), read by the meter at drop time. */
export type PerfProbe = () => Record<string, string | number | boolean>;
let probe: PerfProbe | undefined;
/** Installs the function that reports the canvas's facts (or removes it with `undefined`). */
export function setPerfProbe(next: PerfProbe | undefined): void { probe = next; }
/** The probe's facts, or an empty object when none is installed or it throws. */
export function readPerfProbe(): Record<string, string | number | boolean> {
  try { return probe?.() ?? {}; } catch { return {}; }
}

/**
 * WebSocket traffic in 100 ms buckets (a ring of 16, so the last 1.6 s), for the meter's question "did a burst of
 * messages arrive just before the stall?". One clock read and three typed-array writes per message; no allocation.
 */
const WS_BUCKETS = 16;
/** Message counts per 100 ms bucket; `wsBytes` is the byte total and `wsStamp` the bucket number each slot currently holds (-1 when unused). */
const wsMsgs = new Uint32Array(WS_BUCKETS);
const wsBytes = new Float64Array(WS_BUCKETS);
const wsStamp = new Float64Array(WS_BUCKETS).fill(-1);
/** Records one received WebSocket message of `bytes` bytes in the current 100 ms bucket. */
export function noteWsMessage(bytes: number): void {
  const bucket = Math.floor(performance.now() / 100);
  const i = bucket % WS_BUCKETS;
  if (wsStamp[i] !== bucket) { wsStamp[i] = bucket; wsMsgs[i] = 0; wsBytes[i] = 0; }
  wsMsgs[i]!++;
  wsBytes[i]! += bytes;
}
/** Messages and bytes that arrived in the buckets overlapping `[t0, t1]` (performance.now times, at most 1.6 s back). */
export function wsBetween(t0: number, t1: number): { msgs: number; bytes: number } {
  let msgs = 0, bytes = 0;
  const lo = Math.floor(t0 / 100), hi = Math.floor(t1 / 100);
  for (let i = 0; i < WS_BUCKETS; i++) {
    const b = wsStamp[i]!;
    if (b >= lo && b <= hi) { msgs += wsMsgs[i]!; bytes += wsBytes[i]!; }
  }
  return { msgs, bytes };
}
