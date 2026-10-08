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

export type ActivityTag = "none" | "pan" | "zoom" | "flight" | "drag" | "scroll" | "typing" | "output" | "split" | "sidebar";

const HISTORY = 16;
const tags: ActivityTag[] = new Array<ActivityTag>(HISTORY).fill("none");
const starts = new Float64Array(HISTORY);
const untils = new Float64Array(HISTORY);
let head = 0;
let count = 1;
untils[0] = Infinity;

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
export function setPerfProbe(next: PerfProbe | undefined): void { probe = next; }
export function readPerfProbe(): Record<string, string | number | boolean> {
  try { return probe?.() ?? {}; } catch { return {}; }
}
