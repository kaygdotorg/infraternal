/**
 * The handle on the split module (`split.on-demand.ts`, D188, #322). Splitting a window and opening one beside it are
 * actions, not part of the first screen, so their code is its own chunk.
 *
 * - `splitReady()` is the module's instance once it has loaded, or undefined: the caller then starts at once, in the same
 *   task, so a keyboard split lands in the frame it was pressed in.
 * - `loadSplit(cx)` fetches it (the first time; afterwards the same instance). A failed fetch is forgotten so the next
 *   press tries again.
 * - `warmSplit(cx)` fetches it when the browser is idle after the canvas is up, so the first split does not wait.
 */
import { onDemand, whenIdle } from "../../on-demand";
import type { Ctx } from "../context";
import type { SplitModule } from "./split.on-demand";

/** A busy page may delay an idle callback; it still runs within this long, so a first split is not left waiting for a fetch that never started. */
const WARM_WITHIN_MS = 1000;

/** The split module's instance once loaded; `undefined` until then. */
let ready: SplitModule | undefined;
/** The load in progress or finished; cleared when it fails, so the next press tries again. */
let loading: Promise<SplitModule> | undefined;

/** The split module if it has loaded, else `undefined` (the caller then starts in the same task). */
export const splitReady = (): SplitModule | undefined => ready;
/** Loads the split module (once) and makes it for `cx`. A failed load is forgotten, so a later call tries again. */
export const loadSplit = (cx: Ctx): Promise<SplitModule> =>
  loading ??= onDemand(() => import("./split.on-demand")).then((m) => (ready = m.createSplit(cx)), (e: unknown) => { loading = undefined; throw e; });
/** Loads the split module when the browser is idle (within one second at the most), ignoring a failure. */
export const warmSplit = (cx: Ctx): void => whenIdle(() => { void loadSplit(cx).catch(() => undefined); }, WARM_WITHIN_MS);
