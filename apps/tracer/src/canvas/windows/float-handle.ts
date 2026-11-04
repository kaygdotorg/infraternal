/**
 * The floating terminal's handle: what the rest of the canvas holds. The module behind it (`float.on-demand.ts`) loads
 * the first time a window is floated, so it costs no transfer until a person uses it (D188). Until then nothing is
 * open, so the queries answer from the empty state and close/expand have nothing to do.
 */
import { onDemand } from "../../on-demand";
import type { Ctx } from "../context";
import type { FloatModule } from "./float.on-demand";

/**
 * Makes the stand-in for the floating terminal. `open` loads the real module first (once) and then opens; the other methods answer
 * from the empty state (`isOpen` false, `info` and `close` nothing) until it has loaded.
 */
export function createFloatHandle(cx: Ctx): FloatModule {
  let real: FloatModule | undefined;
  let loading: Promise<FloatModule> | undefined;
  const load = (): Promise<FloatModule> => loading ??= onDemand(() => import("./float.on-demand")).then((m) => (real = m.createFloat(cx)));
  return {
    open: (rec) => { void load().then((f) => f.open(rec)); },
    close: (instant) => real?.close(instant),
    expand: () => real?.expand(),
    isOpen: () => real?.isOpen() ?? false,
    info: () => real?.info(),
    dispose: () => real?.dispose(),
  };
}
