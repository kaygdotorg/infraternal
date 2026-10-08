// SPDX-License-Identifier: AGPL-3.0-only
/**
 * The canvas's flow host: the wizard lives in a window of kind `flow` (TASTE: a flow is a card inside a window,
 * not a layer over the page). The window opens next to the focused one through the same window frame as every
 * other window, can be moved and closed like one, and is never saved to the canvas document (D180).
 */
import type { Ctx } from "../context";
import type { FlowHost } from "./flow-host";

/** `cx` is read when the flow opens: the canvas does not exist yet when the host is made. */
export function createWindowFlowHost(cxOf: () => Ctx, fallback: FlowHost): FlowHost {
  return {
    open(options) {
      const cx = cxOf();
      const rec = cx.win.openFlow(options.title);
      // No tiled view to put a window in: draw over the stage instead of failing.
      if (!rec) return fallback.open(options);
      let gone: (() => void) | undefined;
      let closed = false;
      rec.cleanup = () => { if (closed) return; closed = true; gone?.(); };
      return {
        body: rec.card.body,
        remove() { if (closed) return; closed = true; cx.win.close(rec); },
        onGone(callback) { gone = callback; },
      };
    },
  };
}
