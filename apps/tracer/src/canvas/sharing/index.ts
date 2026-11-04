/** The sharing handle stays with the canvas; the dialog and incoming-share work load on first use. */
import { onDemand } from "../../on-demand";
import type { Ctx } from "../context";
import type { IncomingShare, SharingAdapter } from "./adapter";
import type { SharingController, SharingModule } from "./sharing.on-demand";

/** The sharing actions the canvas calls, re-exported so callers need not import the on-demand module. */
export type { SharingModule } from "./sharing.on-demand";

/**
 * Makes the small sharing handle that stays with the canvas. The real sharing code loads when the first share arrives or the person starts
 * to share; a failed load shows an error toast and is tried again by the next action. The newest incoming snapshot is held until then.
 */
export function createSharingHandle(cx: Ctx, adapter: SharingAdapter): SharingModule {
  let real: SharingController | undefined;
  let loading: Promise<SharingController | undefined> | undefined;
  // The adapter publishes its full inbox on every update, so the newest snapshot is enough during the import.
  let latest: IncomingShare[] | undefined;
  let disposed = false;
  const load = (): Promise<SharingController | undefined> => loading ??= onDemand(() => import("./sharing.on-demand")).then((m) => {
    if (disposed) return undefined;
    real = m.createSharing(cx, adapter);
    if (latest !== undefined) real.receive(latest);
    // A linked view may have painted before the lazy unlink control existed.
    real.paintUnlink();
    return real;
  }).catch(() => {
    // Clear the rejected promise so the next share action retries the chunk request.
    loading = undefined;
    cx.toast.show({ message: "Could not load sharing. Try again.", tone: "error" });
    return undefined;
  });
  const off = adapter.subscribe((shares) => {
    latest = shares;
    if (real) real.receive(shares);
    else if (shares.length) void load();
  });
  return {
    open: async (preselect) => { await (await load())?.open(preselect); },
    unlinkCurrent: () => { if (real) real.unlinkCurrent(); else void load().then((s) => s?.unlinkCurrent()); },
    paintUnlink() {
      if (real) real.paintUnlink();
      else if (cx.views.get(cx.state.currentView)?.view.team) void load().then((s) => s?.paintUnlink());
    },
    reset() { latest = undefined; real?.reset(); },
    schedulePublish(c) {
      if (real) real.schedulePublish(c);
      else if (c.view.published) void load().then((s) => s?.schedulePublish(c));
    },
    dispose() { disposed = true; off(); real?.dispose(); },
  };
}
