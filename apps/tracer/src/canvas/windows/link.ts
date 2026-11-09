/**
 * What a terminal window's connection indicator shows (#212, approved 2026-11-01): one icon per window, in the machine pill's
 * place, with a warm sentence in the shared tooltip. This is the one place that decides it, from what the window's binding
 * knows, so the pill and the sentence can never disagree.
 *
 *   connected     a calm green dot                            (slow: amber, from the page's round trip, in window-card.ts)
 *   connecting    an arc turning: the first attach
 *   reconnecting  the same arc: the link was lost and is being resumed; typed keys are kept, and a small amber key says how many
 *   resumed       a tick for a moment: back, exactly where it was left
 *   approximate   a screen for a moment: back, the picture was rebuilt, a little scrollback may be approximate
 *   stale         a screen with an amber badge: the replayed screen may be out of date (D309); it takes the place of
 *                 connected, resumed and approximate while the link is up, and a lost link or an ended session replaces it
 *   offline       a slashed ring: the session ended, or the host refused to open one; the sentence says which
 *
 * Moments (resumed, approximate) are told by when they happened: the indicator settles back to "connected" by itself, and a
 * repaint after that moment sees none. What was typed while the link was down is never shown, only how many keys are kept:
 * a password typed into a hidden prompt must not appear on screen.
 */
import type { ConnectionIndicatorState } from "../../../../../packages/ui/src/connection-indicator";
import type { WindowStatus } from "../../../../../packages/ui/src/window-card";
import type { SessionBinding } from "../sessions/adapter";
import type { WinRec } from "../context";

/** How long a moment stays (connection-indicator.ts settles "resumed" after 1.8 s and "approximate" after 3.2 s). */
const RESUMED_MS = 1800;
/** How long the "approximate" moment shows (see `RESUMED_MS`). */
const APPROXIMATE_MS = 3200;

/** What a window's connection indicator shows: the status dot, the indicator state, an optional sentence for offline, and the number of kept keys. */
export interface LinkView {
  status: WindowStatus;
  state: ConnectionIndicatorState;
  /** A plain sentence shown after "Offline.". */
  detail?: string;
  /** Keys kept to be sent. */
  held: number;
  /** The screen may be out of date (D309): the machine pill shows its icon. Only while the link is up; a lost link replaces the question. */
  stale: boolean;
}

/** What the indicator is decided from. `now` is a `performance.now()` time, used to end the short "resumed" and "approximate" moments. */
export interface LinkInput {
  binding: Pick<SessionBinding, "connected" | "link"> | undefined;
  /** The window's session has ended. */
  ended: boolean;
  /** The host refused to open a shell; the refusal's own words. */
  refusal: string | undefined;
  now: number;
}

/**
 * Decides the indicator. Order: an ended session or a refusal is offline; a binding that is not connected is connecting (the first
 * attach) or reconnecting (it was connected before) with the count of kept keys; then the two short moments; else connected.
 */
export function linkView(input: LinkInput): LinkView {
  if (input.ended) return { status: "offline", state: "offline", detail: "This session has ended.", held: 0, stale: false };
  if (input.refusal !== undefined) return { status: "offline", state: "offline", detail: input.refusal, held: 0, stale: false };
  const link = input.binding?.link;
  if (input.binding?.connected === false) {
    return { status: "connecting", state: link?.everConnected ? "reconnecting" : "connecting", held: link?.heldKeys ?? 0, stale: false };
  }
  if (link?.approximateAt !== undefined && input.now - link.approximateAt < APPROXIMATE_MS) return { status: "live", state: "approximate", held: 0, stale: link.staleScreen };
  if (link?.resumedAt !== undefined && input.now - link.resumedAt < RESUMED_MS) return { status: "live", state: "resumed", held: 0, stale: link.staleScreen };
  return { status: "live", state: "connected", held: 0, stale: link?.staleScreen === true };
}

/** Paints a terminal window's status and its indicator from its binding. */
export function paintLink(rec: WinRec, ended: boolean, refusal: string | undefined): void {
  const view = linkView({ binding: rec.binding, ended, refusal, now: performance.now() });
  rec.card.setStatus(view.status);
  rec.card.setConnection(view.state, view.detail, view.held);
  rec.card.setStale(view.stale);
}
