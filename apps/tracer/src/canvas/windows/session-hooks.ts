/**
 * The small part of the session UI that stays on the canvas's own path (D188): it keeps windows and the sidebar in
 * line with the session inventory, and loads the rest on demand. The manager popover, the final-screen strip and
 * the "Sized for" badge live in `session-ui.on-demand.ts` and are fetched the first time one is needed: someone
 * opens the manager, a window shows an exited session, or a session another device sized comes on screen.
 *
 * - Every inventory change renames and re-shows the windows it concerns (`syncSession`), repaints their
 *   surfaces, rebuilds the tree, and repaints an open manager.
 * - `windowFor` answers "which window shows this session" for the lifecycle, the manager and the sidebar.
 * - `toggleManager` loads the on-demand part, then opens the card; a failed load shows a toast and nothing else.
 */
import { onDemand, whenIdle } from "../../on-demand";
import type { PopoverSource } from "../../../../../packages/ui/src/anchored-popover";
import type { Ctx, WinRec } from "../context";
import { isTerminal } from "../views/body";
import type { SessionUiPart } from "./session-ui.on-demand";

export interface SessionUi {
  /** Brings a window's own surfaces (final-screen strip, size badge, status dot) in line with its session. */
  paint(rec: WinRec): void;
  /** Touch headers omit Sessions; an absent anchor uses the existing window pill. */
  toggleManager(rec: WinRec, anchor: HTMLElement | null | undefined, source: PopoverSource): void;
  closeManager(): void;
  /** A window was pointed at another session: its name slides in and its frame lights up. */
  arrived(rec: WinRec): void;
  /** The window whose session is `id` on `host`, in any view. */
  windowFor(host: string, id: string): WinRec | undefined;
  dispose(): void;
}

/** Match the frame's existing manager eligibility independently of its touch header. */
function canManage(rec: WinRec): boolean {
  return isTerminal(rec) && !rec.model.noAccess && !rec.owner.view.team;
}

export function createSessionHooks(cx: Ctx): SessionUi {
  const inventory = cx.adapters.inventory!;
  let part: SessionUiPart | undefined;
  let loading: Promise<SessionUiPart | undefined> | undefined;
  const load = (): Promise<SessionUiPart | undefined> => {
    loading ??= onDemand(() => import("./session-ui.on-demand")).then((m) => { part = m.createSessionUi(cx); return part; })
      .catch(() => { loading = undefined; cx.toast.show({ message: "Could not load the session list. Try again.", tone: "error", duration: 5000 }); return undefined; });
    return loading;
  };
  // Warm the manager's code once the page is idle, so the first open never waits for a download (#128).
  whenIdle(() => { void load(); });
  const windows = (): WinRec[] => [...cx.views.values()].flatMap((c) => [...c.wins.values()]);
  const windowFor = (host: string, id: string): WinRec | undefined => windows().find((w) => isTerminal(w) && w.model.host === host && w.model.sessionId === id);

  /** A window needs the on-demand surfaces only for an exited session or one sized elsewhere. */
  const needsSurfaces = (rec: WinRec): boolean => {
    const s = rec.model.sessionId ? inventory.get(rec.model.host, rec.model.sessionId) : undefined;
    return Boolean(s && (s.state === "exited" || inventory.sizedFor(rec.model.host, s.id)));
  };
  const paint = (rec: WinRec): void => {
    if (!isTerminal(rec)) return;
    if (part) part.paint(rec);
    else if (needsSurfaces(rec)) void load().then((p) => { if (p && rec.card.root.isConnected) p.paint(rec); });
  };

  const off = inventory.onChange(() => {
    if (cx.signal.aborted) return;
    for (const rec of windows()) if (isTerminal(rec)) { cx.win.syncSession(rec); paint(rec); }
    cx.tree.render();
    // The Console count leaves out sessions that ended. Inventory changes come after setup, so the pill exists.
    cx.pill.paint();
    part?.render();
  });
  cx.signal.addEventListener("abort", () => off(), { once: true });

  return {
    paint,
    toggleManager(rec, anchor, source) {
      if (!canManage(rec)) return;
      // Keep all manager entry points usable when the touch header has only Close.
      const resolvedAnchor = anchor ?? rec.card.pill;
      if (part) { part.toggleManager(rec, resolvedAnchor, source); return; }
      void load().then((p) => { if (p && resolvedAnchor.isConnected && canManage(rec)) p.toggleManager(rec, resolvedAnchor, source); });
    },
    closeManager() { part?.closeManager(); },
    arrived(rec) { part?.arrived(rec); },
    windowFor,
    dispose() { off(); part?.dispose(); },
  };
}
