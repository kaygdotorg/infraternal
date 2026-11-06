/**
 * The small part of the session UI that stays on the canvas's own path (D188): it keeps windows and the sidebar in
 * line with the session inventory, and loads the rest on demand. The manager popover, the final-screen strip and
 * the "Sized for" badge live in `session-ui.on-demand.ts` and are fetched the first time one is needed: someone
 * opens the manager, a window shows an exited session, or a session another device sized comes on screen.
 *
 * - Every inventory change renames and re-shows the windows it concerns (`syncSession`), repaints their
 *   surfaces, rebuilds the tree, and repaints an open manager.
 * - `windowFor` answers "which window shows this session" for the lifecycle, the manager and the sidebar.
 * - `toggleManager` loads the on-demand part, then opens the card; a failed load shows a toast and nothing else. The idle warm-up that
 *   fetches the same code fails silently (#249).
 */
import { onDemand, whenIdle } from "../../on-demand";
import type { PopoverSource } from "../../../../../packages/ui/src/anchored-popover";
import type { Ctx, WinRec } from "../context";
import { isTerminal } from "../views/body";
import type { SessionUiPart } from "./session-ui.on-demand";
import type { RefusalAction } from "../../terminal-refusal";

/** What the rest of the canvas asks of the session surfaces: repaint a window, open the manager, say a window was refused or cannot connect. */
export interface SessionUi {
  /** Brings a window's own surfaces (final-screen strip, size badge, status dot) in line with its session. */
  paint(rec: WinRec): void;
  /** Touch headers omit Sessions; an absent anchor uses the existing window pill. */
  toggleManager(rec: WinRec, anchor: HTMLElement | null | undefined, source: PopoverSource): void;
  closeManager(): void;
  /** A window was pointed at another session: its name slides in and its frame lights up. */
  arrived(rec: WinRec): void;
  /** The host refused a window's shell: its strip says why. False when no strip claims it (the caller shows a toast). */
  refused(rec: WinRec, message: string, action?: RefusalAction): boolean;
  /** A window has been connecting too long (`message`), or connects again (undefined): its strip says so. */
  unreachable(rec: WinRec, message: string | undefined): void;
  /** The window whose session is `id` on `host`, in any view. */
  windowFor(host: string, id: string): WinRec | undefined;
  dispose(): void;
}

/** Match the frame's existing manager eligibility independently of its touch header. */
function canManage(rec: WinRec): boolean {
  return isTerminal(rec) && !rec.model.noAccess && !rec.owner.view.team;
}

/** Makes the always-loaded part of the session surfaces; it loads the on-demand strip and manager the first time one is needed. */
export function createSessionHooks(cx: Ctx): SessionUi {
  const inventory = cx.adapters.inventory!;
  let part: SessionUiPart | undefined;
  let loading: Promise<SessionUiPart | undefined> | undefined;
  // A failed load clears `loading` so the next call tries again. It stays quiet: whether to tell the person is the
  // caller's choice, because the idle warm-up below is not something they asked for.
  const load = (): Promise<SessionUiPart | undefined> => {
    loading ??= onDemand(() => import("./session-ui.on-demand")).then((m) => { part = m.createSessionUi(cx); return part; })
      .catch(() => { loading = undefined; return undefined; });
    return loading;
  };
  /** A load someone is waiting on (an open manager, a window that needs its surfaces): a failure gets a toast. */
  const loadForUser = (): Promise<SessionUiPart | undefined> => load().then((p) => {
    if (!p) cx.toast.show({ message: "Could not load the session list. Try again.", tone: "error", duration: 5000 });
    return p;
  });
  // Warm the manager's code once the page is idle, so the first open never waits for a download (#128). Nobody asked
  // for it, so a failure (often a network that is reconnecting) shows nothing; it tries once more when the browser
  // is back online, and a real open retries on its own.
  whenIdle(() => {
    void load().then((p) => {
      if (!p && !cx.signal.aborted) window.addEventListener("online", () => { void load(); }, { once: true, signal: cx.signal });
    });
  });
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
    else if (needsSurfaces(rec)) void loadForUser().then((p) => { if (p && rec.card.root.isConnected) p.paint(rec); });
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
      void loadForUser().then((p) => { if (p && resolvedAnchor.isConnected && canManage(rec)) p.toggleManager(rec, resolvedAnchor, source); });
    },
    closeManager() { part?.closeManager(); },
    arrived(rec) { part?.arrived(rec); },
    refused(rec, message, action) {
      if (part) return part.refused(rec, message, action);
      // The strip's code is not here yet: a window with no session claims its refusal now and shows it once the code
      // arrives. If it cannot load, the refusal still reaches the person, as a toast, rather than being lost.
      if (rec.model.sessionId) return false;
      void load().then((p) => {
        if (p) p.refused(rec, message, action);
        else cx.toast.show({ message, tone: "error", duration: Math.max(4200, message.length * 70) });
      });
      return true;
    },
    unreachable(rec, message) {
      if (part) { part.unreachable(rec, message); return; }
      if (message === undefined) return;
      // Only show it if the window is still waiting when the code arrives.
      void load().then((p) => { if (p && rec.binding?.connected === false && rec.card.root.isConnected) p.unreachable(rec, message); });
    },
    windowFor,
    dispose() { off(); part?.dispose(); },
  };
}
