/**
 * The window lifecycle: open a window beside the others, close one, split one (D178, D183).
 *
 * - Opening adds a window in a new column at the end of the Console view; the others glide aside (FLIP).
 * - Closing never ends the session (D178): the binding is disposed, the session keeps running, detached. What
 *   remains in the column takes the freed height; an emptied column goes and its neighbours close the gap, all as
 *   one FLIP; the camera re-snaps to the nearest stop that still exists. A window in a group re-tiles through the grid
 *   (layout/grid.ts), which gives back exactly what its split took.
 * - Four actions (D212). A split divides the window's own space: `down` halves its height, `right` halves its width.
 *   Split right in a stacked column makes a group: the window's column halves and the windows around it span both
 *   halves, so nothing else moves (layout/grid.ts holds the rules). A new window opens a full-size window beside it
 *   (`right`, after its whole group) or under it (`below`, which grows the column). Every action opens a new shell on
 *   the same host, no prompt. Splits play the droplet in their direction and the other windows glide (FLIP) on a mouse
 *   action. Keyboard actions are instant. Splits are windows in the one structure: no nesting.
 *
 * Every layout change measures, changes, then plays (layout/flip.ts); the terminal refits once at the new size.
 */
import { randomUuid } from "../../identifiers";
import { Spring } from "../../../../../packages/ui/src/spring";
import { triggeredByKeyboard } from "../../../../../packages/ui/src/input-source";
import type { HostPlatform } from "../../../../../packages/ui/src/host-icons";
import { clamp } from "../camera/camera";
import type { Ctx, ViewRec, WinRec } from "../context";
import { COLUMN_GAP } from "../layout/geometry";
import { columnEls, freshColumnId, topItem } from "../layout/columns";
import { groupsLoaded, inGroup } from "../layout/groups-handle";
import { setColumnWidth } from "../layout/column-els";
import type { ViewId, WindowModel } from "../model/types";
import { coarse, reduced } from "../dom";
import { makeWindow, setActive } from "./frame";
import { loadSplit, splitReady } from "./split-handle";
import { iconFor } from "../views/icons";
import { isTerminal, makeBody } from "../views/body";
import { SCALE_REST, restAt } from "../springs";
import { EASE_OUT } from "../../../../../packages/ui/src/motion";

/** The window lifecycle API of the canvas: make, open, close, split, step. Each member is described on its own line. */
export interface WindowsModule {
  /** Builds the window for model `m`, owned by view `c`, and returns its record. To add a window to a tiled view use `addColumn`. */
  make(c: ViewRec, m: WindowModel): WinRec;
  /** Makes `rec` the active window, or none for `undefined`. */
  setActive(rec: WinRec | undefined): void;
  /** Adds a window in a new column at `index` of a tiled view; the others glide aside. */
  addColumn(c: ViewRec, m: WindowModel, index: number, w?: number, silent?: boolean, opaque?: boolean): WinRec;
  /** Immediate closure uses the same cleanup when a feature withdraws its windows. */
  close(rec: WinRec, instant?: boolean): void;
  /**
   * The keyboard close (D212 shortcuts): the window closes at once, with no motion, through the same path as the close
   * button (its session keeps running, detached). Focus and the active window move to the next window in reading order
   * first, so the next press closes the next one.
   */
  closeKey(rec: WinRec): void;
  /**
   * Divides a terminal window's own space into two windows (D212): `down` halves its height, `right` halves its
   * width. A new shell takes the other half. Works in a stacked column too: the windows around it span the new half.
   * Started by a key (its chord or a palette row) it has no motion at all: the layout and the focus land in the same frame.
   */
  split(rec: WinRec, direction: "down" | "right"): Promise<boolean>;
  /**
   * Opens a new full-size window next to a terminal window (D212): `right` in a new column of the same width, `below`
   * under it, which grows the column and leaves the others as they were. Opening never divides anything. With
   * `session`, the window shows that existing session of the host (the session manager's "beside") instead of a shell.
   */
  newWindow(rec: WinRec, side: "right" | "below", session?: string): Promise<void>;
  /** Points a terminal window at another session of its host; the old one keeps running (detached). */
  attach(rec: WinRec, sessionId: string): void;
  /** Brings a window's name and screen in line with its session in the inventory (a rename, a run again). */
  syncSession(rec: WinRec, reshow?: boolean): void;
  /**
   * The host's identity became known or changed (the host list, an add, the embedded host's facts): every open terminal of
   * that host takes the system's mark and the shell's account at once, in place and without animation. `hostId` names a
   * remote host; without it `host` names the embedded one. A key left out is left alone; `user: undefined` clears the account.
   */
  setHostIdentity(target: { host: string; hostId?: string }, identity: { os?: HostPlatform; user?: string | undefined }): void;
  /** Shows a session: flies to its window, or opens one (a detached or exited session) in Console. */
  openSession(host: string, sessionId: string): WinRec | undefined;
  /** Opens a shell on `host` as a window in Console (or flies to the one that is already there). */
  open(host: string, container?: string): WinRec | undefined;
  /**
   * Opens a flow window (a short guided task) in a new column right after the focused window's, in the view that
   * has focus (Console when none does). It is never saved. The caller fills `rec.card.body`, may set
   * `rec.cleanup` to hear that the window closed, and closes it with `close` when the task is done.
   */
  openFlow(title: string): WinRec | undefined;
  /** Scales the window up a little and back: "this is the one". */
  pulse(rec: WinRec): void;
  /** Every window of the current view in reading order (column by column, top to bottom). */
  flat(): WinRec[];
  /** Makes the next (1) or previous (-1) window of the current view active and brings it into view. */
  step(dir: number): void;
  /**
   * Makes the nearest window of the current view in a direction active and brings it into view (D222: ⌥⌘ arrows on a
   * Mac, Ctrl+Shift+arrows elsewhere). "Nearest" weighs distance along the direction twice as much as sideways offset,
   * so a window straight above or below beats one further along but offset. Nothing happens when no window lies that way.
   */
  move(dir: "left" | "right" | "up" | "down"): void;
}

/** Makes the lifecycle for the canvas `cx`. */
export function createWindows(cx: Ctx): WindowsModule {
  const { camera, state, views, flip } = cx;

  /** `opaque`: the window's content is there from the first frame (a session already exists); only its size springs. */
  const enterAnimation = (rec: WinRec, opaque = false): void => {
    if (reduced.matches) { rec.card.root.animate([{ opacity: 0 }, { opacity: 1 }], { duration: 160 }); return; }
    const root = rec.card.root;
    const spring = new Spring(1, (p) => {
      if (p === 0) { root.style.transform = ""; root.style.opacity = ""; root.style.transformOrigin = ""; return; }
      root.style.transformOrigin = "0 50%";
      root.style.transform = `scale(${1 - 0.06 * p})`;
      root.style.opacity = opaque ? "" : String(clamp(1 - p * 1.4, 0, 1));
      cx.invalidate();
    }, { visualDuration: 0.5 });
    // p scales the window by 6 % and fades it: it rests when the scale is within 0.0005 (p about 0.008).
    restAt(spring, SCALE_REST / 0.06);
    spring.set(0);
  };

  const addColumn = (c: ViewRec, m: WindowModel, index: number, w = state.metrics.colW, silent = false, opaque = false): WinRec => {
    const before = flip.measure(flip.targets(c.colsEl));
    const rec = makeWindow(cx, c, m);
    c.wins.set(m.id, rec);
    const colEl = cx.view.newCol({ id: freshColumnId(cx, c), w, wins: [m] });
    colEl.append(rec.card.root);
    const kids = columnEls(c.colsEl);
    c.colsEl.insertBefore(colEl, (kids[index] && topItem(c.colsEl, kids[index]!)) ?? null);
    c.empty?.remove(); delete c.empty;
    cx.view.geometry(c);
    cx.view.settle(c.view.id);
    // A window opened by a key (a chord or a palette row) is simply there: the others do not slide aside and it does not swell in (#427).
    const byKey = triggeredByKeyboard();
    if (!byKey) flip.play(before);
    if (!silent && !byKey) enterAnimation(rec, opaque);
    cx.tree.render();
    cx.invalidate();
    return rec;
  };

  /** Where a closed window stood, so Undo can put it back. */
  interface Placed { view: ViewId; model: WindowModel; colIndex: number; aboveId: string | undefined; w: number }
  const placeOf = (rec: WinRec): Placed => {
    const root = rec.card.root;
    const colEl = root.parentElement as HTMLElement;
    const cols = columnEls(rec.owner.colsEl);
    const above = root.previousElementSibling as HTMLElement | null;
    return { view: rec.owner.view.id, model: rec.model, colIndex: Math.max(0, cols.indexOf(colEl)), aboveId: above?.dataset.windowId, w: Number(colEl.dataset.w) || state.metrics.colW };
  };
  /** Undo of a close: the window comes back where it was (under its upper neighbour, or in its own column). */
  const reopen = (at: Placed): void => {
    at = { ...at, model: { ...at.model, id: `w-${randomUuid()}` } };
    const c = views.get(at.view);
    const inv = cx.adapters.inventory;
    if (!c || c.wins.has(at.model.id)) return;
    const above = at.aboveId ? c.wins.get(at.aboveId) : undefined;
    const rec = above ? undefined : addColumn(c, at.model, Math.min(at.colIndex, columnEls(c.colsEl).length), at.w);
    // Splitting registers the window before its first wait, so the steps below find it as soon as the split has started.
    const done = (): void => {
      const shown = rec ?? c.wins.get(at.model.id);
      if (!shown) return;
      if (at.model.sessionId) inv?.attach(at.model.host, at.model.sessionId);
      setActive(cx, shown);
      cx.nav.focusWindow(shown);
      cx.store.changed();
    };
    if (!above) { done(); return; }
    const ready = splitReady();
    if (ready) { void ready.splitInto(above, "down", at.model); done(); return; }
    // The module has not arrived yet (an undo right after load): the window comes back when it does.
    void loadSplit(cx).then((m) => { if (c.wins.get(above.model.id) === above && !c.wins.has(at.model.id)) { void m.splitInto(above, "down", at.model); done(); } }, () => undefined);
  };

  const close = (rec: WinRec, instant = triggeredByKeyboard()): void => {
    if (rec.closing && !instant) return;
    // The card stays in the view until its exit animation finishes. Withdraw it
    // from target reuse immediately, so a quick reopen creates a fresh window.
    rec.closing = true;
    const c = rec.owner;
    // Closing never ends the session (D178): it keeps running, detached. The toast says so once, early on (TASTE: teach once).
    const inv = cx.adapters.inventory;
    const sess = inv && isTerminal(rec) && rec.model.sessionId ? inv.get(rec.model.host, rec.model.sessionId) : undefined;
    const placed = sess ? placeOf(rec) : undefined;
    const wasRunning = sess?.state === "open";
    if (sess && wasRunning) inv!.detach(rec.model.host, sess.id);
    if (placed && wasRunning && cx.adapters.teach?.("close-keeps-running")) cx.toast.show({ message: "Session keeps running", action: { label: "Reopen", onSelect: () => reopen(placed) }, duration: 6000 });
    if (cx.inputLock.state?.win === rec) cx.inputLock.toggle();
    if (state.activeWin === rec) setActive(cx, undefined);
    const root = rec.card.root;
    const finish = (): void => {
      // Immediate withdrawal may finish while the original exit spring still
      // owns a callback. Binding retirement belongs to the retained record once.
      if (c.wins.get(rec.model.id) !== rec) return;
      // The model as it stands with this window in it: a window in a group (or one that spans) re-tiles through the grid.
      const colEl = root.parentElement as HTMLElement | null;
      // A plain window (no group, no span) closes exactly as before; only a grouped one reads the view (D212).
      const grouped = !!colEl && (inGroup(colEl) || (rec.model.span ?? 1) > 1);
      // A group's DOM exists only once the grouped module has run, so a grouped window finds it loaded.
      const g0 = grouped ? groupsLoaded() : undefined;
      const cols = g0 ? g0.readColumns(cx, c) : [];
      const before = flip.measure(flip.targets(c.colsEl));
      c.wins.delete(rec.model.id);
      const freed = root.offsetHeight + COLUMN_GAP;
      rec.stopResize?.();
      cx.visibility.unwatch(rec);
      rec.binding?.dispose();
      rec.cleanup?.();
      root.remove();
      // The structure re-tiles: what remains in the column takes the freed height, an emptied column goes
      // and its neighbours close the gap. Everything animates as one move (a FLIP on the same spring as
      // every other layout move); the terminal refits once, at the new size.
      // The removal (fills, then columns and bands that nothing crosses) is the grouped module's (D212).
      if (g0) {
        g0.applyCols(cx, c, g0.fromGrid(c, g0.removeWin(cols, rec.model.id, COLUMN_GAP)));
        cx.view.geometry(c);
      }
      else if (colEl) {
        const rest = [...colEl.querySelectorAll<HTMLElement>(":scope > .ui-window")];
        if (!rest.length) {
          // A split half that empties gives its width back to the other half, so the layout returns to what it was.
          const partner = colEl.dataset.half ? columnEls(c.colsEl).find((x) => x.dataset.half === colEl.dataset.half && x !== colEl) ?? null : null;
          if (partner) {
            const w = (Number(partner.dataset.w) || state.metrics.colW) + COLUMN_GAP + (Number(colEl.dataset.w) || state.metrics.colW);
            setColumnWidth(partner, w, state.metrics); delete partner.dataset.half;
          }
          colEl.remove();
        }
        else if (rest.length === 1) { rest[0]!.style.height = ""; rest[0]!.style.flex = ""; }
        else {
          const total = rest.reduce((sum, w) => sum + w.offsetHeight, 0) + (rest.length - 1) * COLUMN_GAP;
          const k = (total + freed) / total;
          for (const w of rest) { w.style.height = `${Math.round(w.offsetHeight * k)}px`; w.style.flex = "none"; }
        }
      }
      cx.view.geometry(c);
      cx.view.paintEmpty(c);
      cx.view.settle(c.view.id);
      // Neighbours close the gap without overshoot (a critically damped spring): no value passes its final place. A keyboard
      // close moves nothing on screen with a motion: the layout is simply the new one.
      if (!instant) flip.play(before, true, { visualDuration: 0.38 });
      for (const w of c.wins.values()) w.binding?.refit();
      cx.tree.render();
      // The view's stops changed: the camera re-snaps (canvas lock) to the nearest one that still exists.
      if (state.canvasLock && state.currentView === c.view.id && views.has(c.view.id)) cx.nav.goStop(c, cx.nav.nearestStop(c, camera.cam.cx));
      cx.store.changed();
    };
    if (reduced.matches || instant) { finish(); return; }
    root.style.pointerEvents = "none";
    const spring = new Spring(0, (p) => {
      root.style.transform = `scale(${1 - 0.04 * p})`;
      root.style.opacity = String(1 - p);
      if (p >= 1) finish();
    }, { visualDuration: 0.22 });
    restAt(spring, SCALE_REST);
    spring.set(1);
  };

  const closeKey = (rec: WinRec): void => {
    const list = flat();
    const at = list.indexOf(rec);
    const next = list[at + 1] ?? list[at - 1];
    close(rec, true);
    if (next) { setActive(cx, next); cx.nav.focusWindow(next, true); }
  };

  // Splitting and opening beside live in their own module (split.on-demand.ts, D188): warmed when the canvas is up, started in the
  // same task when it has arrived, and fetched on the first press when it has not.
  const split = async (rec: WinRec, direction: "down" | "right"): Promise<boolean> => (splitReady() ?? await loadSplit(cx)).split(rec, direction);
  const newWindow = async (rec: WinRec, side: "right" | "below", session?: string): Promise<void> => (splitReady() ?? await loadSplit(cx)).newWindow(rec, side, session);

  /** Makes the window's model, title and body agree with its session in the inventory. */
  const syncSession = (rec: WinRec, force = false): void => {
    const s = isTerminal(rec) && rec.model.sessionId ? cx.adapters.inventory?.get(rec.model.host, rec.model.sessionId) : undefined;
    if (!s) return;
    const renamed = rec.model.session !== s.name;
    const repinned = (rec.model.sessionPinned === true) !== s.pinned;
    // A session without a stored screen (the product's: the renderer is the screen) is re-shown only when asked to.
    const reshown = force || (s.screen.length > 0 && rec.model.lines !== s.screen);
    rec.model.session = s.name;
    if (s.pinned) rec.model.sessionPinned = true;
    else delete rec.model.sessionPinned;
    if (s.screen.length) rec.model.lines = s.screen;
    if (renamed) {
      rec.card.setTitle({ host: rec.model.host, ...(rec.model.user ? { user: rec.model.user } : {}), session: s.name });
      cx.pill.paint();
    }
    // A different screen (another session, a run again): the old binding goes and the new one mounts. The work is
    // done at once; only the frame and the name animate (session-ui.ts).
    if (reshown) {
      // Another session of this window: the same terminal shows it (the renderer, the atlas and the canvas stay, and
      // the last known screen is on screen at once); only a binding that cannot do that is built again.
      if (force && rec.binding?.retarget?.(rec.model)) { rec.binding.refit(); cx.sessionUi?.paint(rec); }
      else {
        rec.binding?.dispose();
        makeBody(cx, rec);
        rec.binding?.setActive(state.activeWin === rec);
        rec.binding?.refit();
        cx.sessionUi?.paint(rec);
      }
    }
    if (renamed || repinned || reshown) { cx.tree.render(); cx.store.changed(); }
  };

  const attach = (rec: WinRec, sessionId: string): void => {
    const inv = cx.adapters.inventory;
    if (!inv || !isTerminal(rec) || rec.model.sessionId === sessionId || !inv.get(rec.model.host, sessionId)) return;
    const previous = rec.model.sessionId;
    // The window's model first, so the change events the inventory sends see a consistent window.
    rec.model.sessionId = sessionId;
    if (previous) inv.detach(rec.model.host, previous);
    inv.attach(rec.model.host, sessionId);
    syncSession(rec, true);
    cx.sessionUi?.arrived(rec);
  };

  /** Shows a session: its window if it has one, else a new window in Console that the camera flies to. */
  const openSession = (host: string, sessionId: string): WinRec | undefined => {
    const inv = cx.adapters.inventory;
    const c = views.get("console" as ViewId);
    if (!inv || !c || !inv.list(host).some((session) => session.id === sessionId)) return undefined;
    const existing = cx.sessionUi?.windowFor(host, sessionId);
    const model = cx.adapters.sessions.open(host, { session: sessionId });
    // The window carries the session's name from the first frame (the inventory knows it).
    const named = inv.get(host, sessionId)?.name;
    if (named && !model.session) model.session = named;
    const rec = existing ?? addColumn(c, model, columnEls(c.colsEl).length, state.metrics.colW, false, true);
    if (existing) pulse(rec);
    setActive(cx, rec);
    cx.nav.focusWindow(rec);
    cx.store.changed();
    return rec;
  };

  /** The small "this is the window" swell. A key never plays it (#427): the person asked for the window and is looking at it. */
  const pulse = (rec: WinRec): void => {
    if (triggeredByKeyboard()) return;
    rec.card.root.animate([{ transform: "scale(1)" }, { transform: "scale(1.012)" }, { transform: "scale(1)" }], { duration: 360, easing: EASE_OUT });
  };

  /**
   * Opens a session (a host's shell, or a container's) as a window in Console. Where you are decides what you
   * see: in Console (or zoomed out) the camera flies to the window; anywhere else the camera stays put and the
   * top pill morphs into a floating terminal that is a view of that same Console window.
   */
  const open = (host: string, container?: string): WinRec | undefined => {
    const c = views.get("console" as ViewId);
    if (!c) return undefined;
    const model = cx.adapters.sessions.open(host, container ? { container } : {});
    let rec = c.wins.get(model.id);
    const here = state.currentView === "console" || camera.band === "out";
    if (!rec) rec = addColumn(c, model, c.view.cols.length, state.metrics.colW, !here);
    else if (here) pulse(rec);
    setActive(cx, rec);
    if (here || !cx.flags.float) cx.nav.focusWindow(rec); else cx.float.open(rec);
    // On a desktop the new shell takes the keys at once; on a phone the keyboard waits for a tap.
    if (!coarse.matches) rec.binding?.focus();
    cx.store.changed();
    return rec;
  };

  const openFlow = (title: string): WinRec | undefined => {
    const c = state.activeWin?.owner ?? views.get("console" as ViewId);
    if (!c || c.view.layout !== "tiled") return undefined;
    const columns = [...c.colsEl.querySelectorAll<HTMLElement>(":scope > .cl-col")];
    const at = state.activeWin ? columns.indexOf(state.activeWin.card.root.parentElement as HTMLElement) : -1;
    const model: WindowModel = { id: `f-${randomUuid()}`, kind: "flow", host: title };
    const rec = addColumn(c, model, at < 0 ? columns.length : at + 1, state.metrics.colW);
    setActive(cx, rec);
    if (state.currentView !== c.view.id) cx.nav.flyView(c.view.id);
    cx.nav.focusWindow(rec);
    return rec;
  };

  const flat = (): WinRec[] => {
    const c = views.get(state.currentView);
    return c ? [...c.colsEl.querySelectorAll<HTMLElement>(".ui-window")].map((n) => c.wins.get(n.dataset.windowId ?? "")).filter((w): w is WinRec => !!w) : [];
  };

  return {
    make: (c, m) => makeWindow(cx, c, m),
    setActive: (rec) => setActive(cx, rec),
    addColumn, close, closeKey, split, newWindow, attach, syncSession,
    setHostIdentity(target, identity) {
      let painted = false;
      for (const c of views.values()) for (const rec of c.wins.values()) {
        if (!isTerminal(rec)) continue;
        const m = rec.model;
        if (target.hostId ? m.hostId !== target.hostId : m.hostId || m.noAccess || m.host !== target.host) continue;
        if (identity.os !== undefined && m.os !== identity.os) { m.os = identity.os; rec.card.setIcon(iconFor(m)); }
        if ("user" in identity && m.user !== identity.user) {
          if (identity.user) m.user = identity.user; else delete m.user;
          rec.card.setTitle({ host: m.host, ...(m.user ? { user: m.user } : {}), ...(m.session ? { session: m.session } : {}) });
          painted = true;
        }
      }
      if (painted) cx.pill.paint();
    },
    openSession, open, openFlow, pulse, flat,
    step(dir) {
      const list = flat();
      if (!list.length) return;
      const at = state.activeWin ? list.indexOf(state.activeWin) : -1;
      const next = list[clamp((at < 0 ? (dir > 0 ? -1 : list.length) : at) + dir, 0, list.length - 1)]!;
      setActive(cx, next);
      cx.nav.focusWindow(next, triggeredByKeyboard(), true);
    },
    move(dir) {
      const instant = triggeredByKeyboard();
      const list = flat();
      const from = state.activeWin;
      // Nothing is active yet (a click in a gap cleared it): a move activates the first window, or the last one going back.
      if (!from) {
        const first = list.length ? (dir === "left" || dir === "up" ? list[list.length - 1]! : list[0]!) : undefined;
        if (!first) return;
        setActive(cx, first);
        cx.nav.focusWindow(first, instant, true);
        return;
      }
      if (list.length < 2) return;
      const origin = from.card.root.getBoundingClientRect();
      const ox = origin.left + origin.width / 2, oy = origin.top + origin.height / 2;
      const horizontal = dir === "left" || dir === "right";
      let best: WinRec | undefined;
      let bestScore = Infinity;
      for (const rec of list) {
        if (rec === from) continue;
        const box = rec.card.root.getBoundingClientRect();
        const cx0 = box.left + box.width / 2, cy0 = box.top + box.height / 2;
        const along = dir === "left" ? ox - cx0 : dir === "right" ? cx0 - ox : dir === "up" ? oy - cy0 : cy0 - oy;
        if (along <= 0) continue;
        const across = horizontal ? Math.abs(cy0 - oy) : Math.abs(cx0 - ox);
        const score = along + 2 * across;
        if (score < bestScore) { bestScore = score; best = rec; }
      }
      if (!best) return;
      setActive(cx, best);
      cx.nav.focusWindow(best, instant, true);
    },
  };
}
