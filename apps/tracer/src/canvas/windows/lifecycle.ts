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
import type { HostPlatform } from "../../../../../packages/ui/src/host-icons";
import { clamp } from "../camera/camera";
import type { Ctx, ViewRec, WinRec } from "../context";
import { loadDroplet } from "../layout/droplet-handle";
import { COLUMN_GAP } from "../layout/geometry";
import { columnEls, freshColumnId, topItem } from "../layout/columns";
import { setColumnWidth } from "../layout/column-els";
import type { Col } from "../layout/grid";
import { groupsLoaded, loadGroups, type Groups } from "../layout/groups-handle";
import type { ViewId, WindowModel } from "../model/types";
import { MIN_COLUMN_WEIGHT } from "../model/schema";
import { coarse, reduced } from "../dom";
import { endActivity, setActivity } from "../../perf-activity";
import { makeWindow, setActive } from "./frame";
import { iconFor } from "../views/icons";
import { isTerminal, makeBody } from "../views/body";
import { SCALE_REST, restAt } from "../springs";

export interface WindowsModule {
  make(c: ViewRec, m: WindowModel): WinRec;
  setActive(rec: WinRec | undefined): void;
  /** Adds a window in a new column at `index` of a tiled view; the others glide aside. */
  addColumn(c: ViewRec, m: WindowModel, index: number, w?: number, silent?: boolean, opaque?: boolean): WinRec;
  close(rec: WinRec): void;
  /**
   * The keyboard close (D212 shortcuts): the window closes at once, with no motion, through the same path as the close
   * button (its session keeps running, detached). Focus and the active window move to the next window in reading order
   * first, so the next press closes the next one.
   */
  closeKey(rec: WinRec): void;
  /**
   * Divides a terminal window's own space into two windows (D212): `down` halves its height, `right` halves its
   * width. A new shell takes the other half. Works in a stacked column too: the windows around it span the new half.
   * `instant`: no motion at all (a keyboard action); the layout and the focus land in the same frame.
   */
  split(rec: WinRec, direction: "down" | "right", instant?: boolean): Promise<boolean>;
  /**
   * Opens a new full-size window next to a terminal window (D212): `right` in a new column of the same width, `below`
   * under it, which grows the column and leaves the others as they were. Opening never divides anything. With
   * `session`, the window shows that existing session of the host (the session manager's "beside") instead of a shell.
   */
  newWindow(rec: WinRec, side: "right" | "below", instant?: boolean, session?: string): Promise<void>;
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
  step(dir: number, instant?: boolean): void;
  /**
   * Makes the nearest window of the current view in a direction active and brings it into view (D222: ⌥⌘ arrows on a
   * Mac, Ctrl+Shift+arrows elsewhere). "Nearest" weighs distance along the direction twice as much as sideways offset,
   * so a window straight above or below beats one further along but offset. Nothing happens when no window lies that way.
   */
  move(dir: "left" | "right" | "up" | "down", instant?: boolean): void;
}

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
    }, { visualDuration: 0.5, bounce: 0.28 });
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
    flip.play(before);
    if (!silent) enterAnimation(rec, opaque);
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
    if (above) void splitInto(above, "down", at.model);
    const shown = rec ?? c.wins.get(at.model.id);
    if (!shown) return;
    if (at.model.sessionId) inv?.attach(at.model.host, at.model.sessionId);
    setActive(cx, shown);
    cx.nav.focusWindow(shown);
    cx.store.changed();
  };

  const close = (rec: WinRec, instant = false): void => {
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
      if (!instant) flip.play(before, true, { visualDuration: 0.38, bounce: 0 });
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
    }, { visualDuration: 0.22, bounce: 0 });
    restAt(spring, SCALE_REST);
    spring.set(1);
  };

  /**
   * A grid change (D212): measures the windows for the motion (none for a keyboard action), lets `change` decide the new
   * model from what the DOM holds, writes it into the DOM, reads it back and plays the motion.
   */
  const closeKey = (rec: WinRec): void => {
    const list = flat();
    const at = list.indexOf(rec);
    const next = list[at + 1] ?? list[at - 1];
    close(rec, true);
    if (next) { setActive(cx, next); cx.nav.focusWindow(next, true); }
  };

  const reshape = (g: Groups, c: ViewRec, instant: boolean, change: () => Col[]): void => {
    const before = instant ? undefined : flip.measure(flip.targets(c.colsEl));
    const next = change();
    g.applyCols(cx, c, g.fromGrid(c, next));
    cx.view.geometry(c);
    if (before) flip.play(before);
  };

  /** A column is plain when no group wraps it: its windows stack, and the flat path (what the product always did) is exact. */
  const inGroup = (colEl: HTMLElement): boolean => !!colEl.parentElement?.classList.contains("cl-group");

  /** A window's column is its own when no other window stands in it: only then can it divide sideways as a plain pair. */
  const ownsColumn = (rec: WinRec): boolean => {
    const colEl = rec.card.root.parentElement;
    return !!colEl && colEl.querySelectorAll(":scope > .ui-window").length === 1;
  };

  const split = async (rec: WinRec, direction: "down" | "right", instant = false): Promise<boolean> => {
    if (!isTerminal(rec)) return false;
    await splitInto(rec, direction, cx.adapters.sessions.open(rec.model.host, { from: rec.model }), instant);
    return true;
  };

  const newWindow = async (rec: WinRec, side: "right" | "below", instant = false, session?: string): Promise<void> => {
    if (!isTerminal(rec)) return;
    const nm = session ? { ...cx.adapters.sessions.open(rec.model.host, { session }), splitOf: rec.model.id } : cx.adapters.sessions.open(rec.model.host, { from: rec.model });
    const c = rec.owner;
    const root = rec.card.root;
    const colEl = root.parentElement as HTMLElement;
    const grouped = inGroup(colEl);
    // The grouped module loads before the window is made: a keyboard action then finds it there (warmed when a view is built).
    const g = grouped ? await loadGroups() : undefined;
    const before = flip.measure(flip.targets(c.colsEl));
    if (g) {
      // Inside a group the grid decides where the window goes (D212): a full-size window beside the group, or a band below.
      const b = makeWindow(cx, c, side === "below" ? { ...nm, h: 1 } : nm);
      c.wins.set(nm.id, b);
      reshape(g, c, instant, () => {
        const cols = g.readColumns(cx, c);
        if (side === "right") return g.newRight(cols, rec.model.id, { id: nm.id, colId: freshColumnId(cx, c) }, Number(colEl.dataset.w) || state.metrics.colW);
        const at = columnEls(c.colsEl).indexOf(colEl);
        const run = g.runsOf(cols).find((r) => at >= r.from && at <= r.to);
        for (let j = run?.from ?? at; j <= (run?.to ?? at); j++) for (const m of cols[j]?.wins ?? []) {
          const el = c.wins.get(m.id)?.card.root;
          if (el && (m.rows ?? 1) === 1) m.h = el.offsetHeight;
        }
        return g.splitDown(cols, rec.model.id, { id: nm.id }, undefined, 1);
      });
    } else if (side === "right") {
      const next = cx.view.newCol({ id: freshColumnId(cx, c), w: Number(colEl.dataset.w) || state.metrics.colW, wins: [nm] });
      const b = makeWindow(cx, c, nm);
      c.wins.set(nm.id, b);
      next.append(b.card.root);
      colEl.after(next);
    } else {
      // The windows already there keep their heights: a window that flexes would shrink to its minimum next to a full
      // size one. Their heights are pinned in pixels, in the model too, so a saved layout reopens the same way.
      for (const w of colEl.querySelectorAll<HTMLElement>(":scope > .ui-window")) {
        const h = w.offsetHeight;
        w.style.height = `${h}px`; w.style.flex = "none";
        const pinned = c.wins.get(w.dataset.windowId ?? "")?.model;
        if (pinned) pinned.h = h;
      }
      // Full size: a ratio of the column's height (1), so it is saved as "one column height" and the column grows by it.
      const b0: WindowModel = { ...nm, h: 1 };
      const b = makeWindow(cx, c, b0);
      c.wins.set(nm.id, b);
      root.after(b.card.root);
    }
    if (!grouped) cx.view.geometry(c);
    cx.view.settle(c.view.id);
    cx.tree.render();
    const b = c.wins.get(nm.id)!;
    rec.binding?.refit();
    // A new window by mouse glides the others aside (FLIP), as a new column always has. A keyboard action is instant.
    if (!instant) flip.play(before);
    land(b, instant);
    b.binding?.refit();
    cx.store.changed();
  };

  /**
   * Brings a new window in: it becomes the active one, the camera brings it fully into view and it takes the keys.
   * A keyboard action lands in the same frame. The keyboard only follows on a device that has one (a phone is never
   * asked to open it).
   */
  const land = (b: WinRec, instant: boolean): void => {
    cx.win.setActive(b);
    cx.nav.focusWindow(b, instant);
    if (!coarse.matches) b.binding?.focus();
  };

  /**
   * Divides a window (D212). In a plain column the base path does it: `down` stacks the new window under it, `right` (a
   * window that owns its column) gives it the other half, and the droplet plays. A window in a group, or a stacked window
   * split right, goes through the grid: the windows around it span the new half. Splits are windows in the one structure:
   * no nesting, and the total footprint does not change.
   */
  const splitInto = async (rec: WinRec, direction: "down" | "right", nm: WindowModel, instant = false): Promise<void> => {
    cx.store.changed({ windowId: nm.id, anchorId: rec.model.id, axis: direction });
    const c = rec.owner;
    const root = rec.card.root;
    const b = makeWindow(cx, c, nm);
    c.wins.set(nm.id, b);
    const colEl = root.parentElement as HTMLElement;
    // The window's height before the split: a window in a group is its band, which the split halves.
    const h0 = root.offsetHeight;
    // A stacked window split right, or any window in a group, is the grouped module's; a plain split is the flat path.
    const plain = !inGroup(colEl) && (direction === "down" || ownsColumn(rec));
    const g = plain ? undefined : await loadGroups();
    if (plain) {
      if (direction === "down") {
        const half = Math.round((h0 - COLUMN_GAP) / 2);
        root.style.height = `${half}px`; root.style.flex = "none";
        b.card.root.style.height = `${half}px`; b.card.root.style.flex = "none";
        root.after(b.card.root);
      } else {
        // The column's width splits into two columns with the gap between them: the pair is exactly the old width.
        const w = Number(colEl.dataset.w) || state.metrics.colW;
        const minimum = Math.ceil(state.metrics.colW * MIN_COLUMN_WEIGHT);
        const first = Math.max(minimum, Math.round((w - COLUMN_GAP) / 2));
        setColumnWidth(colEl, first, state.metrics);
        const next = cx.view.newCol({ id: freshColumnId(cx, c), w: Math.max(minimum, w - COLUMN_GAP - first), wins: [nm] });
        // The two halves name each other: closing one of them gives its width back to the other (see `close`).
        const pair = `p${++state.serial}`;
        colEl.dataset.half = pair; next.dataset.half = pair;
        next.append(b.card.root);
        colEl.after(next);
      }
      cx.view.geometry(c);
      cx.view.settle(c.view.id);
    } else {
      reshape(g!, c, instant, () => {
        const cols = g!.readColumns(cx, c);
        if (direction === "right") return g!.splitRight(cols, rec.model.id, { id: nm.id, colId: freshColumnId(cx, c), pair: `p${++state.serial}` }, COLUMN_GAP, Math.ceil(state.metrics.colW * MIN_COLUMN_WEIGHT));
        const half = Math.round((h0 - COLUMN_GAP) / 2);
        return g!.splitDown(cols, rec.model.id, { id: nm.id }, half, half);
      });
    }
    cx.tree.render();
    rec.binding?.refit();
    land(b, instant);
    if (instant) {
      // A keyboard action never animates (TASTE): the new window is simply there, refit once, with no silhouette.
      b.binding?.refit();
      cx.store.changed();
      return;
    }
    colEl.dataset.split = "";
    setActivity("split");
    const { dropletSplit } = await loadDroplet();
    await dropletSplit(root, b.card.root, direction, c.colsEl);
    endActivity("split");
    delete colEl.dataset.split;
    rec.binding?.refit();
    b.binding?.refit();
    cx.store.changed();
  };

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

  const pulse = (rec: WinRec): void => {
    rec.card.root.animate([{ transform: "scale(1)" }, { transform: "scale(1.012)" }, { transform: "scale(1)" }], { duration: 360, easing: "cubic-bezier(0.23, 1, 0.32, 1)" });
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
    step(dir, instant = false) {
      const list = flat();
      if (!list.length) return;
      const at = state.activeWin ? list.indexOf(state.activeWin) : -1;
      const next = list[clamp((at < 0 ? (dir > 0 ? -1 : list.length) : at) + dir, 0, list.length - 1)]!;
      setActive(cx, next);
      cx.nav.focusWindow(next, instant, true);
    },
    move(dir, instant = false) {
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
