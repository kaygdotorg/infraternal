/**
 * The sidebar tree (D178: sidebar = inventory, canvas = workspace): one section per view, listing its windows
 * (or a graph view's nodes). Tapping a view flies the canvas there; tapping an item makes it active and flies to
 * it. Settings sits after a divider, like a person's own corner of the app. Rendering is coalesced to one per
 * microtask because a layout change calls it from several places.
 *
 * With a session inventory (D178) the Console section lists its hosts, and under each host every session of it,
 * whether or not it has a window, each marked open (filled dot), detached (hollow dot and "detached") or
 * exited (hollow square and its exit code ✓ 0 / ✗ 1), with the activity mark of a detached one, in frecency
 * order. Tapping an open session flies to its window; tapping a detached or exited one opens it in a new
 * window and flies there. A closed sidebar is not rebuilt; it is brought up to date when it opens.
 */
import type { BranchedMenu, BranchSection } from "../../../../../packages/ui/src/branched";
import type { Ctx } from "../context";
import type { ViewId } from "../model/types";
import { coarse } from "../dom";
import { isFreeView } from "../layout/stops";
import { onDemand, whenIdle } from "../../on-demand";

export interface TreeModule {
  /** Rebuilds the sidebar tree from the views (coalesced). */
  render(): void;
  dispose(): void;
}

export function createTree(cx: Ctx): TreeModule {
  const { core, stage, signal, views, state } = cx;
  const inv = cx.adapters.inventory;
  // The session list (markers, marks, hosts as captions) loads the first time the sidebar shows it (D188).
  let leavesOf: ((cx: Ctx) => BranchSection["leaves"]) | undefined;
  let loadingLeaves = false;
  const loadLeaves = (): void => {
    if (leavesOf || loadingLeaves) return;
    loadingLeaves = true;
    void onDemand(() => import("./session-tree.on-demand")).then((m) => { leavesOf = m.consoleLeaves; loadingLeaves = false; render(); }, () => { loadingLeaves = false; });
  };
  const viewSections = (): BranchSection[] => [...views.values()].map((c) => {
    const graph = c.view.layout === "graph";
    return {
      id: `view:${c.view.id}`,
      label: c.view.name,
      meta: graph ? `${c.view.nodes.filter((v) => v.kind === "host").length} hosts` : `${c.wins.size}`,
      open: c.view.id !== "settings" && c.view.id !== "docs",
      // A big graph lists no nodes: a thousand rows would be the cost of the sidebar, and its cards are not all in the
      // DOM. The section still flies to the view, where the clusters are.
      leaves: graph
        ? (isFreeView(c.view) ? [] : c.view.nodes).map((n) => ({ id: `n-${n.id}`, label: n.label, glyph: n.kind === "tag" ? "#" : "◦", ...(n.kind === "host" && c.view.id === "mesh" ? { renamable: true } : {}) }))
        : [...c.wins.values()].map((w) => ({ id: w.model.id, label: w.model.kind === "terminal" ? `${w.model.host}${w.model.session ? ` · ${w.model.session}` : ""}` : w.model.kind === "settings" || w.model.kind === "docs" ? w.model.host : (w.model.session ?? w.model.kind), glyph: w.model.kind === "terminal" ? "›_" : "▤" })),
    };
  });
  // Warmed at idle too, so the first time the sidebar opens its sessions are there at once (#128).
  if (inv) whenIdle(loadLeaves);
  const sections = (): BranchSection[] => {
    const all = viewSections();
    if (!inv || inv.status() !== "ready") return all;
    if (!leavesOf) { loadLeaves(); return all; }
    // Console lists the sessions of its hosts, not only the ones that have a window (D178).
    const leaves = leavesOf(cx);
    return all.map((sec) => (sec.id === "view:console" ? { ...sec, meta: `${leaves.filter((l) => !l.heading).length}`, leaves } : sec));
  };
  const current = (): string => {
    const w = state.activeWin;
    return inv && w?.model.sessionId ? `s:${w.model.host}/${w.model.sessionId}` : w?.model.id ?? "";
  };
  let queued = false;
  let stale = false;
  /** A host's name is being edited in the tree: it is not rebuilt under the person's hands (it is, once they are done). */
  let editing = false;
  /** A second tap on a host's name renames it; the sidebar on a phone therefore waits this long before it closes. */
  const DOUBLE_TAP_WAIT_MS = 360;
  let marks = new Set<string>();
  /** The shared tree behind the sidebar; the row menu's Rename and F2 open its inline-rename field through it. */
  let treeMenu: BranchedMenu | undefined;
  /** The row menu, swipes and pill (D309, #215): their code loads the first time the sidebar is shown (D188). */
  let rows: { openRename(row: HTMLElement): boolean; dispose(): void } | undefined;
  let rowsLoading: Promise<unknown> | undefined;
  const closeSidebar = (): void => { stage.querySelector<HTMLButtonElement>("#sidebar-toggle[aria-expanded='true']")?.click(); };
  const loadRows = (): void => {
    rowsLoading ??= onDemand(() => import("./row-actions.on-demand")).then((m) => { if (!signal.aborted) rows = m.createRowActions(cx, stage.querySelector<HTMLElement>("#tree")!, { closeSidebar, rename: (id) => treeMenu?.rename(id) ?? false, editing: (open) => { editing = open; if (!open) render(); } }); });
  };
  /** On a phone something that was chosen closes the sidebar; a row whose name a second tap renames waits out the double tap first. */
  const chosen = (id: string): void => {
    if (!coarse.matches) return;
    if (stage.querySelector(`#tree [data-renamable][data-id="${CSS.escape(id)}"]`)) window.setTimeout(() => { if (!editing) closeSidebar(); }, DOUBLE_TAP_WAIT_MS); else closeSidebar();
  };
  const sidebar = stage.querySelector<HTMLElement>("#sidebar");
  const render = (): void => {
    if (queued) return;
    queued = true;
    queueMicrotask(() => {
      queued = false;
      if (signal.aborted) return;
      // A closed sidebar costs a rebuild and a layout for nothing; it is rebuilt when it opens.
      if (sidebar?.hidden) { stale = true; return; }
      if (editing) return;
      stale = false;
      loadRows();
      treeMenu = core.setHostTree(sections(), current(), (id) => {
        if (id.startsWith("s:")) {
          const [host, sid] = id.slice(2).split("/");
          if (host && sid) cx.win.openSession(host, sid);
          chosen(id);
          return;
        }
        const target = [...views.values()].flatMap((c) => [...c.wins.values()]).find((w) => w.model.id === id);
        if (!target) return;
        cx.win.setActive(target);
        if (target.model.kind === "node") cx.nav.flyView("mesh"); else cx.nav.focusWindow(target);
        chosen(id);
      }, { openRename: (row) => rows?.openRename(row) ?? false });
      // A mark that was not on the last tree draws in; the others stay still.
      const now = new Set<string>();
      for (const leaf of stage.querySelectorAll<HTMLElement>("#tree .bm-leaf")) {
        const mark = leaf.querySelector<HTMLElement>(".ui-mark");
        if (!mark) continue;
        const id = `${leaf.dataset.id}:${mark.dataset.mark}`;
        now.add(id);
        if (marks.size && !marks.has(id)) mark.classList.add("is-new");
      }
      marks = now;
    });
  };
  const shown = sidebar ? new MutationObserver(() => { if (stale && !sidebar.hidden) render(); }) : undefined;
  if (sidebar) shown!.observe(sidebar, { attributes: true, attributeFilter: ["hidden"] });
  const tree = stage.querySelector<HTMLElement>("#tree");
  tree?.addEventListener("click", (e) => {
    const head = (e.target as Element).closest(".bm-head");
    const raw = head?.parentElement?.dataset.id ?? "";
    const id = raw.replace(/^view:/, "") as ViewId;
    if (id && views.has(id)) cx.nav.flyView(id);
  }, { signal });
  const markDivider = (): void => { stage.querySelector('#tree .bm-sec[data-id="view:settings"]')?.classList.add("cl-divided"); };
  const observer = tree ? new MutationObserver(markDivider) : undefined;
  if (tree) observer!.observe(tree, { childList: true });
  const sideTitle = stage.querySelector<HTMLElement>(".sidebar-title");
  if (sideTitle) sideTitle.textContent = "Views";
  return { render, dispose() { observer?.disconnect(); shown?.disconnect(); rows?.dispose(); } };
}
