/**
 * The sidebar tree (D178: sidebar = inventory, canvas = workspace): one section per view, listing its windows
 * (or a graph view's nodes). Tapping a view flies the canvas there; tapping an item makes it active and flies to
 * it. Settings sits after a divider, like a person's own corner of the app. Rendering is coalesced to one per
 * microtask because a layout change calls it from several places.
 */
import type { BranchSection } from "../../../../../packages/ui/src/branched";
import type { Ctx } from "../context";
import type { ViewId } from "../model/types";
import { coarse } from "../dom";
import { isFreeView } from "../layout/stops";

export interface TreeModule {
  /** Rebuilds the sidebar tree from the views (coalesced). */
  render(): void;
  dispose(): void;
}

export function createTree(cx: Ctx): TreeModule {
  const { core, stage, signal, views, state } = cx;
  const sections = (): BranchSection[] => [...views.values()].map((c) => {
    const graph = c.view.layout === "graph";
    return {
      id: `view:${c.view.id}`,
      label: c.view.name,
      meta: graph ? `${c.view.nodes.filter((v) => v.kind === "host").length} hosts` : `${c.wins.size}`,
      open: c.view.id !== "settings",
      // A big graph lists no nodes: a thousand rows would be the cost of the sidebar, and its cards are not all in the
      // DOM. The section still flies to the view, where the clusters are.
      leaves: graph
        ? (isFreeView(c.view) ? [] : c.view.nodes).map((n) => ({ id: `n-${n.id}`, label: n.label, glyph: n.kind === "tag" ? "#" : "◦" }))
        : [...c.wins.values()].map((w) => ({ id: w.model.id, label: w.model.kind === "terminal" ? `${w.model.host}${w.model.session ? ` · ${w.model.session}` : ""}` : w.model.kind === "settings" ? w.model.host : (w.model.session ?? w.model.kind), glyph: w.model.kind === "terminal" ? "›_" : "▤" })),
    };
  });
  let queued = false;
  const render = (): void => {
    if (queued) return;
    queued = true;
    queueMicrotask(() => {
      queued = false;
      core.setHostTree(sections(), state.activeWin?.model.id ?? "", (id) => {
        const target = [...views.values()].flatMap((c) => [...c.wins.values()]).find((w) => w.model.id === id);
        if (!target) return;
        cx.win.setActive(target);
        if (target.model.kind === "node") cx.nav.flyView("mesh"); else cx.nav.focusWindow(target);
        if (coarse.matches) stage.querySelector<HTMLButtonElement>("#sidebar-toggle[aria-expanded='true']")?.click();
      });
    });
  };
  const tree = stage.querySelector<HTMLElement>("#tree");
  tree?.addEventListener("click", (e) => {
    const head = (e.target as Element).closest(".bm-head");
    const id = head?.parentElement?.dataset.id?.replace(/^view:/, "") as ViewId | undefined;
    if (id && views.has(id)) cx.nav.flyView(id);
  }, { signal });
  const markDivider = (): void => { stage.querySelector('#tree .bm-sec[data-id="view:settings"]')?.classList.add("cl-divided"); };
  const observer = tree ? new MutationObserver(markDivider) : undefined;
  if (tree) observer!.observe(tree, { childList: true });
  const sideTitle = stage.querySelector<HTMLElement>(".sidebar-title");
  if (sideTitle) sideTitle.textContent = "Views";
  return { render, dispose() { observer?.disconnect(); } };
}
