/**
 * The view list: tapping the top pill lists the views with their shortcuts, morphed out of the pill (the shared
 * pill morph). Escape or a press outside closes it. The last row opens the palette ("Search everything").
 *
 * An on-demand module (D188): the pill's hook (viewlist.ts) loads it at idle and on the first tap, so the list and the
 * morph are not part of the deferred canvas.
 */
import { createPillMorph, type PillMorph } from "../../../../../packages/ui/src/pill-morph";
import { keyCaps, PALETTE_KEYS } from "../../../../../packages/ui/src/shortcuts";
import type { Ctx } from "../context";
import { el } from "../dom";
import { viewIcon } from "../views/icons";
import { viewKeys, type ViewList } from "./viewlist";

/** Builds the view list: the views with their keys, morphed out of the top pill; its last row opens the whole palette directly. */
export function createViewListPanel(cx: Ctx): ViewList {
  const { stage, state, views } = cx;
  let morph: PillMorph | undefined;
  let abort: AbortController | undefined;
  const close = (instant = false): void => {
    abort?.abort(); abort = undefined;
    morph?.close(instant);
  };
  const toggle = (from?: HTMLElement): void => {
    if (morph?.isOpen) { close(); return; }
    if (cx.float.isOpen()) cx.float.close(true);
    const capsule = from ?? cx.pill.capsule;
    const panel = el("section", "cl-viewlist ui-overlay-surface");
    panel.setAttribute("role", "dialog");
    panel.setAttribute("aria-label", "Views");
    const list = el("ul", "cl-viewlist-rows");
    [...views.values()].forEach((c, i) => {
      const li = el("li");
      if (c.view.id === "settings") li.classList.add("cl-divided");
      const b = el("button", "cl-viewrow");
      b.type = "button";
      b.dataset.view = c.view.id;
      if (c.view.id === state.currentView) b.setAttribute("aria-current", "true");
      b.innerHTML = `<span class="cl-viewrow-icon"><svg viewBox="0 0 24 24" aria-hidden="true">${viewIcon(c.view.id)}</svg></span><span class="cl-viewrow-name"></span><span class="cl-viewrow-meta"></span><span class="cl-viewrow-keys"></span>`;
      (b.querySelector(".cl-viewrow-name") as HTMLElement).textContent = c.view.name;
      // Generated Settings section cards are navigation, not saved workspace memberships.
      const count = c.view.id === "settings" ? [...c.wins.values()].filter((w) => w.model.kind !== "settings").length : c.wins.size;
      (b.querySelector(".cl-viewrow-meta") as HTMLElement).textContent = c.view.layout === "graph" ? `${c.view.nodes.filter((v) => v.kind === "host").length} hosts` : c.view.id === "settings" && count === 0 ? "" : `${count} ${c.view.id === "docs" ? (count === 1 ? "page" : "pages") : count === 1 ? "window" : "windows"}`;
      const keys = b.querySelector(".cl-viewrow-keys") as HTMLElement;
      for (const cap of keyCaps(viewKeys(i))) keys.append(el("kbd", "", cap));
      b.addEventListener("click", () => { close(); cx.nav.flyView(c.view.id); });
      li.append(b);
      list.append(li);
    });
    const foot = el("button", "cl-viewrow cl-viewrow-search");
    foot.type = "button";
    foot.innerHTML = '<span class="cl-viewrow-icon"><svg viewBox="0 0 20 20" aria-hidden="true"><circle cx="9" cy="9" r="5.5"/><path d="m13 13 3.5 3.5"/></svg></span><span class="cl-viewrow-name">Search everything</span><span class="cl-viewrow-keys"></span>';
    for (const cap of keyCaps(PALETTE_KEYS)) (foot.querySelector(".cl-viewrow-keys") as HTMLElement).append(el("kbd", "", cap));
    // Opens the palette directly (not by faking its chord), so a click animates like any pointer open.
    foot.addEventListener("click", () => { close(true); cx.core.showPalette(); });
    panel.append(list, foot);
    morph = createPillMorph({ pill: capsule, stage, panel, content: [list, foot], width: 340, onClosed: () => { abort?.abort(); } });
    abort = new AbortController();
    const sig = abort.signal;
    document.addEventListener("keydown", (e) => { if (e.key === "Escape") { e.preventDefault(); e.stopPropagation(); close(); } }, { capture: true, signal: sig });
    document.addEventListener("pointerdown", (e) => { if (!panel.contains(e.target as Node) && !capsule.contains(e.target as Node)) close(); }, { capture: true, signal: sig });
    morph.open();
  };
  return { toggle, close, isOpen: () => Boolean(morph?.isOpen) };
}
