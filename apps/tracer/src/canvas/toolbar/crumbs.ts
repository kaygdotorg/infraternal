// SPDX-License-Identifier: AGPL-3.0-only
/**
 * The top breadcrumb of Settings (issue #304): three pills, Settings › Mesh › Keys, in the place of the session capsule while a
 * window of Settings is focused. It follows the focused window and each pill navigates:
 *
 *   Settings  the list of views (the same list the capsule opens)
 *   Mesh      the components: choosing one flies to the first window of its row
 *   Keys      the groups of this component: choosing one flies to its window
 *
 * The three pills are centred on the screen's centre line, exactly where the capsule is (they sit in the capsule's grid track),
 * so nothing else in the top bar moves. A source without an `outline` never creates this.
 *
 * The capsule is not taken away while the breadcrumb shows: it stays in the layout as an invisible ghost with the breadcrumb's own
 * rectangle (`--crumbs-w`), and what the morph writes on it (its fade, its pointer-events, the palette's "covered" mark) is mirrored
 * onto the breadcrumb. So everything that grows out of the top pill (the view list, the `?` shortcuts panel, the floating terminal, the
 * palette) starts from where the breadcrumb is and fades it, in place, with no code of its own for Settings. A capsule that is
 * `display: none` has an empty rectangle, and a morph made from it opens at the top left of the screen.
 *
 * A name that changes crossfades (a short rise and fade, no fill left behind, so text is crisp at rest); changes that come
 * faster than the animation (arrowing through windows) do not animate (TASTE: repeated keyboard actions don't animate).
 * A menu opens under its pill in the shared overlay material, grows from the pill, and closes on a press outside, on Escape
 * and on choosing; the choice is ticked.
 */
import type { Ctx } from "../context";
import { el } from "../dom";
import { ICON, lineIcon, viewIcon } from "../views/icons";

export interface Crumbs { paint(): void; dispose(): void }

const EASE = "cubic-bezier(0.23, 1, 0.32, 1)";
const CHEVRON = `<svg viewBox="0 0 24 24" aria-hidden="true">${ICON.chevron}</svg>`;
const TICK = '<svg class="ui-sp-tick" viewBox="0 0 24 24" aria-hidden="true"><path d="m5.5 12.5 4 4 9-9"/></svg>';

export function createCrumbs(cx: Ctx): Crumbs {
  const { stage, state, camera, signal, views } = cx;
  const outline = cx.adapters.settings.outline!;
  const top = stage.querySelector<HTMLElement>(".top")!;
  const capsule = stage.querySelector<HTMLElement>("#capsule")!;
  const root = el("nav", "cl-crumbs");
  root.setAttribute("aria-label", "Where you are in Settings");
  root.hidden = true;
  const pill = (level: string): HTMLButtonElement => {
    const b = el("button", "ui-pill cl-crumb");
    b.type = "button";
    b.dataset.level = level;
    b.append(el("span", "cl-crumb-icon"), el("span", "cl-crumb-name"));
    return b;
  };
  const [viewPill, rowPill, groupPill] = [pill("view"), pill("row"), pill("group")] as const;
  const sep = (): HTMLElement => { const s = el("span", "cl-crumb-sep"); s.setAttribute("aria-hidden", "true"); s.innerHTML = CHEVRON; return s; };
  viewPill.querySelector<HTMLElement>(".cl-crumb-icon")!.innerHTML = lineIcon(viewIcon("settings"));
  viewPill.querySelector<HTMLElement>(".cl-crumb-name")!.textContent = "Settings";
  viewPill.setAttribute("aria-label", "Settings, all views");
  for (const p of [rowPill, groupPill]) { p.querySelector(".cl-crumb-icon")!.remove(); p.setAttribute("aria-haspopup", "true"); p.setAttribute("aria-expanded", "false"); }
  root.append(viewPill, sep(), rowPill, sep(), groupPill);
  capsule.after(root);
  groupPill.setAttribute("aria-current", "page");

  // The ghost capsule is as wide as the breadcrumb, whatever the names say.
  const fit = (): void => { capsule.style.setProperty("--crumbs-w", `${root.offsetWidth}px`); };
  const sizeWatch = new ResizeObserver(fit);
  sizeWatch.observe(root);
  // What a morph or the palette writes on the capsule is what the person sees happen to the breadcrumb.
  const mirror = (): void => {
    root.style.opacity = capsule.style.opacity;
    root.style.pointerEvents = capsule.style.pointerEvents;
    root.toggleAttribute("data-palette-covered", capsule.hasAttribute("data-palette-covered"));
    root.toggleAttribute("data-expanded", capsule.getAttribute("aria-expanded") === "true");
  };
  const mirrorWatch = new MutationObserver(mirror);
  mirrorWatch.observe(capsule, { attributes: true, attributeFilter: ["style", "data-palette-covered", "aria-expanded"] });

  let lastMotion = 0;
  const setName = (pillEl: HTMLElement, text: string): void => {
    const name = pillEl.querySelector<HTMLElement>(".cl-crumb-name")!;
    if (name.textContent === text) return;
    const had = name.textContent !== "";
    name.textContent = text;
    pillEl.setAttribute("aria-label", text);
    const now = performance.now();
    if (had && now - lastMotion > 260 && !matchMedia("(prefers-reduced-motion: reduce)").matches) name.animate([{ opacity: 0, transform: "translateY(4px)" }, { opacity: 1, transform: "none" }], { duration: 180, easing: EASE });
    if (had) lastMotion = now;
  };

  const place = (windowId: string | undefined) => {
    const rows = outline.rows();
    const row = rows.find((r) => r.groups.some((g) => g.windowId === windowId));
    return row ? { rows, row, group: row.groups.find((g) => g.windowId === windowId)! } : undefined;
  };
  const here = (): ReturnType<typeof place> => place(state.activeWin?.model.id);

  // ---- the menus ---------------------------------------------------------------------------------------
  let menu: { el: HTMLElement; anchor: HTMLElement } | undefined;
  const closeMenu = (instant = false): void => {
    if (!menu) return;
    const { el: node, anchor } = menu;
    menu = undefined;
    anchor.setAttribute("aria-expanded", "false");
    if (instant || matchMedia("(prefers-reduced-motion: reduce)").matches) { node.remove(); return; }
    node.style.pointerEvents = "none";
    node.animate([{ opacity: 1 }, { opacity: 0 }], { duration: 120, easing: EASE }).onfinish = () => node.remove();
  };
  const openMenu = (anchor: HTMLElement, label: string, items: Array<{ label: string; icon?: string; current: boolean; go(): void }>, source: "pointer" | "keyboard"): void => {
    closeMenu(true);
    const node = el("div", "ui-overlay-surface cl-crumb-menu");
    node.setAttribute("role", "group");
    node.setAttribute("aria-label", label);
    for (const item of items) {
      const b = el("button", "ui-sp-row cl-crumb-item");
      b.type = "button";
      if (item.current) b.dataset.current = "";
      b.innerHTML = `${item.icon ? `<span class="ui-ts-icon"><svg viewBox="0 0 24 24" aria-hidden="true">${item.icon}</svg></span>` : ""}<span class="ui-sp-label"></span>${TICK}`;
      b.querySelector(".ui-sp-label")!.textContent = item.label;
      b.addEventListener("click", () => { closeMenu(); item.go(); });
      node.append(b);
    }
    stage.append(node);
    const screen = stage.getBoundingClientRect(), box = anchor.getBoundingClientRect();
    const width = Math.min(Math.max(node.offsetWidth, box.width), screen.width - 16);
    node.style.minWidth = `${Math.round(box.width)}px`;
    node.style.left = `${Math.round(Math.max(8, Math.min(box.left - screen.left, screen.width - 8 - width)))}px`;
    node.style.top = `${Math.round(box.bottom - screen.top + 8)}px`;
    node.style.maxHeight = `${Math.max(120, Math.floor(screen.bottom - box.bottom - 16))}px`;
    node.style.transformOrigin = `${Math.round(box.left + box.width / 2 - screen.left - parseFloat(node.style.left))}px 0`;
    anchor.setAttribute("aria-expanded", "true");
    if (source === "pointer" && !matchMedia("(prefers-reduced-motion: reduce)").matches) node.animate([{ opacity: 0, transform: "translateY(-4px) scale(0.96)" }, { opacity: 1, transform: "none" }], { duration: 200, easing: EASE });
    menu = { el: node, anchor };
  };
  const focusWindow = (windowId: string | undefined): void => {
    const rec = windowId ? views.get("settings")?.wins.get(windowId) : undefined;
    if (!rec) return;
    cx.win.setActive(rec);
    cx.nav.focusWindow(rec);
  };
  const sourceOf = (e: MouseEvent): "pointer" | "keyboard" => (e.detail === 0 ? "keyboard" : "pointer");
  viewPill.addEventListener("click", () => { closeMenu(true); cx.viewList.toggle(); }, { signal });
  rowPill.addEventListener("click", (e) => {
    if (menu?.anchor === rowPill) { closeMenu(); return; }
    const at = here();
    if (!at) return;
    openMenu(rowPill, "Components of Settings", at.rows.map((r) => ({ label: r.title, icon: r.icon, current: r.id === at.row.id, go: () => focusWindow(r.groups[0]?.windowId) })), sourceOf(e));
  }, { signal });
  groupPill.addEventListener("click", (e) => {
    if (menu?.anchor === groupPill) { closeMenu(); return; }
    const at = here();
    if (!at) return;
    openMenu(groupPill, `${at.row.title} groups`, at.row.groups.map((g) => ({ label: g.title, current: g.id === at.group.id, go: () => focusWindow(g.windowId) })), sourceOf(e));
  }, { signal });
  document.addEventListener("pointerdown", (e) => { if (menu && !menu.el.contains(e.target as Node) && !menu.anchor.contains(e.target as Node)) closeMenu(); }, { signal, capture: true });
  document.addEventListener("keydown", (e) => { if (menu && e.key === "Escape") { e.stopPropagation(); closeMenu(true); } }, { signal, capture: true });

  const paint = (): void => {
    const free = !state.canvasLock && camera.lod === "thumb";
    const at = state.currentView === "settings" && !free ? here() : undefined;
    top.toggleAttribute("data-crumbs", at !== undefined);
    root.hidden = at === undefined;
    if (!at) { closeMenu(true); return; }
    setName(rowPill, at.row.title);
    setName(groupPill, at.group.title);
    fit();
  };
  return { paint, dispose() { closeMenu(true); sizeWatch.disconnect(); mirrorWatch.disconnect(); capsule.style.removeProperty("--crumbs-w"); root.remove(); top.removeAttribute("data-crumbs"); } };
}
