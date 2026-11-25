// SPDX-License-Identifier: AGPL-3.0-only
/**
 * The top breadcrumb of Settings (issue #304): three pills, Settings › Mesh › Keys, in the place of the session capsule while a
 * window of Settings is focused. It names the row in view (and the window of that row in view), and each pill navigates:
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
 * On a phone (720 px and narrower) the trail does not fit, so it becomes an iOS-style header: a back pill "‹ Machines" (the parent of
 * the window in view) and the window's own name as the heading. Back flies to the first window of that parent; from the first window
 * it reads "‹ Settings" and opens the list of views, one level up. The Settings pill and the separators are hidden; ☰ and + stay at
 * the bar's edges because the bar's grid is unchanged. Desktop keeps the full trail.
 *
 * A name that changes crossfades (a short rise and fade, no fill left behind, so text is crisp at rest); changes that come
 * faster than the animation (arrowing through windows) do not animate (TASTE: repeated keyboard actions don't animate).
 * A menu opens under its pill, centred on it, in the shared overlay material, grows from the pill, and closes on a press outside, on Escape
 * and on choosing; the choice is ticked.
 */
import { triggeredByKeyboard } from "../../../../../packages/ui/src/input-source";
import type { Ctx } from "../context";
import { el } from "../dom";
import { ICON, lineIcon, viewIcon } from "../views/icons";

export interface Crumbs { paint(): void; dispose(): void }

/** The shared easing token (WAAPI cannot read a `var()` in an easing string, so the value is read once). */
const ease = (): string => getComputedStyle(document.documentElement).getPropertyValue("--ease-out").trim() || "ease-out";
const CHEVRON = `<svg viewBox="0 0 24 24" aria-hidden="true">${ICON.chevron}</svg>`;
/** The phone header's back pill is on narrow screens only; this is the width the stylesheet also uses for it. */
const PHONE = "(max-width: 720px)";
const TICK = '<svg class="ui-sp-tick" viewBox="0 0 24 24" aria-hidden="true"><path d="m5.5 12.5 4 4 9-9"/></svg>';

/** Builds the breadcrumb pills (view, window, session) in the top bar and returns their controls; a name changed by a key shows at once (#427). */
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
  // The back chevron shows on a phone only (clusters.css); the icon slot of the row pill is it, so the pill's icon keeps its own place.
  const backIcon = rowPill.querySelector<HTMLElement>(".cl-crumb-icon")!;
  backIcon.classList.add("cl-crumb-back");
  backIcon.innerHTML = CHEVRON;
  // The phone's label of the back pill lives beside the trail's name for the same pill, so the trail (what the specs and a screen reader's tree read) never changes.
  const backLabel = el("span", "cl-crumb-back-label");
  rowPill.append(backLabel);
  groupPill.querySelector(".cl-crumb-icon")!.remove();
  for (const p of [rowPill, groupPill]) { p.setAttribute("aria-haspopup", "true"); p.setAttribute("aria-expanded", "false"); }
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
    // A crumb that changes because a key moved the camera or opened a view reads its new name at once (#427).
    if (had && now - lastMotion > 260 && !triggeredByKeyboard() && !matchMedia("(prefers-reduced-motion: reduce)").matches) name.animate([{ opacity: 0, transform: "translateY(4px)" }, { opacity: 1, transform: "none" }], { duration: 180, easing: ease() });
    if (had) lastMotion = now;
  };

  const place = (windowId: string | undefined) => {
    const rows = outline.rows();
    const row = rows.find((r) => r.groups.some((g) => g.windowId === windowId));
    return row ? { rows, row, group: row.groups.find((g) => g.windowId === windowId)! } : undefined;
  };
  /** The Settings window in view (`Nav.windowInView`): the breadcrumb names what the person sees, not what was clicked last (D323). */
  const inView = (): string | undefined => { const rec = views.get("settings"); return rec ? cx.nav.windowInView(rec) : undefined; };
  /** While the camera flies, the window it flies to (the focused one) is where the person is going; at rest, what is in view. */
  const here = (): ReturnType<typeof place> => place(camera.isMoving ? state.activeWin?.model.id : inView() ?? state.activeWin?.model.id);

  // ---- the menus ---------------------------------------------------------------------------------------
  let menu: { el: HTMLElement; anchor: HTMLElement } | undefined;
  const closeMenu = (instant = false): void => {
    if (!menu) return;
    const { el: node, anchor } = menu;
    menu = undefined;
    anchor.setAttribute("aria-expanded", "false");
    if (instant || matchMedia("(prefers-reduced-motion: reduce)").matches) { node.remove(); return; }
    node.style.pointerEvents = "none";
    node.animate([{ opacity: 1 }, { opacity: 0 }], { duration: 120, easing: ease() }).onfinish = () => node.remove();
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
    node.style.minWidth = `${Math.round(box.width)}px`;
    // The drawn width, not the rounded one: a half pixel of difference moves the centre by a quarter pixel (the menu is centred to 0.5 px).
    const width = Math.min(Math.max(node.getBoundingClientRect().width, box.width), screen.width - 16);
    // Centred on the pill it came from, shifted only as far as the screen's inset needs (TASTE: a menu opened from a pill is centred on that pill).
    const centre = box.left + box.width / 2 - screen.left;
    node.style.left = `${Math.round(Math.max(8, Math.min(centre - width / 2, screen.width - 8 - width)))}px`;
    node.style.top = `${Math.round(box.bottom - screen.top + 8)}px`;
    node.style.maxHeight = `${Math.max(120, Math.floor(screen.bottom - box.bottom - 16))}px`;
    node.style.transformOrigin = `${Math.round(box.left + box.width / 2 - screen.left - parseFloat(node.style.left))}px 0`;
    anchor.setAttribute("aria-expanded", "true");
    if (source === "pointer" && !matchMedia("(prefers-reduced-motion: reduce)").matches) node.animate([{ opacity: 0, transform: "translateY(-4px) scale(0.96)" }, { opacity: 1, transform: "none" }], { duration: 200, easing: ease() });
    menu = { el: node, anchor };
  };
  const focusWindow = (windowId: string | undefined): void => {
    const rec = windowId ? views.get("settings")?.wins.get(windowId) : undefined;
    if (!rec) return;
    cx.win.setActive(rec);
    cx.nav.focusWindow(rec);
  };
  const phone = matchMedia(PHONE);
  /** Whether the window in view is its component's first, so its parent on a phone is Settings itself. */
  const isFirst = (at: NonNullable<ReturnType<typeof place>>): boolean => at.row.groups[0]?.windowId === at.group.windowId;
  const sourceOf = (e: MouseEvent): "pointer" | "keyboard" => (e.detail === 0 ? "keyboard" : "pointer");
  // The views list grows from, and is centred on, the Settings pill (TASTE: a menu opened from a pill is centred on that pill); the morph fades that
  // pill, and the rest of the breadcrumb fades with it, so the list does not open over half a breadcrumb.
  // On a phone the back pill is the one the list of views grows from (the Settings pill is hidden), so whichever of the two is the anchor
  // fades the rest. A pill only copies the fade of the pill that was touched, so the two never feed each other.
  const fadeWatch = new MutationObserver((records) => {
    for (const record of records) {
      const source = record.target as HTMLElement;
      for (const n of root.children) if (n !== source && n instanceof HTMLElement && n.style.opacity !== source.style.opacity && (source === viewPill || source === rowPill) && !(source === rowPill && n === viewPill)) n.style.opacity = source.style.opacity;
    }
  });
  fadeWatch.observe(viewPill, { attributes: true, attributeFilter: ["style"] });
  fadeWatch.observe(rowPill, { attributes: true, attributeFilter: ["style"] });
  viewPill.addEventListener("click", () => { closeMenu(true); cx.viewList.toggle(viewPill); }, { signal });
  rowPill.addEventListener("click", (e) => {
    if (menu?.anchor === rowPill) { closeMenu(); return; }
    const at = here();
    if (!at) return;
    if (phone.matches) {
      // The back button of the phone header: up one level. From the first window of a component that is the list of views.
      closeMenu(true);
      if (isFirst(at)) cx.viewList.toggle(rowPill); else focusWindow(at.row.groups[0]?.windowId);
      return;
    }
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
    // Written only when it changes: an attribute written again with the same value still notifies every mutation observer.
    if (root.hidden !== (at === undefined)) root.hidden = at === undefined;
    if (!at) { closeMenu(true); return; }
    const phoneHeader = phone.matches;
    root.toggleAttribute("data-phone", phoneHeader);
    // The back pill's phone label names the parent: the component, or Settings from the component's first window. Desktop shows the trail's own name.
    const parent = isFirst(at) ? "Settings" : at.row.title;
    setName(rowPill, at.row.title);
    if (backLabel.textContent !== parent) backLabel.textContent = parent;
    rowPill.setAttribute("aria-label", phoneHeader ? `Back to ${parent}` : at.row.title);
    rowPill.toggleAttribute("data-back", phoneHeader);
    if (phoneHeader && isFirst(at)) rowPill.setAttribute("aria-haspopup", "true"); else if (phoneHeader) rowPill.removeAttribute("aria-haspopup"); else rowPill.setAttribute("aria-haspopup", "true");
    setName(groupPill, at.group.title);
    fit();
  };
  // The rows of the view scroll inside it (one band at a time) and the camera does not move for that: a scroll anywhere in the stage
  // (scroll events do not bubble, so the capture phase) repaints the names once a frame.
  phone.addEventListener("change", () => paint(), { signal });
  let scrollFrame = 0;
  stage.addEventListener("scroll", () => { if (!scrollFrame) scrollFrame = requestAnimationFrame(() => { scrollFrame = 0; paint(); }); }, { capture: true, passive: true, signal });
  return { paint, dispose() { cancelAnimationFrame(scrollFrame); closeMenu(true); sizeWatch.disconnect(); mirrorWatch.disconnect(); fadeWatch.disconnect(); capsule.style.removeProperty("--crumbs-w"); root.remove(); top.removeAttribute("data-crumbs"); } };
}
