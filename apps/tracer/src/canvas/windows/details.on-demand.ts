/**
 * The window details popover: facts for one window, anchored to its header pill (#127).
 *
 * - Material: the shared floating overlay (`.ui-overlay-surface`); content behind it reads as soft shapes.
 * - Layout: the mark and name on top, capsule tabs, then a key/value list (keys left, values right, each cell copies on
 *   click or double tap). The list scrolls inside a popover that never runs past the visible viewport or under the key
 *   tray. The facts come from a `DetailsSource` (details-source.ts); this module only draws them.
 * - Motion: a pointer open grows from the pill (scale 0.96 to 1 with opacity, 200 ms strong ease-out); closing is quicker
 *   (130 ms). Keyboard opens and closes are instant. The animations use the Web Animations API without fill, so nothing
 *   is left transformed at rest and text stays crisp.
 * - It loads on demand (D188): nothing of it is fetched until a pill is first pressed.
 */
import { createCapsuleTabs } from "../../../../../packages/ui/src/capsule-tabs";
import { hostIconMarkup } from "../../../../../packages/ui/src/host-icons";
import { createKeyValueList } from "../../../../../packages/ui/src/kv-list";
import type { Ctx, WinRec } from "../context";
import type { DetailsFacts, DetailsSource } from "./details-source";
import { currentUiScale } from "../../../../../packages/ui/src/ui-scale";
import { EASE_OUT } from "../../../../../packages/ui/src/motion";
import { REMOVAL_EFFECT } from "../host-removal-confirm";

export interface DetailsPopover {
  readonly windowId: string;
  close(source: "pointer" | "keyboard"): void;
  refresh(): void;
}

interface DetailsInput {
  windowId: string;
  /** Read at open and each time a tab is shown. */
  read: () => DetailsFacts;
  /**
   * A destructive action under the facts: its short name, what it does (optional) and what runs, anchored to its row.
   * `subject` is what it acts on ("compute01"); `runConfirmed` does it when the panel itself already asked (#486).
   */
  action?: DetailsAction;
}

/** The details card's one destructive action (remove host). */
export interface DetailsAction { label: string; hint?: string; subject: string; run(anchor: HTMLElement): void; runConfirmed(): void }

/**
 * Review variants of how the removal is offered (#486, owner picks): `?removalui=foot` (default, a danger row that opens the
 * glass confirmation card), `menu` (a ⋯ button in the header opens a menu whose entry opens that card) and `inline`
 * (the row turns into the question inside the panel). Only `foot` is in this chunk; the others load when asked for.
 */
function removalVariant(): "foot" | "menu" | "inline" {
  const ui = new URLSearchParams(location.search).get("removalui");
  return ui === "menu" || ui === "inline" ? ui : "foot";
}

/** The window header's padding: the gap kept between the popover and its window's edges. */
const INSET = 8;

/** Opens the popover under `anchor`; `onClosed` runs once it has gone. */
export function openDetailsPopover(
  stage: HTMLElement,
  anchor: HTMLElement,
  input: DetailsInput,
  source: "pointer" | "keyboard",
  onClosed: () => void,
): DetailsPopover {
  const first = input.read();
  const root = document.createElement("section");
  root.className = "canvas-popover ui-overlay-surface";
  root.setAttribute("role", "dialog");
  root.setAttribute("aria-label", `Details for ${first.title}`);
  root.innerHTML = `
    <header class="canvas-popover-head">
      <span class="canvas-popover-logo"></span>
      <span class="canvas-popover-names"><span class="canvas-popover-title"></span><span class="canvas-popover-sub"></span></span>
    </header>
    <div class="canvas-popover-tabs"></div>
    <div class="canvas-popover-scroll"></div>`;
  const logo = root.querySelector<HTMLElement>(".canvas-popover-logo")!;
  const title = root.querySelector<HTMLElement>(".canvas-popover-title")!;
  const subtitle = root.querySelector<HTMLElement>(".canvas-popover-sub")!;
  const updateHeader = (facts: DetailsFacts): void => {
    root.setAttribute("aria-label", `Details for ${facts.title}`);
    title.textContent = facts.title;
    subtitle.textContent = facts.subtitle;
    if (facts.os) {
      logo.innerHTML = hostIconMarkup(facts.os, "ui-host-mark");
      logo.hidden = false;
    } else {
      logo.replaceChildren();
      logo.hidden = true;
    }
  };
  updateHeader(first);

  const list = createKeyValueList(`${first.title} details`);
  const scroll = root.querySelector<HTMLElement>(".canvas-popover-scroll")!;
  scroll.append(list.root);
  const variant = removalVariant();
  if (input.action && variant !== "foot") {
    const action = input.action;
    void import("./details-removal-variants.on-demand").then((m) => { if (root.isConnected) m.mountRemovalVariant(root, variant, action, stage); });
  } else if (input.action) {
    // A destructive action is a row of its own under the facts: the settings row (shared, packages/ui) in its
    // danger tone, its label left on the keys' edge and what it does under it, never a button of centred prose.
    // It asks through the anchored confirmation card.
    const foot = document.createElement("div");
    foot.className = "canvas-popover-action ui-sp-list";
    foot.dataset.stacked = "";
    const row = document.createElement("button");
    row.type = "button";
    row.className = "ui-sp-row";
    row.dataset.tone = "danger";
    row.innerHTML = '<span class="ui-sp-text"><span class="ui-sp-label"></span><span class="ui-sp-hint"></span></span>';
    row.querySelector<HTMLElement>(".ui-sp-label")!.textContent = input.action.label;
    row.querySelector<HTMLElement>(".ui-sp-hint")!.textContent = input.action.hint ?? "";
    row.addEventListener("click", () => input.action?.run(row));
    foot.append(row);
    root.append(foot);
  }
  let scrolled = false;
  scroll.addEventListener("scroll", () => { scrolled = true; }, { passive: true });
  let selected = first.sections[0]?.id ?? "";
  const show = (id: string, animate: boolean): void => {
    selected = id;
    const facts = input.read();
    updateHeader(facts);
    list.root.setAttribute("aria-label", `${facts.title} details`);
    const section = facts.sections.find((x) => x.id === id) ?? first.sections[0];
    list.set((section?.rows ?? []).filter((row) => row.value.trim() !== ""));
    // Resetting the scroll position forces a layout; only a popover that was scrolled needs it.
    if (scrolled) { scroll.scrollTop = 0; scrolled = false; }
    if (animate && !matchMedia("(prefers-reduced-motion: reduce)").matches) {
      list.root.animate([{ opacity: 0 }, { opacity: 1 }], { duration: 140, easing: EASE_OUT });
    }
  };
  const tabs = createCapsuleTabs(first.sections.map((s) => ({ id: s.id, label: s.label, icon: s.icon })), first.sections[0]?.id ?? "", (id, how) => show(id, how === "pointer"), "Details", true);
  root.querySelector(".canvas-popover-tabs")!.append(tabs.root);
  show(first.sections[0]?.id ?? "", false);

  // ---- placement: inside the window, under the pill, one inset on every side ----------
  // The inset equals the window header's padding, so at its maximum height the popover sits
  // in its window with the same gap on the left, right and bottom as the pill has at the
  // top. The visible viewport and the key tray only ever shrink it further.
  const place = (): void => {
    const pill = anchor.getBoundingClientRect();
    const win = anchor.closest(".ui-window")?.getBoundingClientRect() ?? pill;
    const screen = stage.getBoundingClientRect();
    const frame = parseFloat(getComputedStyle(anchor.closest(".ui-window") ?? anchor).borderLeftWidth) || 0;
    const inset = INSET + frame;
    const width = Math.min(400 * currentUiScale(), win.width - inset * 2);
    const left = Math.round(Math.max(win.left + inset, Math.min(pill.left, win.right - inset - width)));
    const top = Math.round(pill.bottom + INSET);
    const tray = stage.querySelector<HTMLElement>("#keybar");
    const trayTop = tray && getComputedStyle(tray).display !== "none" ? tray.getBoundingClientRect().top : screen.bottom;
    const bottom = Math.min(win.bottom - inset, trayTop - INSET, (window.visualViewport?.height ?? innerHeight) - INSET);
    root.style.left = `${left - screen.left}px`;
    root.style.top = `${top - screen.top}px`;
    root.style.width = `${Math.round(width)}px`;
    root.style.maxHeight = `${Math.max(0, Math.floor(bottom - top))}px`;
    root.style.transformOrigin = `${Math.round(pill.left + pill.width / 2 - left)}px 0`;
  };
  // Placed before it is attached: every measurement (the pill, the window, the stage, the key tray) is read
  // while no new content is pending, so the browser lays out once, after the single write below.
  place();
  stage.append(root);

  if (source === "pointer" && !matchMedia("(prefers-reduced-motion: reduce)").matches) {
    root.animate([
      { opacity: 0, transform: "translateY(-4px) scale(0.96)" },
      { opacity: 1, transform: "none" },
    ], { duration: 200, easing: EASE_OUT });
  } else if (source === "pointer") {
    root.animate([{ opacity: 0 }, { opacity: 1 }], { duration: 160, easing: EASE_OUT });
  }
  anchor.setAttribute("aria-expanded", "true");

  let closed = false;
  const events = new AbortController();
  const close = (how: "pointer" | "keyboard"): void => {
    if (closed) return;
    closed = true;
    events.abort();
    anchor.setAttribute("aria-expanded", "false");
    const done = (): void => { tabs.dispose(); list.dispose(); root.remove(); onClosed(); };
    if (how === "keyboard" || matchMedia("(prefers-reduced-motion: reduce)").matches) { done(); return; }
    root.style.pointerEvents = "none";
    root.animate([
      { opacity: 1, transform: "none" },
      { opacity: 0, transform: "translateY(-2px) scale(0.98)" },
    ], { duration: 130, easing: EASE_OUT, fill: "forwards" }).onfinish = done;
  };
  // Outside presses close it (the pill toggles it itself); Escape closes it instantly.
  document.addEventListener("pointerdown", (event) => {
    const target = event.target as Node;
    // The host-actions menu opened from the card's ⋯ (a review variant, #486) belongs to the card.
    if (root.contains(target) || anchor.contains(target) || (target instanceof Element && target.closest(".ui-window-menu"))) return;
    close("pointer");
  }, { capture: true, signal: events.signal });
  document.addEventListener("keydown", (event) => {
    // A pane inside the popover that owns Escape (the access-level consent) takes this one; the popover closes on the next.
    if (event.key === "Escape" && !(event.target instanceof Element && event.target.closest("[data-owns-escape]"))) { event.stopPropagation(); close("keyboard"); anchor.focus({ preventScroll: true }); }
  }, { capture: true, signal: events.signal });
  window.addEventListener("resize", () => place(), { signal: events.signal });
  window.visualViewport?.addEventListener("resize", () => place(), { signal: events.signal });
  if (source === "keyboard") root.querySelector<HTMLElement>(".ui-tab[aria-selected='true']")?.focus({ preventScroll: true });

  return { windowId: input.windowId, close, refresh: () => show(selected, false) };
}

export interface DetailsModule {
  /** Opens the popover for a window, or closes it when it is that window's. */
  toggle(rec: WinRec, source: "pointer" | "keyboard"): void;
  /** Closes it (instantly when `instant`). */
  close(instant?: boolean): void;
  isOpen(): boolean;
  dispose(): void;
}

export function createDetails(cx: Ctx, source: DetailsSource): DetailsModule {
  let open: DetailsPopover | undefined;
  // The "Access level" row (#215) exists only on an instance that can raise the agent's privileges; its code loads with the first popover that needs it.
  let access: import("./access-level.on-demand").AccessLevel | undefined;
  let accessLoading: Promise<void> | undefined;
  const loadAccess = (): Promise<void> => accessLoading ??= cx.adapters.privilege
    ? import("./access-level.on-demand").then((m) => { access = m.createAccessLevel(cx, cx.adapters.privilege!); })
    : Promise.resolve();
  /** Adds the Access level row after Login in the Host tab. */
  const withAccess = (rec: WinRec, facts: DetailsFacts, refresh: () => void): DetailsFacts => {
    if (!access || rec.model.kind !== "terminal") return facts;
    const rows = facts.sections.find((x) => x.id === "host")?.rows;
    if (!rows) return facts;
    const at = rows.findIndex((r) => r.key === "Login");
    const row = access.row(rec.model.host, rec.model.user ?? "your user", refresh);
    const group = rows[at]?.group;
    rows.splice(at + 1, 0, group ? { ...row, group } : row);
    return facts;
  };
  const close = (instant = false): void => { open?.close(instant ? "keyboard" : "pointer"); };
  const module: DetailsModule = {
    toggle(rec, how) {
      if (open?.windowId === rec.model.id) { open.close(how); return; }
      open?.close("keyboard");
      if (!source.facts(rec)) return;
      if (cx.adapters.privilege && !access) { void loadAccess().then(() => module.toggle(rec, how)); return; }
      let stop = (): void => {};
      let repaint = (): void => {};
      const popover = openDetailsPopover(cx.stage, rec.card.pill, { windowId: rec.model.id, read: () => withAccess(rec, source.facts(rec)!, () => repaint()), ...(rec.model.hostId && cx.adapters.hostRemoval?.label() ? { action: { label: cx.adapters.hostRemoval.label()!, hint: REMOVAL_EFFECT, subject: rec.model.host, run: (anchor: HTMLElement) => cx.adapters.hostRemoval?.remove(rec.model.hostId!, rec.model.host, anchor), runConfirmed: () => cx.adapters.hostRemoval?.remove(rec.model.hostId!, rec.model.host, null, undefined, true) } } : {}) }, how, () => {
        stop();
        if (open === popover) open = undefined;
      });
      open = popover;
      repaint = popover.refresh;
      stop = source.open?.(rec, popover.refresh) ?? stop;
    },
    close,
    isOpen: () => open !== undefined,
    dispose() { open?.close("keyboard"); access?.dispose(); },
  };
  return module;
}
