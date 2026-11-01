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

export interface DetailsPopover {
  readonly windowId: string;
  close(source: "pointer" | "keyboard"): void;
  refresh(): void;
}

interface DetailsInput {
  windowId: string;
  /** Read at open and each time a tab is shown. */
  read: () => DetailsFacts;
  /** A destructive action under the facts: its short name, what it does (optional) and what runs, anchored to its row. */
  action?: { label: string; hint?: string; run(anchor: HTMLElement): void };
}

const EASE = "cubic-bezier(0.23, 1, 0.32, 1)";
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
  if (input.action) {
    // A destructive action is a row of its own under the facts: the settings row (shared, packages/ui) in its
    // danger tone, its label left on the keys' edge and what it does under it, never a button of centred prose.
    // It asks through the anchored confirmation for now; TASTE asks for the in-row question (#242, #291).
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
      list.root.animate([{ opacity: 0 }, { opacity: 1 }], { duration: 140, easing: EASE });
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
    ], { duration: 200, easing: EASE });
  } else if (source === "pointer") {
    root.animate([{ opacity: 0 }, { opacity: 1 }], { duration: 160, easing: "ease" });
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
    ], { duration: 130, easing: EASE, fill: "forwards" }).onfinish = done;
  };
  // Outside presses close it (the pill toggles it itself); Escape closes it instantly.
  document.addEventListener("pointerdown", (event) => {
    const target = event.target as Node;
    if (root.contains(target) || anchor.contains(target)) return;
    close("pointer");
  }, { capture: true, signal: events.signal });
  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape") { event.stopPropagation(); close("keyboard"); anchor.focus({ preventScroll: true }); }
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
  const close = (instant = false): void => { open?.close(instant ? "keyboard" : "pointer"); };
  return {
    toggle(rec, how) {
      if (open?.windowId === rec.model.id) { open.close(how); return; }
      open?.close("keyboard");
      if (!source.facts(rec)) return;
      let stop = (): void => {};
      const popover = openDetailsPopover(cx.stage, rec.card.pill, { windowId: rec.model.id, read: () => source.facts(rec)!, ...(rec.model.hostId && cx.adapters.hostRemoval?.label() ? { action: { label: "Remove host", hint: cx.adapters.hostRemoval.label()!, run: (anchor: HTMLElement) => cx.adapters.hostRemoval?.remove(rec.model.hostId!, rec.model.host, anchor) } } : {}) }, how, () => {
        stop();
        if (open === popover) open = undefined;
      });
      open = popover;
      stop = source.open?.(rec, popover.refresh) ?? stop;
    },
    close,
    isOpen: () => open !== undefined,
    dispose() { open?.close("keyboard"); },
  };
}
