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
import { keyboardIsOpen, watchKeyboard } from "../../keyboard-viewport";
import { createCapsuleTabs } from "../../../../../packages/ui/src/capsule-tabs";
import { hostIconMarkup } from "../../../../../packages/ui/src/host-icons";
import { createKeyValueList } from "../../../../../packages/ui/src/kv-list";
import type { Ctx, WinRec } from "../context";
import type { DetailsFacts, DetailsSource } from "./details-source";
import { currentUiScale } from "../../../../../packages/ui/src/ui-scale";
import { EASE_OUT } from "../../../../../packages/ui/src/motion";
import { REMOVAL_EFFECT } from "../host-removal-confirm";
import { createRemovalFoot, type DetailsAction, type RemovalStatus } from "./details-removal";

export interface DetailsPopover {
  readonly windowId: string;
  close(source: "pointer" | "keyboard"): void;
  refresh(): void;
}

/** What the popover shows and can do: the facts to read, and the optional destructive action. */
interface DetailsInput {
  windowId: string;
  /** Read at open and each time a tab is shown. */
  read: () => DetailsFacts;
  /** The destructive action at the end of the Connection tab (remove host, D385); it asks inside the panel. */
  action?: DetailsAction;
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
  // D385: Remove host sits at the end of the Connection tab only, inline: its row turns into the question in the panel.
  const removal = input.action ? createRemovalFoot(input.action) : undefined;
  if (removal) {
    removal.root.hidden = true;
    scroll.append(removal.root);
    // A removal that went through closes the card (its window goes with the host); a failure or refusal stays, said inline.
    removal.onOutcome = (outcome) => { if (outcome.state === "removed") close("pointer"); };
  }
  let scrolled = false;
  scroll.addEventListener("scroll", () => { scrolled = true; }, { passive: true });
  let selected = first.sections[0]?.id ?? "";
  /**
   * Draws tab `id`. `tabChange` is true only when the person picked a tab: the list then starts from the top. A refresh
   * (the facts poll repaints about once a second) passes false and keeps the scroll position, so reading further down
   * the panel is never undone by new data (J508).
   */
  const show = (id: string, animate: boolean, tabChange = true): void => {
    selected = id;
    const facts = input.read();
    updateHeader(facts);
    list.root.setAttribute("aria-label", `${facts.title} details`);
    const section = facts.sections.find((x) => x.id === id) ?? first.sections[0];
    list.set((section?.rows ?? []).filter((row) => row.value.trim() !== ""));
    if (removal) {
      // Leaving the tab takes an open question back to the row (a refresh on the tab itself must not); the host's state is read each time.
      if (section?.id !== "connection") removal.reset();
      removal.root.hidden = section?.id !== "connection";
      removal.sync();
    }
    // Resetting the scroll position forces a layout; only a popover that was scrolled needs it.
    if (tabChange && scrolled) { scroll.scrollTop = 0; scrolled = false; }
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
    const bottom = Math.min(win.bottom - inset, trayTop - INSET, (keyboardIsOpen() ? window.visualViewport?.height ?? innerHeight : innerHeight) - INSET);
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
    if (root.contains(target) || anchor.contains(target)) return;
    close("pointer");
  }, { capture: true, signal: events.signal });
  document.addEventListener("keydown", (event) => {
    // A pane inside the popover that owns Escape (the access-level consent) takes this one; the popover closes on the next.
    if (event.key === "Escape" && !(event.target instanceof Element && event.target.closest("[data-owns-escape]"))) { event.stopPropagation(); close("keyboard"); anchor.focus({ preventScroll: true }); }
  }, { capture: true, signal: events.signal });
  window.addEventListener("resize", () => place(), { signal: events.signal });
  // The keyboard watcher also re-places after focus changes and a settle delay, so a panel never keeps a keyboard-sized height.
  const stopKeyboardWatch = watchKeyboard(() => place());
  events.signal.addEventListener("abort", stopKeyboardWatch, { once: true });
  if (source === "keyboard") root.querySelector<HTMLElement>(".ui-tab[aria-selected='true']")?.focus({ preventScroll: true });

  return { windowId: input.windowId, close, refresh: () => show(selected, false, false) };
}

/** Controls the one open machine panel and keeps it aligned with its window identity. */
export interface DetailsModule {
  /** Opens the popover for a window, or closes it when it is that window's. */
  toggle(rec: WinRec, source: "pointer" | "keyboard"): void;
  /** Closes it (instantly when `instant`). */
  close(instant?: boolean): void;
  /** Re-read an open window after its host identity changes, keeping the loading state current. */
  refresh(windowId: string): void;
  isOpen(): boolean;
  dispose(): void;
}

/** The host's state for the removal question: gone when the host list no longer has it, offline when the server last saw its infraternal agent disconnected. */
function hostStatus(cx: Ctx, hostId: string): RemovalStatus {
  const entry = cx.adapters.sessions.hosts().find((h) => h.id === hostId);
  return !entry ? "gone" : entry.online === false ? "offline" : "ready";
}

/** Own the one open details panel, repaint it when its window target changes, and add the product's extra rows and removal action. */
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
      const popover = openDetailsPopover(cx.stage, rec.card.pill, { windowId: rec.model.id, read: () => withAccess(rec, source.facts(rec)!, () => repaint()), ...(rec.model.hostId && cx.adapters.hostRemoval?.label() ? { action: { label: cx.adapters.hostRemoval.label()!, hint: REMOVAL_EFFECT, subject: rec.model.host, status: () => hostStatus(cx, rec.model.hostId!), runConfirmed: async () => (await cx.adapters.hostRemoval?.remove(rec.model.hostId!, rec.model.host, null, undefined, true)) ?? { state: "refused", message: "Removing hosts is not available right now." } } } : {}) }, how, () => {
        stop();
        if (open === popover) open = undefined;
      });
      open = popover;
      repaint = popover.refresh;
      stop = source.open?.(rec, popover.refresh) ?? stop;
    },
    close,
    refresh: (windowId) => { if (open?.windowId === windowId) open.refresh(); },
    isOpen: () => open !== undefined,
    dispose() { open?.close("keyboard"); access?.dispose(); },
  };
  return module;
}
