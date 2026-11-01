/**
 * The version panel (#216): what the sidebar's version pill opens. It is a card inside the sidebar, above the footer, built on
 * the shared sidebar card the Inbox uses (it grows out of the pill and back, the host tree gives way, the pill toggles it).
 * Its body is the shared key/value list, so every fact behaves as it does everywhere else.
 *
 *   infraternal 5a0ec9e                                                     ×     the heading says the version, once
 *   Updates                                  ! 2 updates available — proceed?     one row: lag shows by itself
 *   Community edition                                                              the licence section is titled by the edition
 *   Every feature, unlimited hosts, one person
 *
 * What a press does (owner, 2026-11-01: the default action is contextual; copy only when there is none):
 * - the Updates value is the row's action (updates.ts): it checks every host together, then asks "proceed?", then updates;
 *   it never copies;
 * - the heading has no action of its own, so it copies the whole build id;
 * - the licence lines are plain text with no action, so each copies its own text.
 *
 * No word is said twice: the heading is the version (no "Version" row), the section title is the edition (no "Edition" row),
 * and a value never repeats its key. A licence that needs a word gets one sentence under the list, and only then. No prices.
 * Community is free, one person, every feature, unlimited hosts (D32).
 *
 * Not here yet: entering a licence key and the release notes. Both need a backend the product does not have (the key is
 * checked offline against the signing key's public half, D31; release notes need a place to read them); the source decides,
 * and the panel shows them only when it can (`releaseNotes`).
 */
import { ICONS } from "../../../../../packages/ui/src/icons";
import { installCopyCells, createKeyValueList, type KeyValueRow } from "../../../../../packages/ui/src/kv-list";
import { createSidebarCard } from "../../../../../packages/ui/src/sidebar-card";
import { morphSidebarCard, type CardSource, type MorphingCard } from "../../../../../packages/ui/src/sidebar-card-morph";
import { watchScrollFade } from "../../../../../packages/ui/src/scroll-fade";
import { el } from "../dom";
import type { VersionSource } from "./source";
import type { FleetController } from "./updates";
import { endLine, licenceLabel, licenceNote, panelTitle, peopleLine, seatsNearlyFull, effectiveTier, updatesLine } from "./words";

export interface VersionPanelEnv {
  /** The sidebar, and the footer the card sits directly above. */
  parent: HTMLElement;
  before: Element | null;
  /** The pill: it toggles the panel, shows `aria-expanded`, and keeps Escape for the panel while it is open. */
  anchor: HTMLElement;
  source: VersionSource;
  fleet: FleetController;
}

export interface VersionPanel {
  readonly root: HTMLElement;
  isOpen(): boolean;
  /** `focus`: move focus into the panel (a palette action opened it; a press on the pill keeps focus on the pill). */
  open(focus: boolean, source?: CardSource): void;
  close(focusPill: boolean, source?: CardSource): void;
  dispose(): void;
}

interface Built { list: ReturnType<typeof createKeyValueList>; note: HTMLElement; heading: HTMLButtonElement; headingText: Text; stop(): void }

export function createVersionPanel(env: VersionPanelEnv): VersionPanel {
  const { source, fleet, anchor } = env;
  let built: Built | undefined;
  // The card grows out of the pill and back (sidebar-card-morph.ts); the shell itself is the one the Inbox uses.
  const card: MorphingCard = morphSidebarCard(createSidebarCard({
    parent: env.parent, before: env.before, label: "Version and updates", className: "cl-vp",
  }), anchor);
  const closeButton = el("button", "ui-sidebar-card-close");
  closeButton.type = "button";
  closeButton.dataset.tip = "Close";
  closeButton.setAttribute("aria-label", "Close version and updates");
  closeButton.innerHTML = `<svg viewBox="0 0 24 24" aria-hidden="true">${ICONS.close}</svg>`;
  card.header.append(closeButton);

  const rows = (): KeyValueRow[] => {
    const facts = source.facts();
    const line = updatesLine(fleet.view());
    const out: KeyValueRow[] = [{
      key: "Updates", value: line.value, copy: line.value, ...(line.mark ? { mark: line.mark } : {}),
      press: { tip: line.tip, run: () => { void fleet.press(); } },
    }];
    if (facts.releaseNotes) {
      const url = facts.releaseNotes;
      out.push({ key: "What's new", value: "What's new", wide: true, copy: url, press: { tip: "Open the release notes", run: () => { window.open(url, "_blank", "noopener,noreferrer"); } } });
    }
    // The licence section is titled by the edition itself; its rows never repeat that word.
    const { licence } = facts;
    const group = licenceLabel(licence);
    const add = (row: KeyValueRow): void => { out.push({ group, ...row }); };
    if (effectiveTier(licence) === "community") {
      if (licence.endedTier) {
        const end = endLine(licence);
        add({ key: end.key, value: end.value, wide: true, mark: "off" });
      } else add({ key: "Includes", value: "Every feature, unlimited hosts, one person", wide: true });
    } else {
      if (licence.people) {
        add({ key: "People", value: peopleLine(licence.people), ...(seatsNearlyFull(licence.people) ? { mark: "warn" as const } : {}), meter: (licence.people.used / licence.people.max) * 100 });
      }
      const end = endLine(licence);
      add({ key: end.key, value: end.value, ...(licence.days !== undefined && licence.days <= 14 ? { mark: "warn" as const } : {}) });
    }
    return out;
  };

  const render = (): void => {
    if (!built) return;
    const facts = source.facts();
    built.headingText.data = panelTitle(facts);
    built.heading.dataset.copy = facts.copy;
    built.list.set(rows());
    const words = licenceNote(facts.licence);
    built.note.textContent = words ?? "";
    built.note.toggleAttribute("hidden", !words);
  };

  /** Builds the contents on the first open: nothing here is needed to paint the sidebar. */
  const build = (): Built => {
    const heading = el("button", "ui-kv-cell ui-kv-key cl-vp-heading");
    heading.type = "button";
    heading.setAttribute("aria-description", "Copies the build id to the clipboard");
    const run = el("span", "ui-kv-text");
    const headingText = document.createTextNode("");
    run.append(headingText);
    heading.append(run);
    // The title is a span of the shared card; the heading is the cell that copies it (no action of its own, so it copies).
    card.title.replaceChildren(heading);
    const stopCopy = installCopyCells(card.header, () => undefined);
    const list = createKeyValueList("Version and updates");
    const note = el("p", "cl-vp-note");
    const body = el("div", "cl-vp-body");
    body.append(list.root, note);
    card.root.append(body);
    const stopFade = watchScrollFade(body);
    // The rows follow the fleet and the facts while the panel is closed too, so a warm open has nothing to rebuild.
    const stopFleet = fleet.onChange(render);
    const stopSource = source.onChange(render);
    return { list, note, heading, headingText, stop: () => { stopFleet(); stopSource(); stopFade(); stopCopy(); list.dispose(); } };
  };

  const setOpen = (open: boolean): void => {
    anchor.setAttribute("aria-expanded", String(open));
    // While the panel is open, Escape on the pill or inside the panel closes the panel and keeps the sidebar.
    anchor.toggleAttribute("data-owns-escape", open);
    if (open) card.root.setAttribute("data-owns-escape", "page"); else card.root.removeAttribute("data-owns-escape");
  };

  const open = (focus: boolean, how: CardSource = "pointer"): void => {
    if (card.isOpen()) return;
    if (!built) { built = build(); render(); }
    // Next to the pill that opens it, below an Inbox that may be showing.
    if (card.root.nextElementSibling !== env.before) env.parent.insertBefore(card.root, env.before);
    card.show(how);
    setOpen(true);
    if (focus) closeButton.focus({ preventScroll: true });
  };
  const close = (focusPill: boolean, how: CardSource = "pointer"): void => {
    if (!card.isOpen()) return;
    const inside = card.root.contains(document.activeElement);
    card.hide(how);
    setOpen(false);
    if (focusPill || inside) anchor.focus({ preventScroll: true });
  };

  closeButton.addEventListener("click", (event) => close(true, event.detail === 0 ? "keyboard" : "pointer"));
  const onKey = (event: KeyboardEvent): void => {
    if (event.key !== "Escape" || !card.isOpen()) return;
    event.preventDefault();
    event.stopPropagation();
    close(true, "keyboard");
  };
  card.root.addEventListener("keydown", onKey);
  anchor.addEventListener("keydown", onKey);
  // The listener is on the window's capture phase, ahead of the core screen's own Escape handling (which would close the sidebar).
  // A press on the pill leaves focus on the page in browsers that do not focus a button on click (Safari), so Escape would
  // never reach the card or the pill. While the panel is open, Escape closes it from anywhere, unless something above it
  // (the palette, Settings, the shortcuts list) is open and takes the key for itself.
  const onPage = (event: KeyboardEvent): void => {
    if (event.key !== "Escape" || !card.isOpen() || event.defaultPrevented) return;
    if (document.querySelector(".palette:not([hidden]), .ui-settings, .ui-shortcuts, .canvas-popover, .ui-anchored-popover")) return;
    event.preventDefault();
    event.stopPropagation();
    close(true, "keyboard");
  };
  window.addEventListener("keydown", onPage, true);

  return {
    root: card.root,
    isOpen: () => card.isOpen(),
    open,
    close,
    dispose() { window.removeEventListener("keydown", onPage, true); built?.stop(); card.dispose(); setOpen(false); },
  };
}
