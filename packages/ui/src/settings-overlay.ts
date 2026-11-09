/**
 * The Settings overlay shell (D160): one floating card in the shared overlay material, with a
 * list of sections on the left (a single row on a phone) and the open section on the right.
 * Only the About section is filled today; Settings itself is not built yet, so this is the
 * shell its sections will hang on, not a one-off. A section is `{ id, title, icon, render }`,
 * where `render(container)` fills the pane and may return a disposer.
 *
 * About is the build's facts as a shared key/value list: tap or click a value to copy it; the text fades
 * out and a clipboard icon with "Copied" replaces it in place (no copy buttons, no tooltip).
 *
 * Motion: a pointer open scales in from 0.96 with opacity (200 ms strong ease-out), closing is
 * quicker; keyboard opens and closes are instant. Escape, the close icon and a press outside
 * close it. Focus returns to whatever opened it.
 *
 *   const settings = createSettingsOverlay({ stage, sections: [aboutSection(info)] });
 *   settings.open("about", "pointer");
 */
import type { KeyValueRow } from "./kv-list";
import { EASE_OUT } from "./motion";

/** One entry of the settings list: a stable `id`, the `title`, an `icon` and `render`, which fills the pane and may return a function that cleans up when the pane closes. */
export interface SettingsSection {
  id: string;
  title: string;
  /** Inner SVG markup on a 24 grid, stroked. */
  icon: string;
  render(container: HTMLElement): (() => void) | void;
}

/** `stage` is the element the overlay card is mounted in; `sections` is the list shown, the first being the default. */
export interface SettingsOverlayOptions {
  stage: HTMLElement;
  sections: SettingsSection[];
}

/** The handle returned by {@link createSettingsOverlay}. `open` falls back to the first section for an unknown id; `source` says whether the keyboard or the pointer asked, because keyboard changes skip the animation. */
export interface SettingsOverlay {
  readonly isOpen: boolean;
  open(section: string, source: "pointer" | "keyboard"): void;
  close(source: "pointer" | "keyboard"): void;
  dispose(): void;
}

/** The build facts the About section lists. */
export interface AboutInfo {
  name: string;
  version: string;
  commit: string;
  /** ISO timestamp of the build, or empty when unknown. */
  built: string;
}

/** The strong ease-out curve of the open and close motion. */
/** The About section's icon, as inner SVG markup. */
const INFO_ICON = '<circle cx="12" cy="12" r="9"/><path d="M12 11v5M12 8h.01"/>';
/** The close button's icon, as inner SVG markup. */
const CLOSE_ICON = '<path d="m7 7 10 10M17 7 7 17"/>';

/** "2026-10-08 14:03 UTC" from an ISO string; the empty string stays empty. */
const formatBuilt = (iso: string): string => {
  const date = new Date(iso);
  return Number.isNaN(date.getTime()) ? "" : `${date.toISOString().slice(0, 16).replace("T", " ")} UTC`;
};

/**
 * The About section: name, version, commit, build date. Its list is the shared key/value list, which the first screen does
 * not need, so it loads when About is opened (`fact-list.on-demand.ts`, a chunk of its own, D188) and is fetched when the
 * page is idle, so the first open shows its rows at once. The section is empty for the frame or two the chunk takes if it is
 * not there yet.
 */
export function aboutSection(info: AboutInfo): SettingsSection {
  const short = info.commit.slice(0, 7);
  const rows: KeyValueRow[] = [
    { key: "Name", value: info.name },
    { key: "Version", value: short, copy: info.commit },
    { key: "Commit", value: info.commit },
    ...(formatBuilt(info.built) ? [{ key: "Built", value: formatBuilt(info.built), copy: info.built }] : []),
  ];
  const idle = (window as unknown as { requestIdleCallback?: (run: () => void) => number }).requestIdleCallback;
  if (idle) idle(() => { void import("./fact-list.on-demand"); }); else window.setTimeout(() => { void import("./fact-list.on-demand"); }, 1500);
  return {
    id: "about",
    title: "About",
    icon: INFO_ICON,
    render(container) {
      let stop: (() => void) | undefined, gone = false;
      void import("./fact-list.on-demand").then((m) => { if (!gone) stop = m.renderFactList(container, "About infraternal", rows); });
      return () => { gone = true; stop?.(); };
    },
  };
}

/** Builds the overlay in `options.stage`; nothing is shown until `open` is called. */
export function createSettingsOverlay(options: SettingsOverlayOptions): SettingsOverlay {
  const { stage, sections } = options;
  const reduced = matchMedia("(prefers-reduced-motion: reduce)");
  let root: HTMLElement | undefined;
  let disposePane: (() => void) | void;
  let restore: HTMLElement | null = null;
  let controller: AbortController | undefined;

  const teardown = (): void => {
    disposePane?.();
    disposePane = undefined;
    root?.remove();
    root = undefined;
    if (restore?.isConnected) restore.focus({ preventScroll: true });
    restore = null;
  };

  const close = (source: "pointer" | "keyboard"): void => {
    const node = root;
    if (!node || controller === undefined) return;
    controller.abort();
    controller = undefined;
    if (source === "keyboard") { teardown(); return; }
    node.style.pointerEvents = "none";
    node.animate(reduced.matches ? [{ opacity: 1 }, { opacity: 0 }] : [{ opacity: 1, transform: "none" }, { opacity: 0, transform: "scale(0.98)" }],
      { duration: 130, easing: EASE_OUT, fill: "forwards" }).onfinish = () => { if (root === node) teardown(); };
  };

  const open = (sectionId: string, source: "pointer" | "keyboard"): void => {
    const section = sections.find((entry) => entry.id === sectionId) ?? sections[0];
    if (!section) return;
    if (root) { controller?.abort(); teardown(); }
    restore = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    const card = document.createElement("section");
    card.className = "ui-settings ui-overlay-surface";
    card.dataset.overlaySize = "large";
    card.setAttribute("role", "dialog");
    card.setAttribute("aria-label", "Settings");
    card.tabIndex = -1;
    card.innerHTML = `
      <header class="ui-settings-head"><span class="ui-settings-title">Settings</span>
        <button class="ui-window-action ui-settings-close" type="button" aria-label="Close" data-tip="Close"><svg viewBox="0 0 24 24" aria-hidden="true">${CLOSE_ICON}</svg></button></header>
      <div class="ui-settings-main"><nav class="ui-settings-nav" aria-label="Settings sections"></nav><div class="ui-settings-pane" role="region"></div></div>`;
    const nav = card.querySelector<HTMLElement>(".ui-settings-nav")!;
    const pane = card.querySelector<HTMLElement>(".ui-settings-pane")!;
    for (const entry of sections) {
      const row = document.createElement("button");
      row.type = "button";
      row.className = "ui-settings-nav-row";
      row.dataset.section = entry.id;
      row.setAttribute("aria-current", String(entry.id === section.id));
      row.innerHTML = `<svg viewBox="0 0 24 24" aria-hidden="true">${entry.icon}</svg><span>${entry.title}</span>`;
      nav.append(row);
    }
    pane.setAttribute("aria-label", section.title);
    disposePane = section.render(pane);
    stage.append(card);
    root = card;
    controller = new AbortController();
    const { signal } = controller;
    card.querySelector(".ui-settings-close")!.addEventListener("click", () => close("pointer"), { signal });
    document.addEventListener("keydown", (event) => {
      if (event.key !== "Escape") return;
      event.preventDefault();
      event.stopPropagation();
      close("keyboard");
    }, { capture: true, signal });
    document.addEventListener("pointerdown", (event) => {
      if (event.target instanceof Node && !card.contains(event.target) && !(event.target as Element).closest?.(".tip, .ui-sidebar-foot")) close("pointer");
    }, { capture: true, signal });
    card.focus({ preventScroll: true });
    if (source === "pointer") {
      card.animate(reduced.matches ? [{ opacity: 0 }, { opacity: 1 }] : [{ opacity: 0, transform: "scale(0.96)" }, { opacity: 1, transform: "none" }],
        { duration: 200, easing: EASE_OUT });
    }
  };

  return {
    get isOpen() { return root !== undefined && controller !== undefined; },
    open,
    close,
    dispose() { controller?.abort(); controller = undefined; teardown(); },
  };
}
