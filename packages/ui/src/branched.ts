/** Builds the accessible host/session tree and updates its current-host indicators. */
import { ICON_DETACHED, icon } from "./icons";
import { onDoubleActivate } from "./double-activate";

import { cssPx } from "./ui-scale";
export interface BranchLeaf {
  id: string;
  label: string;
  glyph?: string;
  meta?: string;
  disabled?: boolean;
  /**
   * What the leaf is, for items that live in states (a session is open, detached or exited): drawn by CSS
   * as the leaf's marker in place of the text glyph, so every list of such items marks them the same way.
   */
  state?: "open" | "detached" | "exited";
  /** A caption between groups of leaves inside one section (a host's name above its sessions): not selectable, no branch. */
  heading?: boolean;
  /** A quiet note after the label: new output (a dot), or the result of a finished command. */
  mark?: "output" | "ok" | "fail";
  /** What the warm tooltip of the mark says, when the default ("Finished successfully", "Failed", "New output") is not enough. */
  markTip?: string;
  /** The label is a name the person may change by double click, double tap, F2 or the row menu (the tree's `rename` option saves it). */
  renamable?: boolean;
  /** The rename field's accessible name ("Session name"). Default "Host name". */
  renameLabel?: string;
}

export interface BranchSection {
  id: string;
  label: string;
  /** Optional single-colour detected-platform mark (for example, a Simple Icons path). */
  icon?: { path: string; viewBox?: string };
  meta?: string;
  live?: boolean;
  open?: boolean;
  disabled?: boolean;
  leaves: BranchLeaf[];
}

export interface BranchedOptions {
  active: string;
  onSelect?: (id: string) => void;
  /**
   * Opens the rename field on a renamable row (a double click or double tap, F2, or the row menu's Rename); false when it cannot.
   * The caller owns the field and the saving (the sidebar's is an on-demand module, D188): this tree only knows which rows
   * may be renamed and what gesture starts it.
   */
  openRename?: (row: HTMLElement) => boolean;
}

export interface BranchedMenu {
  /** `notify` is false only when synchronizing a model update back into the tree. */
  select(id: string, instant?: boolean, notify?: boolean): void;
  /** Opens the rename field on the renamable row with this id (F2 and the row menu; a double click does the same). False when there is none. */
  rename(id: string): boolean;
  dispose(): void;
}

/** The id a list row carries (a leaf's button, or a caption that names a thing), for the row menu. */
export const branchRowId = (row: Element): string | undefined => (row as HTMLElement).dataset.id ?? row.querySelector<HTMLElement>(".bm-leaf")?.dataset.id;

const DETACHED_NAME = "Detached";
const MARK_TIP = { output: "New output", ok: "Finished successfully", fail: "Failed" } as const;
const MARK_NAME ={ output: "new output", ok: "command finished", fail: "command failed" } as const;
const RADIUS = 8;
const STUB = 12;
const EASE = "cubic-bezier(0.23, 1, 0.32, 1)";
const reduced = () => matchMedia("(prefers-reduced-motion: reduce)").matches;

function el<K extends keyof HTMLElementTagNameMap>(tag: K, className: string): HTMLElementTagNameMap[K] {
  const node = document.createElement(tag);
  node.className = className;
  return node;
}

function makeSection(section: BranchSection): HTMLElement {
  const root = el("section", "bm-sec");
  root.dataset.id = section.id;
  root.setAttribute("role", "treeitem");
  const open = Boolean(section.open && section.leaves.length);
  root.setAttribute("aria-expanded", String(open));
  root.toggleAttribute("data-open", open);

  const head = el("button", "bm-head");
  head.type = "button";
  head.disabled = section.disabled || section.leaves.length === 0;
  head.setAttribute("aria-label", `${section.label}${section.meta ? `, ${section.meta}` : ""}`);
  if (section.live) {
    const dot = el("span", "dot live");
    dot.setAttribute("aria-hidden", "true");
    head.append(dot);
  }
  if (section.icon) {
    const icon = el("span", "bm-icon");
    icon.setAttribute("aria-hidden", "true");
    const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
    svg.setAttribute("viewBox", section.icon.viewBox ?? "0 0 24 24");
    const path = document.createElementNS("http://www.w3.org/2000/svg", "path");
    path.setAttribute("d", section.icon.path);
    svg.append(path);
    icon.append(svg);
    head.append(icon);
  }
  const name = el("span", "bm-name");
  name.textContent = section.label;
  const meta = el("span", "bm-meta");
  meta.textContent = section.meta ?? "";
  head.append(name, meta);

  const fold = el("div", "bm-fold");
  const foldInner = el("div", "bm-fold-in");
  const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  svg.classList.add("bm-branches");
  svg.setAttribute("aria-hidden", "true");
  const dim = document.createElementNS("http://www.w3.org/2000/svg", "g");
  dim.classList.add("bm-dim");
  const lit = document.createElementNS("http://www.w3.org/2000/svg", "path");
  lit.classList.add("bm-lit");
  lit.setAttribute("pathLength", "1");
  svg.append(dim, lit);

  const list = el("ul", "bm-list");
  list.setAttribute("role", "group");
  for (const leaf of section.leaves) {
    if (leaf.heading) {
      const caption = el("li", "bm-row bm-subhead");
      // A caption that names a thing (a host) is a row of its own for the row menu (D309): focusable, so the menu key reaches it.
      if (leaf.id) {
        const name = el("span", "bm-label");
        name.textContent = leaf.label;
        caption.append(name);
        caption.dataset.id = leaf.id;
        caption.setAttribute("role", "treeitem");
        caption.tabIndex = 0;
        if (leaf.renamable) { caption.dataset.renamable = ""; if (leaf.renameLabel) caption.dataset.renameLabel = leaf.renameLabel; }
      } else {
        caption.textContent = leaf.label;
        caption.setAttribute("role", "presentation");
      }
      list.append(caption);
      continue;
    }
    const row = el("li", "bm-row");
    row.setAttribute("role", "treeitem");
    const button = el("button", "bm-leaf");
    button.type = "button";
    button.dataset.id = leaf.id;
    if (leaf.renamable) { button.dataset.renamable = ""; if (leaf.renameLabel) button.dataset.renameLabel = leaf.renameLabel; }
    button.disabled = Boolean(leaf.disabled);
    const spoken = [leaf.label, leaf.state, leaf.mark ? MARK_NAME[leaf.mark] : "", leaf.meta].filter(Boolean);
    button.setAttribute("aria-label", spoken.join(", "));
    const glyph = el("span", "glyph");
    if (leaf.state) { glyph.className = "glyph ui-state-dot"; glyph.dataset.state = leaf.state; }
    else glyph.textContent = leaf.glyph ?? "›_";
    const label = el("span", "bm-label");
    label.textContent = leaf.label;
    const leafMeta = el("span", "bm-meta");
    if (leaf.state === "detached") {
      // The note for a detached session is an icon, not the word: the hollow dot already says "not open" and the
      // word took a third of the row. The warm tooltip and the accessible name carry the word (TASTE: icons with tooltips).
      leafMeta.classList.add("is-detached");
      leafMeta.dataset.tip = DETACHED_NAME;
      leafMeta.setAttribute("role", "img");
      leafMeta.setAttribute("aria-label", DETACHED_NAME);
      leafMeta.innerHTML = icon(ICON_DETACHED);
    } else leafMeta.textContent = leaf.meta ?? "";
    button.append(glyph, label);
    if (leaf.mark) {
      const mark = el("span", "ui-mark");
      mark.dataset.mark = leaf.mark;
      mark.setAttribute("aria-hidden", "true"); // the row's own name already says it (MARK_NAME)
      mark.dataset.tip = leaf.markTip ?? MARK_TIP[leaf.mark]; // an icon without a tooltip is a bug (TASTE)
      button.append(mark);
    }
    button.append(leafMeta);
    row.append(button);
    list.append(row);
  }
  foldInner.append(svg, list);
  fold.append(foldInner);
  root.append(head, fold);
  return root;
}

/**
 * Builds a tree with a fading trunk, a moving current-host marker, and a drawn-on branch.
 * Identifiers and labels are installed as DOM text/data rather than interpolated HTML.
 */
export function branchedMenu(
  host: HTMLElement,
  sections: BranchSection[],
  opts: BranchedOptions,
): BranchedMenu {
  host.replaceChildren();
  host.classList.add("bm");
  host.setAttribute("role", "tree");
  host.setAttribute("aria-label", "Hosts and sessions");

  // The trunk line itself is drawn by each section (`.bm-sec::before`, see style.css), so it belongs to the content's
  // own boxes and runs exactly to the last row however long the list is. Only the moving marker is a child of the host.
  const markerEl = el("span", "bm-marker");
  markerEl.setAttribute("aria-hidden", "true");
  host.append(markerEl, ...sections.map(makeSection));

  const marker = host.querySelector<HTMLElement>(".bm-marker")!;
  let active = opts.active;
  let disposed = false;

  const drawOn = new WeakMap<SVGPathElement, Animation>();
  const pathFor = (x: number, center: number): string =>
    `M ${x} 0 V ${center - RADIUS} Q ${x} ${center} ${x + RADIUS} ${center} H ${x + RADIUS + STUB}`;

  /**
   * Two passes, so the browser lays out once: every measurement first (widths, heights, row offsets,
   * the branch's x), then every write (svg sizes, paths, classes, the marker). Interleaving a write
   * before the next section's reads forced a layout per section and per leaf.
   */
  function layout(animate: boolean): void {
    if (disposed) return;
    let branchX: number | undefined;
    const sections = [...host.querySelectorAll<HTMLElement>(".bm-sec")].map((section) => {
      const list = section.querySelector<HTMLElement>("ul")!;
      const leaves = [...list.querySelectorAll<HTMLElement>(".bm-leaf")];
      branchX ??= cssPx(list, "--bm-x", 0);
      const x = branchX;
      return {
        section, list, leaves, x, width: list.offsetWidth, height: list.offsetHeight,
        centers: leaves.map((leaf) => leaf.parentElement!.offsetTop + leaf.parentElement!.offsetHeight / 2),
      };
    });
    const heads = host.querySelectorAll<HTMLElement>(".bm-sec .bm-head");
    // A section is the head's offset parent (it draws a piece of the trunk), so the head's top is relative to it.
    const headMetrics = [...heads].map((head) => ({ head, top: head.offsetTop + (head.offsetParent as HTMLElement).offsetTop, height: head.offsetHeight }));
    const markerHeight = marker.offsetHeight;

    for (const { section, leaves, x, width, height, centers } of sections) {
      const svg = section.querySelector<SVGSVGElement>(".bm-branches")!;
      const dim = svg.querySelector<SVGGElement>(".bm-dim")!;
      const lit = svg.querySelector<SVGPathElement>(".bm-lit")!;
      svg.setAttribute("width", String(width));
      svg.setAttribute("height", String(height));
      // One path for the whole group: a stroke is composited once however much its subpaths overlap. One path per leaf,
      // each running from the top, stacked their translucent strokes, so the line was opaque at the top of a long list
      // and faded toward its end. The vertical run is drawn once, to the last connector; each leaf adds only its curve.
      const dimPath = document.createElementNS("http://www.w3.org/2000/svg", "path");
      dimPath.setAttribute("d", centers.length
        ? `M ${x} 0 V ${centers.at(-1)! - RADIUS} ${centers.map((center) => `M ${x} ${center - RADIUS} Q ${x} ${center} ${x + RADIUS} ${center} H ${x + RADIUS + STUB}`).join(" ")}`
        : "");
      dim.replaceChildren(dimPath);
      const mineIndex = leaves.findIndex((leaf) => leaf.dataset.id === active);
      lit.style.transition = animate && !reduced() ? `opacity 150ms ${EASE}` : "none";
      // Cancelling by handle: `getAnimations()` flushes style for the whole document.
      if (animate) { drawOn.get(lit)?.cancel(); drawOn.delete(lit); }
      if (mineIndex >= 0) {
        lit.setAttribute("d", pathFor(x, centers[mineIndex]!));
        // The owner approved paint-based draw-on for this small, rarely changed tree.
        if (animate && !reduced()) drawOn.set(lit, lit.animate(
          [{ strokeDashoffset: 1 }, { strokeDashoffset: 0 }],
          { duration: 300, easing: EASE, fill: "both" },
        ));
        lit.style.opacity = "1";
      } else {
        lit.style.opacity = "0";
      }
      leaves.forEach((leaf, index) => leaf.toggleAttribute("aria-current", leaf.dataset.id === active));
      section.classList.toggle("is-current", mineIndex >= 0);
    }

    // The current section changed above; its head is the marker's row (positions were read before).
    const current = sections.find(({ section }) => section.classList.contains("is-current"));
    const currentHead = current ? headMetrics.find(({ head }) => head.parentElement === current.section) : undefined;
    marker.style.opacity = currentHead ? "1" : "0";
    if (currentHead) {
      marker.style.transition = animate && !reduced() ? `transform 280ms ${EASE}` : "none";
      marker.style.transform = `translateY(${Math.round(currentHead.top + (currentHead.height - markerHeight) / 2)}px)`;
    }
  }

  const onClick = (event: MouseEvent): void => {
    const target = event.target;
    if (!(target instanceof Element)) return;
    const leaf = target.closest<HTMLButtonElement>(".bm-leaf");
    if (leaf && !leaf.disabled && leaf.dataset.id) {
      api.select(leaf.dataset.id, event.detail === 0);
      return;
    }
    const head = target.closest<HTMLButtonElement>(".bm-head");
    if (!head || head.disabled) return;
    const section = head.parentElement!;
    const open = !section.hasAttribute("data-open");
    section.toggleAttribute("data-open", open);
    section.setAttribute("aria-expanded", String(open));
    section.classList.toggle("no-motion", event.detail === 0);
  };
  host.addEventListener("click", onClick);

  // Renaming in place: a double click or double tap on a renamable row's name, F2 or the row menu on the focused row. The
  // click that comes first still selects the leaf (a single click keeps its meaning); the field is placed over the name,
  // never inside the button. A row is a leaf (its button) or a caption that names a host.
  const renamableOf = (from: Element | null): HTMLElement | undefined => from?.closest<HTMLElement>("[data-renamable][data-id]") ?? undefined;
  const leafOf = (event: Event): HTMLElement | undefined => (event.target instanceof Element ? renamableOf(event.target) : undefined);
  const abort = new AbortController();
  if (opts.openRename) {
    // The key is the first press's row id: the tree is rebuilt, and re-sorted, between the two presses.
    onDoubleActivate(host, (event, key) => {
      const row = typeof key === "string" ? [...host.querySelectorAll<HTMLElement>("[data-renamable][data-id]")].find((n) => n.dataset.id === key) : leafOf(event);
      if (row) opts.openRename!(row);
    }, abort.signal, (event) => leafOf(event)?.dataset.id); // by id: the tree is rebuilt between the two taps, its buttons are new
  }

  // Observe folds as well as the host so branch geometry stays aligned after a fold toggles.
  const observer = new ResizeObserver(() => layout(false));
  observer.observe(host);
  for (const fold of host.querySelectorAll<HTMLElement>(".bm-fold")) observer.observe(fold);

  const api: BranchedMenu = {
    select(id, instant = false, notify = true) {
      active = id;
      layout(!instant);
      if (notify) opts.onSelect?.(id);
    },
    rename(id) {
      const row = [...host.querySelectorAll<HTMLElement>("[data-renamable][data-id]")].find((n) => n.dataset.id === id);
      return row ? opts.openRename?.(row) ?? false : false;
    },
    dispose() {
      disposed = true;
      observer.disconnect();
      host.removeEventListener("click", onClick);
      abort.abort();
    },
  };
  // No first layout here: the observer above reports the host after the browser's own layout and before paint, so the
  // first measurement costs no extra forced layout inside the mount task.
  return api;
}
