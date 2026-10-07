/** Builds the accessible host/session tree and updates its current-host indicators. */

export interface BranchLeaf {
  id: string;
  label: string;
  glyph?: string;
  meta?: string;
  disabled?: boolean;
}

export interface BranchSection {
  id: string;
  label: string;
  meta?: string;
  live?: boolean;
  open?: boolean;
  disabled?: boolean;
  leaves: BranchLeaf[];
}

export interface BranchedMenu {
  select(id: string, instant?: boolean): void;
  dispose(): void;
}

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
    const row = el("li", "bm-row");
    row.setAttribute("role", "treeitem");
    const button = el("button", "bm-leaf");
    button.type = "button";
    button.dataset.id = leaf.id;
    button.disabled = Boolean(leaf.disabled);
    button.setAttribute("aria-label", `${leaf.label}${leaf.meta ? `, ${leaf.meta}` : ""}`);
    const glyph = el("span", "glyph");
    glyph.textContent = leaf.glyph ?? "›_";
    const label = el("span", "bm-label");
    label.textContent = leaf.label;
    const leafMeta = el("span", "bm-meta");
    leafMeta.textContent = leaf.meta ?? "";
    button.append(glyph, label, leafMeta);
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
  opts: { active: string; onSelect?: (id: string) => void },
): BranchedMenu {
  host.replaceChildren();
  host.classList.add("bm");
  host.setAttribute("role", "tree");
  host.setAttribute("aria-label", "Hosts and sessions");

  const trunk = el("div", "bm-trunk");
  trunk.setAttribute("aria-hidden", "true");
  trunk.append(el("span", "bm-marker"));
  host.append(trunk, ...sections.map(makeSection));

  const marker = host.querySelector<HTMLElement>(".bm-marker")!;
  let active = opts.active;
  let disposed = false;

  const branch = (list: HTMLElement, row: HTMLElement): string => {
    const x = Number.parseFloat(getComputedStyle(list).getPropertyValue("--bm-x")) || 0;
    const center = row.offsetTop + row.offsetHeight / 2;
    return `M ${x} 0 V ${center - RADIUS} Q ${x} ${center} ${x + RADIUS} ${center} H ${x + RADIUS + STUB}`;
  };

  function layout(animate: boolean): void {
    if (disposed) return;
    for (const section of host.querySelectorAll<HTMLElement>(".bm-sec")) {
      const list = section.querySelector<HTMLElement>("ul")!;
      const svg = section.querySelector<SVGSVGElement>(".bm-branches")!;
      const dim = svg.querySelector<SVGGElement>(".bm-dim")!;
      const lit = svg.querySelector<SVGPathElement>(".bm-lit")!;
      svg.setAttribute("width", String(list.offsetWidth));
      svg.setAttribute("height", String(list.offsetHeight));
      dim.replaceChildren(...[...list.querySelectorAll<HTMLElement>(".bm-leaf")].map((leaf) => {
        const path = document.createElementNS("http://www.w3.org/2000/svg", "path");
        path.setAttribute("d", branch(list, leaf.parentElement!));
        return path;
      }));
      const leaves = [...list.querySelectorAll<HTMLElement>(".bm-leaf")];
      const mine = leaves.find((leaf) => leaf.dataset.id === active);
      lit.style.transition = animate && !reduced() ? `opacity 150ms ${EASE}` : "none";
      if (animate) lit.getAnimations().forEach((animation) => animation.cancel());
      if (mine) {
        lit.setAttribute("d", branch(list, mine.parentElement!));
        // The owner approved paint-based draw-on for this small, rarely changed tree.
        if (animate && !reduced()) lit.animate(
          [{ strokeDashoffset: 1 }, { strokeDashoffset: 0 }],
          { duration: 300, easing: EASE, fill: "both" },
        );
        lit.style.opacity = "1";
      } else {
        lit.style.opacity = "0";
      }
      for (const leaf of leaves) leaf.toggleAttribute("aria-current", leaf.dataset.id === active);
      section.classList.toggle("is-current", Boolean(mine));
    }

    const currentHead = host.querySelector<HTMLElement>(".bm-sec.is-current .bm-head");
    marker.style.opacity = currentHead ? "1" : "0";
    if (currentHead) {
      marker.style.transition = animate && !reduced() ? `transform 280ms ${EASE}` : "none";
      marker.style.transform = `translateY(${currentHead.offsetTop + currentHead.offsetHeight / 2 - 10}px)`;
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

  // Observe folds as well as the host so branch geometry stays aligned after a fold toggles.
  const observer = new ResizeObserver(() => layout(false));
  observer.observe(host);
  for (const fold of host.querySelectorAll<HTMLElement>(".bm-fold")) observer.observe(fold);

  const api: BranchedMenu = {
    select(id, instant = false) {
      active = id;
      layout(!instant);
      opts.onSelect?.(id);
    },
    dispose() {
      disposed = true;
      observer.disconnect();
      host.removeEventListener("click", onClick);
    },
  };
  layout(false);
  return api;
}
