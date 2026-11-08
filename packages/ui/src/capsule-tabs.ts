import { EASE_OUT } from "./motion";
/**
 * Capsule tabs: a small segmented tab list whose selected capsule glides to the chosen
 * tab (docs/design/segmented-selection.md). One component for every icon/label tab set.
 *
 * - Pointer changes glide (200 ms strong ease-out, transform + width of one element);
 *   arrow keys move instantly, because keyboard actions never animate.
 * - Roving tabindex with Left/Right/Home/End, `role="tablist"` so the focus-ring module
 *   treats arrows as navigation.
 * - The capsule settles on whole device pixels, so the labels above it stay crisp.
 * - Compact lists (narrow popovers) show the label only on the selected tab; the others
 *   are icon-only and get the shared tooltip from their aria-label.
 */

export interface CapsuleTab {
  id: string;
  label: string;
  icon?: string; // inner SVG markup, 24×24 grid
}

export interface CapsuleTabs {
  readonly root: HTMLElement;
  readonly selected: string;
  select(id: string, instant?: boolean): void;
  dispose(): void;
}


/** Builds a tab list; `onChange` runs after the selection moves. */
export function createCapsuleTabs(
  tabs: CapsuleTab[],
  initial: string,
  onChange: (id: string, source: "pointer" | "keyboard") => void,
  label = "Sections",
  compact = false,
): CapsuleTabs {
  const root = document.createElement("div");
  root.className = "ui-tabs";
  root.setAttribute("role", "tablist");
  root.setAttribute("aria-label", label);
  root.toggleAttribute("data-compact", compact);
  const capsule = document.createElement("span");
  capsule.className = "ui-tabs-capsule";
  capsule.setAttribute("aria-hidden", "true");
  root.append(capsule);

  const buttons = tabs.map((tab) => {
    const button = document.createElement("button");
    button.type = "button";
    button.className = "ui-tab";
    button.setAttribute("role", "tab");
    button.dataset.tab = tab.id;
    if (compact) button.setAttribute("aria-label", tab.label);
    button.innerHTML = `${tab.icon ? `<svg viewBox="0 0 24 24" aria-hidden="true">${tab.icon}</svg>` : ""}<span>${tab.label}</span>`;
    root.append(button);
    return button;
  });

  let selected = tabs.some((tab) => tab.id === initial) ? initial : tabs[0]!.id;
  // A compact list changes its own width when the label moves between tabs, which fires the
  // resize observer below in the middle of the glide. Re-placing instantly then would cancel
  // the motion (the capsule jumped), so resizes are ignored while a glide is in flight.
  let glideUntil = 0;
  const place = (instant: boolean): void => {
    const button = buttons.find((item) => item.dataset.tab === selected);
    if (!button || !root.isConnected) return;
    const dpr = devicePixelRatio || 1;
    const x = Math.round(button.offsetLeft * dpr) / dpr;
    const width = Math.round(button.offsetWidth * dpr) / dpr;
    const reduced = matchMedia("(prefers-reduced-motion: reduce)").matches;
    capsule.style.transition = instant || reduced ? "none" : `transform 200ms ${EASE_OUT}, width 200ms ${EASE_OUT}`;
    glideUntil = instant || reduced ? 0 : performance.now() + 260;
    capsule.style.width = `${width}px`;
    capsule.style.transform = `translateX(${x}px)`;
  };
  const render = (instant: boolean, measure = true): void => {
    for (const button of buttons) {
      const on = button.dataset.tab === selected;
      button.setAttribute("aria-selected", String(on));
      button.tabIndex = on ? 0 : -1;
    }
    // A compact list changes tab widths when the label moves; measure after that layout.
    if (!measure) return;
    if (compact && !instant) requestAnimationFrame(() => place(false)); else place(instant);
  };
  const select = (id: string, instant = false): void => {
    if (!tabs.some((tab) => tab.id === id)) return;
    selected = id;
    render(instant);
  };

  const click = (event: MouseEvent): void => {
    const button = (event.target as Element | null)?.closest<HTMLButtonElement>(".ui-tab");
    if (!button?.dataset.tab || button.dataset.tab === selected) return;
    select(button.dataset.tab, event.detail === 0);
    onChange(selected, event.detail === 0 ? "keyboard" : "pointer");
  };
  const keydown = (event: KeyboardEvent): void => {
    const index = buttons.findIndex((button) => button.dataset.tab === selected);
    let next = index;
    if (event.key === "ArrowRight") next = (index + 1) % buttons.length;
    else if (event.key === "ArrowLeft") next = (index + buttons.length - 1) % buttons.length;
    else if (event.key === "Home") next = 0;
    else if (event.key === "End") next = buttons.length - 1;
    else return;
    event.preventDefault();
    select(buttons[next]!.dataset.tab!, true);
    buttons[next]!.focus();
    onChange(selected, "keyboard");
  };
  root.addEventListener("click", click);
  root.addEventListener("keydown", keydown);
  // The first placement waits for the observer, which reports after the browser's own layout: measuring here would
  // force a layout inside the mount task.
  render(true, false);
  const observer = new ResizeObserver(() => { if (performance.now() >= glideUntil) place(true); });
  observer.observe(root);

  return {
    root,
    get selected() { return selected; },
    select,
    dispose() {
      observer.disconnect();
      root.removeEventListener("click", click);
      root.removeEventListener("keydown", keydown);
      root.remove();
    },
  };
}
