/**
 * The `?` view (D160): the top-middle pill morphs into a list of shortcuts, in place. There is
 * no separate page or modal.
 *
 * The morph is one continuous shape. The panel is laid out once at its final size and a spring
 * (about 400 ms, critically damped) opens a `clip-path: inset(... round r)` from the pill's
 * rectangle to the whole panel, so width, height and corner radius move together and nothing
 * reflows. The pill underneath fades out over the first third (the panel has the same material,
 * so the shape reads as one), and the content fades in only after the shape has settled. Close
 * reverses the same spring from wherever it is, so it can be interrupted either way. At rest no
 * clip, no transform and no opacity is left on anything (crisp text). Reduced motion: a
 * crossfade, no shape travel.
 *
 * Toggling is idempotent and never leaves a shell behind: opening while the close is still playing takes the panel that
 * is on screen and runs the same spring back from where it is (one panel at a time, the only one ever mounted), and a
 * press that arrives while the panel is already in the state it asks for does nothing. Whatever the sequence of
 * presses, the end state is the panel fully open with its content, or no panel at all.
 *
 * Closes on Escape, `?` again, a press outside, or `close()`. Content comes from the registry
 * (shortcuts.ts): current area first, then global, one shortcut per action for this platform.
 */
import { Spring } from "./spring";
import { comboLabel, isOverridden, isTypingTarget, keyCaps, shortcutSections } from "./shortcuts";
/** Re-exported for callers that already import the view: true for keystrokes that belong to a field or terminal. */
export { isTypingTarget } from "./shortcuts";

/** What {@link mountShortcutsView} needs: the `pill` that morphs, the `stage` that holds the panel, and `areas()`, the current areas most specific first. */
export interface ShortcutsViewOptions {
  /** The pill that morphs (the session capsule). */
  pill: HTMLElement;
  /** The positioned container the panel is mounted in (the screen). */
  stage: HTMLElement;
  /** The current areas, most specific first (e.g. `["canvas", "terminal"]`). */
  areas(): string[];
}

/** The handle returned by {@link mountShortcutsView}. `toggle()` opens or closes; `close(true)` skips the animation; `dispose()` removes everything it added. */
export interface ShortcutsView {
  readonly isOpen: boolean;
  open(): void;
  close(instant?: boolean): void;
  toggle(): void;
  dispose(): void;
}


/** Limits a value to 0 to 1. */
const clamp01 = (value: number): number => Math.min(1, Math.max(0, value));
/** An eased 0 to 1 ramp of `value` between `from` and `to` (smoothstep), used to stage the content fade. */
const smooth = (from: number, to: number, value: number): number => { const t = clamp01((value - from) / (to - from)); return t * t * (3 - 2 * t); };

/**
 * Prepares the `?` view for `options.pill` and returns its handle. Nothing is drawn until it is opened.
 * @example
 * const view = mountShortcutsView({ pill, stage, areas: () => ["canvas"] }); view.toggle();
 */
export function mountShortcutsView(options: ShortcutsViewOptions): ShortcutsView {
  const { pill, stage } = options;
  const reduced = matchMedia("(prefers-reduced-motion: reduce)");
  let panel: HTMLElement | undefined;
  let content: HTMLElement[] = [];
  let from = { top: 0, right: 0, bottom: 0, left: 0, radius: 19 };
  let to = { radius: 18 };
  let openState = false;
  let restore: HTMLElement | null = null;
  let controller: AbortController | undefined;

  const apply = (t: number): void => {
    if (!panel) return;
    if (t >= 0.99) {
      // Settled open: nothing left on the panel but its content.
      panel.style.clipPath = "";
      for (const node of content) node.style.opacity = "";
      pill.style.opacity = "0";
      return;
    }
    const k = Math.max(0, t);
    const inset = (side: number): number => Math.max(0, side * (1 - k));
    panel.style.clipPath = `inset(${inset(from.top)}px ${inset(from.right)}px ${inset(from.bottom)}px ${inset(from.left)}px round ${from.radius + (to.radius - from.radius) * k}px)`;
    const show = String(smooth(0.7, 1, k));
    for (const node of content) node.style.opacity = show;
    pill.style.opacity = String(1 - smooth(0, 0.35, k));
  };
  const spring = new Spring(0, apply, { visualDuration: 0.4 });

  const build = (): HTMLElement => {
    const root = document.createElement("section");
    root.className = "ui-shortcuts ui-overlay-surface";
    root.setAttribute("role", "dialog");
    root.setAttribute("aria-label", "Keyboard shortcuts");
    root.tabIndex = -1;
    const head = document.createElement("header");
    head.className = "ui-shortcuts-head";
    head.innerHTML = '<span class="ui-shortcuts-heading">Keyboard shortcuts</span><kbd class="ui-shortcuts-esc">Esc</kbd>';
    const body = document.createElement("div");
    body.className = "ui-shortcuts-body";
    for (const section of shortcutSections(options.areas())) {
      const block = document.createElement("section");
      block.className = "ui-shortcuts-section";
      const title = document.createElement("h3");
      title.className = "ui-shortcuts-title";
      title.textContent = section.title;
      const list = document.createElement("ul");
      list.className = "ui-shortcuts-list";
      for (const shortcut of section.shortcuts) {
        const row = document.createElement("li");
        row.className = "ui-shortcuts-row";
        const label = document.createElement("span");
        label.className = "ui-shortcuts-label";
        label.textContent = shortcut.label;
        const keys = document.createElement("span");
        keys.className = "ui-shortcuts-keys";
        for (const cap of keyCaps(shortcut.keys)) {
          const key = document.createElement("kbd");
          key.textContent = cap;
          keys.append(key);
        }
        // The other bindings that run the same action (they work while the primary is not rebound) sit on the same row,
        // quieter: the same keycaps, dimmed. They show nothing when the person has rebound the primary.
        for (const alternate of isOverridden(shortcut.id) ? [] : shortcut.alternates ?? []) {
          for (const cap of keyCaps(comboLabel(alternate))) {
            const key = document.createElement("kbd");
            key.className = "ui-shortcuts-alt";
            key.textContent = cap;
            keys.append(key);
          }
        }
        row.append(label, keys);
        list.append(row);
      }
      block.append(title, list);
      body.append(block);
    }
    root.append(head, body);
    content = [head, body];
    return root;
  };

  const finishClose = (): void => {
    panel?.remove();
    panel = undefined;
    content = [];
    pill.style.opacity = "";
    pill.style.pointerEvents = "";
    pill.removeAttribute("aria-expanded");
    if (restore?.isConnected) restore.focus({ preventScroll: true });
    restore = null;
  };

  const close = (instant = false): void => {
    if (!openState) return;
    openState = false;
    controller?.abort();
    controller = undefined;
    if (instant || !panel) { spring.set(0, true); finishClose(); return; }
    if (reduced.matches) {
      const node = panel;
      pill.style.opacity = "";
      node.animate([{ opacity: 1 }, { opacity: 0 }], { duration: 140, easing: "ease-out", fill: "forwards" }).onfinish = () => { if (!openState) finishClose(); };
      return;
    }
    panel.style.boxShadow = "none";
    spring.set(0);
    // The spring settles at 0; remove the panel once it has.
    const wait = (): void => { if (openState) return; if (spring.value > 0.002) { requestAnimationFrame(wait); return; } finishClose(); };
    requestAnimationFrame(wait);
  };

  /** Keys and presses that close the panel while it is open. */
  const listen = (): void => {
    controller = new AbortController();
    const { signal } = controller;
    document.addEventListener("keydown", (event) => {
      if (event.key === "Escape" || (event.key === "?" && !event.ctrlKey && !event.metaKey)) {
        event.preventDefault();
        event.stopPropagation();
        close();
      }
    }, { capture: true, signal });
    document.addEventListener("pointerdown", (event) => {
      if (!(event.target instanceof Node) || panel?.contains(event.target)) return;
      close();
    }, { capture: true, signal });
  };

  /** Brings the shadow back once the shape is whole (the clip would cut it off while morphing). */
  const settle = (): void => {
    if (!openState || !panel) return;
    if (spring.value < 0.999) { requestAnimationFrame(settle); return; }
    panel.style.boxShadow = "";
    panel.animate([{ boxShadow: "none" }, { boxShadow: getComputedStyle(panel).boxShadow }], { duration: 160, easing: "ease-out" });
  };

  const open = (): void => {
    if (openState) return;
    openState = true;
    listen();
    if (panel) {
      // The close is still playing: reverse it, on the panel that is there. A second panel would leave the first one
      // behind, half clipped and without content.
      for (const animation of panel.getAnimations()) animation.cancel();
      pill.style.pointerEvents = "none";
      if (reduced.matches) { pill.style.opacity = "0"; panel.style.opacity = ""; spring.set(1, true); return; }
      spring.set(1);
      requestAnimationFrame(settle);
      return;
    }
    restore = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    panel = build();
    stage.append(panel);
    const screen = stage.getBoundingClientRect();
    const rect = pill.getBoundingClientRect();
    const width = Math.min(560, screen.width - 24);
    const left = Math.max(12, Math.min(screen.width - width - 12, rect.left - screen.left + rect.width / 2 - width / 2));
    const top = rect.top - screen.top;
    panel.style.left = `${Math.round(left)}px`;
    panel.style.top = `${Math.round(top)}px`;
    panel.style.width = `${Math.round(width)}px`;
    // Never taller than the space under the pill; the list scrolls inside.
    const tray = stage.querySelector<HTMLElement>("#keybar");
    const trayTop = tray && getComputedStyle(tray).display !== "none" ? tray.getBoundingClientRect().top - screen.top : screen.height;
    panel.style.maxHeight = `${Math.max(160, Math.floor(Math.min(screen.height, trayTop) - top - 12))}px`;
    const height = panel.offsetHeight;
    const radius = Math.min(rect.height / 2, 24);
    from = {
      top: 0, bottom: Math.max(0, height - rect.height),
      left: Math.max(0, rect.left - screen.left - left), right: Math.max(0, left + width - (rect.right - screen.left)), radius,
    };
    to = { radius: parseFloat(getComputedStyle(panel).borderTopLeftRadius) || 18 };
    pill.setAttribute("aria-expanded", "true");
    pill.style.pointerEvents = "none";
    panel.focus({ preventScroll: true });
    if (reduced.matches) {
      pill.style.opacity = "0";
      panel.animate([{ opacity: 0 }, { opacity: 1 }], { duration: 160, easing: "ease-out" });
      spring.set(1, true);
      return;
    }
    panel.style.boxShadow = "none";
    spring.set(0, true);
    apply(0);
    spring.set(1);
    requestAnimationFrame(settle);
  };

  return {
    get isOpen() { return openState; },
    open,
    close,
    toggle() { if (openState) close(); else open(); },
    dispose() { close(true); },
  };
}
