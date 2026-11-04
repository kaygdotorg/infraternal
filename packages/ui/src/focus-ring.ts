/**
 * Keyboard-only focus rings.
 *
 * `:focus-visible` alone is not enough: browsers also match it when a shortcut such as
 * Cmd+K or Escape moves focus in script, and on text fields after a click. The product
 * shows a ring only while the person is actually navigating with the keyboard, so this
 * module keeps one attribute on the root, `data-focus-ring="on"`, and styles draw rings
 * only under it (`[data-focus-ring="on"] :focus-visible`, see packages/ui/styles.css).
 *
 * - Tab and Shift+Tab turn it on. So do arrow, Home and End keys pressed inside a
 *   composite widget (tablist, listbox, menu, radiogroup, tree, grid, toolbar), where
 *   arrows move focus between items.
 * - Any pointer press turns it off, and so does any shortcut (a key held with Cmd, Ctrl
 *   or Alt, or Escape), because those move focus in script rather than by navigation.
 * - Keys inside an element marked `data-captures-keys` (the terminal, which sends Tab
 *   and arrows to the shell) never change the modality.
 *
 * The listeners are passive and run in the capture phase on window, so they see a key
 * before any shortcut handler moves focus; they never prevent default or stop
 * propagation, and they cost one attribute write per change of modality.
 */

/** Selector for widgets in which arrow keys move focus between items. */
const COMPOSITE = '[role="tablist"],[role="listbox"],[role="menu"],[role="menubar"],[role="radiogroup"],[role="tree"],[role="grid"],[role="toolbar"]';
/** Keys that count as keyboard navigation inside a composite widget. */
const NAVIGATION_KEYS = new Set(["ArrowUp", "ArrowDown", "ArrowLeft", "ArrowRight", "Home", "End"]);

/** The disposer of the active tracker, or `undefined` when none is installed. */
let installed: (() => void) | undefined;

/** Installs the page-wide keyboard-modality tracker once and returns its disposer. */
export function installFocusRing(root: HTMLElement = document.documentElement): () => void {
  if (installed) return installed;
  const on = (): void => { if (root.dataset.focusRing !== "on") root.dataset.focusRing = "on"; };
  const off = (): void => { if (root.dataset.focusRing) delete root.dataset.focusRing; };

  const keydown = (event: KeyboardEvent): void => {
    if (event.metaKey || event.ctrlKey || event.altKey || event.key === "Escape") { off(); return; }
    if (event.target instanceof Element && event.target.closest("[data-captures-keys]")) return;
    if (event.key === "Tab") { on(); return; }
    if (NAVIGATION_KEYS.has(event.key) && event.target instanceof Element && event.target.closest(COMPOSITE)) on();
  };

  window.addEventListener("keydown", keydown, { capture: true, passive: true });
  window.addEventListener("pointerdown", off, { capture: true, passive: true });
  installed = () => {
    window.removeEventListener("keydown", keydown, { capture: true });
    window.removeEventListener("pointerdown", off, { capture: true });
    off();
    installed = undefined;
  };
  return installed;
}
