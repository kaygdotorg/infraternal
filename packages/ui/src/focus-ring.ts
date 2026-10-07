/**
 * Keyboard-navigation focus rings for the whole document.
 *
 * `:focus-visible` alone is not enough: browsers also match it when a keyboard
 * shortcut moves focus programmatically (for example a shortcut that focuses a
 * search field), and some engines match it on clicked checkboxes. Rings must
 * appear only while the user is navigating with Tab, so this sets
 * `data-focus-ring="on"` on the root after Tab / Shift+Tab, keeps it while
 * arrow keys move inside a composite the user tabbed into, and clears it on any
 * pointer press or modified shortcut. Styles draw rings only under
 * `:root[data-focus-ring="on"] :focus-visible`.
 */

let installed = false;

/** Installs the document-wide listeners once; later calls are no-ops. */
export function installFocusRing(root: HTMLElement = document.documentElement): void {
  if (installed) return;
  installed = true;
  root.dataset.focusRing = "off";
  document.addEventListener("keydown", (event) => {
    if (event.key === "Tab" && !event.metaKey && !event.ctrlKey && !event.altKey) root.dataset.focusRing = "on";
    else if (event.metaKey || event.ctrlKey || event.altKey) root.dataset.focusRing = "off";
  }, true);
  document.addEventListener("pointerdown", () => { root.dataset.focusRing = "off"; }, true);
}
