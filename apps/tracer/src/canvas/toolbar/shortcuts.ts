/**
 * Canvas shortcuts. Every rebindable shortcut lives in the registry (Settings, Shortcuts edits it); the handlers
 * follow the binding live. Fixed keys: Escape flies out to all views (or closes the float), Command or Ctrl with
 * 1 to 9 flies to a view.
 */
import { allShortcuts, bindShortcut, bindingOf, comboLabel, onBindingsChange, registerShortcuts } from "../../../../../packages/ui/src/shortcuts";
import { isTypingTarget } from "../../../../../packages/ui/src/shortcuts-view";
import { isMacPlatform } from "../../../../../packages/ui/src/platform";
import type { Ctx } from "../context";
import { isTerminal } from "../views/body";

/** The current key combination of a shortcut as text ("" when unbound). */
export const bindingText = (id: string): string => {
  const found = allShortcuts().find((e) => e.shortcut.id === id);
  const c = found && bindingOf(found.shortcut);
  return c ? comboLabel(c) : "";
};

export function installShortcuts(cx: Ctx): () => void {
  const { stage, signal, state, views } = cx;
  const removeRegistry = registerShortcuts({ id: "canvas", title: "Canvas", area: "canvas", shortcuts: [
    { id: "canvas-lock", label: "Canvas lock", keys: "", combo: { code: "KeyG", mod: true, shift: true } },
    { id: "input-lock", label: "Input lock", keys: "", combo: { code: "KeyL", mod: true, shift: true } },
    // Mac: Control+Option+R (right) and Control+Option+D (down), with Command+D and Command+Shift+D as alternates (D206).
    // Elsewhere plain Control+D is the terminal's end-of-input, so the defaults add Shift (right) and Alt+Shift (down);
    // both can be rebound in Settings, Shortcuts.
    { id: "split-right", label: "Split right", keys: "", combo: isMacPlatform() ? { code: "KeyR", ctrl: true, alt: true } : { code: "KeyD", mod: true, shift: true }, ...(isMacPlatform() ? { alternates: [{ code: "KeyD", mod: true }] } : {}) },
    { id: "split-down", label: "Split down", keys: "", combo: isMacPlatform() ? { code: "KeyD", ctrl: true, alt: true } : { code: "KeyD", mod: true, shift: true, alt: true }, ...(isMacPlatform() ? { alternates: [{ code: "KeyD", mod: true, shift: true }] } : {}) },
    { id: "next-window", label: "Next window", keys: "", combo: { code: "ArrowRight", mod: true, shift: true } },
    { id: "previous-window", label: "Previous window", keys: "", combo: { code: "ArrowLeft", mod: true, shift: true } },
    { id: "overview", label: "All views (overview)", keys: "Esc" },
    { id: "pan", label: "Next window or column", keys: "Scroll" },
    { id: "views", label: "Go to view 1 to 3", keys: { mac: "⌘1–3", other: "Ctrl+1–3" } },
  ] });
  // A key never animates and one press is one split: auto-repeat is ignored, so holding the key cannot queue work.
  const splitActive = (direction: "right" | "down", e: KeyboardEvent): void => {
    if (e.repeat) return;
    const w = state.activeWin;
    // The instant (motionless) keyboard split misplaced the camera in production at 54 windows (#141); until it is
    // fixed it takes the animated path, which is correct. One split per press still holds (auto-repeat is ignored).
    if (!cx.inputLock.state && w && isTerminal(w)) void cx.win.split(w, direction);
  };
  const removeBindings = [
    bindShortcut("canvas-lock", () => cx.nav.setCanvasLock(!state.canvasLock)),
    bindShortcut("input-lock", () => cx.inputLock.toggle()),
    bindShortcut("split-right", (e) => splitActive("right", e)),
    bindShortcut("split-down", (e) => splitActive("down", e)),
    bindShortcut("next-window", () => { if (!cx.inputLock.state) cx.win.step(1, true); }),
    bindShortcut("previous-window", () => { if (!cx.inputLock.state) cx.win.step(-1, true); }),
  ];
  const offBindings = onBindingsChange(() => cx.toolbar.update());
  window.addEventListener("keydown", (e) => {
    if (e.key !== "Escape" || e.defaultPrevented || stage.querySelector(".palette:not([hidden])") || document.querySelector(".ui-confirm-tip[data-open='true']")) return;
    if (isTypingTarget(e.target)) return;
    if (cx.float.isOpen()) { cx.float.close(); return; }
    cx.nav.showOverview();
  }, { signal });
  // Every jump is the same camera spring: Command or Ctrl with 1 to 9.
  window.addEventListener("keydown", (e) => {
    const mod = isMacPlatform() ? e.metaKey : e.ctrlKey;
    if (!mod || e.altKey || e.shiftKey || !/^[1-9]$/.test(e.key)) return;
    const id = [...views.keys()][Number(e.key) - 1];
    if (!id) return;
    e.preventDefault(); e.stopPropagation();
    cx.viewList.close(true);
    cx.camera.keyFlight(() => cx.nav.flyView(id));
  }, { signal, capture: true });
  return () => { removeRegistry(); removeBindings.forEach((r) => r()); offBindings(); };
}
