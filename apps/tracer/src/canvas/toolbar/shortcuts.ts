/**
 * Canvas shortcuts (D222). Every rebindable shortcut lives in the registry (Settings, Shortcuts edits it); the handlers
 * follow the binding live. Fixed keys: Escape flies out to all views (or closes the float), and the digit row flies to a view.
 *
 * The defaults are each platform's terminal conventions: Command on a Mac (⌘D split right, ⌥⌘W close window), Ctrl+Shift
 * on PC (Ctrl+Shift+D split right, Ctrl+Shift+E split down). Ctrl+Alt is never a default, because it is AltGr on many
 * layouts, and the Super key is never a default, because the OS owns it. Printable keys match the character the layout
 * types (`key`); arrows and the digit row match the physical key, which is what a position means.
 */
import { allShortcuts, bindCombo, bindShortcut, bindingOf, comboLabel, matchesCombo, onBindingsChange, platformCombo, registerShortcuts, type Combo } from "../../../../../packages/ui/src/shortcuts";
import { isTypingTarget } from "../../../../../packages/ui/src/shortcuts-view";
import { isKeyboardLocked } from "../../../../../packages/ui/src/keyboard-lock";
import { bindTerminalFont } from "../../terminal-font-shortcuts";
import type { Ctx, WinRec } from "../context";
import { isTerminal } from "../views/body";

/** The digit-row chord that flies to view `n` (1 to 9): ⌘n on a Mac, Ctrl+Shift+n elsewhere. A position, so the digit row is matched by physical key. */
const viewCombo = (n: number): Combo => platformCombo({ code: `Digit${n}`, mod: true }, { code: `Digit${n}`, mod: true, shift: true });

/** The current key combination of a shortcut as text ("" when unbound). */
export const bindingText = (id: string): string => {
  const found = allShortcuts().find((e) => e.shortcut.id === id);
  const c = found && bindingOf(found.shortcut);
  return c ? comboLabel(c) : "";
};

export function installShortcuts(cx: Ctx): () => void {
  const { stage, signal, state, views } = cx;
  const removeRegistry = registerShortcuts({ id: "canvas", title: "Canvas", area: "canvas", shortcuts: [
    { id: "canvas-lock", label: "Canvas lock", keys: "", combo: { code: "KeyG", key: "g", mod: true, shift: true } },
    { id: "input-lock", label: "Input lock", keys: "", combo: { code: "KeyL", key: "l", mod: true, shift: true } },
    // Four window actions (D212, D222). Split right and split down divide this window's own space; new window right and
    // new window below open a full-size window beside or under it.
    { id: "split-right", label: "Split right", keys: "", combo: platformCombo({ code: "KeyD", key: "d", mod: true, shift: false }, { code: "KeyD", key: "d", mod: true, shift: true }) },
    { id: "split-down", label: "Split down", keys: "", combo: platformCombo({ code: "KeyD", key: "d", mod: true, shift: true }, { code: "KeyE", key: "e", mod: true, shift: true }) },
    { id: "new-window-right", label: "New window right", keys: "", combo: platformCombo({ code: "Enter", key: "Enter", mod: true, shift: false }, { code: "Enter", key: "Enter", mod: true, shift: true }) },
    { id: "new-window-below", label: "New window below", keys: "", combo: platformCombo({ code: "Enter", key: "Enter", mod: true, shift: true }, { code: "Enter", key: "Enter", mod: true, shift: true, alt: true }) },
    // Not a binding: the other pair of the four, reached from the split buttons' own place (#280). Listed so `?` shows it.
    { id: "split-buttons-alt", label: "Split buttons: new window instead", keys: { mac: "⌥ click", other: "Alt+click" } },
    // Close the active window (D178: its session keeps running, detached). ⌥⌘W on a Mac (⌘W is the browser's), Ctrl+Shift+X elsewhere.
    { id: "close-window", label: "Close window", keys: "", combo: platformCombo({ code: "KeyW", mod: true, alt: true }, { code: "KeyX", key: "x", mod: true, shift: true }) },
    { id: "next-window", label: "Next window", keys: "", combo: platformCombo({ code: "BracketRight", key: "]", mod: true, shift: false }, { code: "BracketRight", key: "]", mod: true, shift: true }) },
    { id: "previous-window", label: "Previous window", keys: "", combo: platformCombo({ code: "BracketLeft", key: "[", mod: true, shift: false }, { code: "BracketLeft", key: "[", mod: true, shift: true }) },
    // Move between windows: the arrows, with Option and Command on a Mac and Ctrl+Shift elsewhere (the nearest window that way).
    { id: "move-left", label: "Move to the window on the left", keys: "", combo: platformCombo({ code: "ArrowLeft", mod: true, alt: true }, { code: "ArrowLeft", mod: true, shift: true }) },
    { id: "move-right", label: "Move to the window on the right", keys: "", combo: platformCombo({ code: "ArrowRight", mod: true, alt: true }, { code: "ArrowRight", mod: true, shift: true }) },
    { id: "move-up", label: "Move to the window above", keys: "", combo: platformCombo({ code: "ArrowUp", mod: true, alt: true }, { code: "ArrowUp", mod: true, shift: true }) },
    { id: "move-down", label: "Move to the window below", keys: "", combo: platformCombo({ code: "ArrowDown", mod: true, alt: true }, { code: "ArrowDown", mod: true, shift: true }) },
    { id: "overview", label: "All views (overview)", keys: "Esc" },
    { id: "pan", label: "Next window or column", keys: "Scroll" },
    { id: "views", label: "Go to view 1 to 3", keys: { mac: "⌘1–3", other: "Ctrl+Shift+1–3" } },
  ] });
  // A key never animates and one press is one action: auto-repeat is ignored, so holding the key cannot queue work.
  // A keyboard action is instant (TASTE): it lands on the new window in the same frame.
  const windowKey = (e: KeyboardEvent, run: (w: WinRec) => unknown): void => {
    if (e.repeat) return;
    const w = state.activeWin;
    if (!cx.inputLock.state && w && isTerminal(w)) void run(w);
  };
  // One press, one window: a repeat is ignored, and the window closes before the next press can see it.
  const closeActive = (e: KeyboardEvent): void => { if (e.repeat) return; const w = state.activeWin; if (w && !cx.inputLock.state && w.model.kind !== "node" && w.model.kind !== "settings") cx.win.closeKey(w); };
  const removeBindings = [
    ...bindTerminalFont(() => cx.adapters.activeTerminal?.()),
    bindShortcut("canvas-lock", () => cx.nav.setCanvasLock(!state.canvasLock)),
    bindShortcut("input-lock", () => cx.inputLock.toggle()),
    bindShortcut("split-right", (e) => windowKey(e, (w) => cx.win.split(w, "right", true))),
    bindShortcut("split-down", (e) => windowKey(e, (w) => cx.win.split(w, "down", true))),
    bindShortcut("new-window-right", (e) => windowKey(e, (w) => cx.win.newWindow(w, "right", true))),
    bindShortcut("new-window-below", (e) => windowKey(e, (w) => cx.win.newWindow(w, "below", true))),
    bindShortcut("close-window", closeActive),
    // Keyboard Lock (fullscreen only, D222): ⌘W on a Mac and Ctrl+Shift+W elsewhere close the window too, but only while the
    // browser has handed those keys over. Otherwise the browser keeps them (it closes the tab), so the chord is not bound.
    bindCombo(platformCombo({ code: "KeyW", key: "w", mod: true, shift: false }, { code: "KeyW", key: "w", mod: true, shift: true }), closeActive, () => isKeyboardLocked()),
    bindShortcut("next-window", () => { if (!cx.inputLock.state) cx.win.step(1, true); }),
    bindShortcut("previous-window", () => { if (!cx.inputLock.state) cx.win.step(-1, true); }),
    bindShortcut("move-left", () => { if (!cx.inputLock.state) cx.win.move("left", true); }),
    bindShortcut("move-right", () => { if (!cx.inputLock.state) cx.win.move("right", true); }),
    bindShortcut("move-up", () => { if (!cx.inputLock.state) cx.win.move("up", true); }),
    bindShortcut("move-down", () => { if (!cx.inputLock.state) cx.win.move("down", true); }),
  ];
  const offBindings = onBindingsChange(() => cx.toolbar.update());
  window.addEventListener("keydown", (e) => {
    if (e.key !== "Escape" || e.defaultPrevented || stage.querySelector(".palette:not([hidden])") || document.querySelector(".ui-confirm-tip[data-open='true']")) return;
    if (isTypingTarget(e.target)) return;
    if (cx.float.isOpen()) { cx.float.close(); return; }
    cx.nav.showOverview();
  }, { signal });
  // Every jump is the same camera spring: ⌘ (a Mac) or Ctrl+Shift (elsewhere) with the digit row 1 to 9.
  window.addEventListener("keydown", (e) => {
    const n = [1, 2, 3, 4, 5, 6, 7, 8, 9].find((digit) => matchesCombo(e, viewCombo(digit)));
    const id = n === undefined ? undefined : [...views.keys()][n - 1];
    if (!id) return;
    e.preventDefault(); e.stopPropagation();
    cx.viewList.close(true);
    cx.camera.keyFlight(() => cx.nav.flyView(id));
  }, { signal, capture: true });
  return () => { removeRegistry(); removeBindings.forEach((r) => r()); offBindings(); };
}
