/**
 * Canvas shortcuts. Every rebindable shortcut lives in the registry (Settings, Shortcuts edits it); the handlers
 * follow the binding live. Fixed keys: Escape flies out to all views (or closes the float), Command or Ctrl with
 * 1 to 9 flies to a view.
 */
import { allShortcuts, bindShortcut, bindingOf, comboLabel, onBindingsChange, registerShortcuts, type Combo } from "../../../../../packages/ui/src/shortcuts";
import { isTypingTarget } from "../../../../../packages/ui/src/shortcuts-view";
import { isMacPlatform } from "../../../../../packages/ui/src/platform";
import type { Ctx, WinRec } from "../context";
import { isTerminal } from "../views/body";

/**
 * The chord of a new-window action (D212): Control+Option+key on a Mac, where Control is its own modifier; elsewhere
 * `mod` is Control, so the same chord is Control+Alt+key. Command is never used here: it stays the split key on a Mac.
 */
const newWindowChord = (code: string): Combo => (isMacPlatform() ? { code, ctrl: true, alt: true } : { code, mod: true, alt: true });

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
    // Four window actions (D212). Split right and split down divide this window's own space; new window right and
    // new window below open a full-size window beside or under it. The usual terminal bindings: Command+D and
    // Command+Shift+D on a Mac, Control+Shift+D and Control+Shift+Alt+D elsewhere (`mod` is Control there). The new
    // window chords are Control+Option+R and Control+Option+D on a Mac, Control+Alt+R and Control+Alt+D elsewhere.
    // All four can be rebound in Settings, Shortcuts.
    { id: "split-right", label: "Split right", keys: "", combo: isMacPlatform() ? { code: "KeyD", mod: true } : { code: "KeyD", mod: true, shift: true } },
    { id: "split-down", label: "Split down", keys: "", combo: isMacPlatform() ? { code: "KeyD", mod: true, shift: true } : { code: "KeyD", mod: true, shift: true, alt: true } },
    { id: "new-window-right", label: "New window right", keys: "", combo: newWindowChord("KeyR") },
    { id: "new-window-below", label: "New window below", keys: "", combo: newWindowChord("KeyD") },
    // Close the active window (D178: its session keeps running, detached). Control+Option+W on a Mac (Command+W is the
    // browser's), Control+Alt+W elsewhere. Rebindable like the rest.
    { id: "close-window", label: "Close window", keys: "", combo: newWindowChord("KeyW") },
    { id: "next-window", label: "Next window", keys: "", combo: { code: "ArrowRight", mod: true, shift: true } },
    { id: "previous-window", label: "Previous window", keys: "", combo: { code: "ArrowLeft", mod: true, shift: true } },
    { id: "overview", label: "All views (overview)", keys: "Esc" },
    { id: "pan", label: "Next window or column", keys: "Scroll" },
    { id: "views", label: "Go to view 1 to 3", keys: { mac: "⌘1–3", other: "Ctrl+1–3" } },
  ] });
  // A key never animates and one press is one action: auto-repeat is ignored, so holding the key cannot queue work.
  // A keyboard action is instant (TASTE): it lands on the new window in the same frame.
  const windowKey = (e: KeyboardEvent, run: (w: WinRec) => unknown): void => {
    if (e.repeat) return;
    const w = state.activeWin;
    if (!cx.inputLock.state && w && isTerminal(w)) void run(w);
  };
  const removeBindings = [
    bindShortcut("canvas-lock", () => cx.nav.setCanvasLock(!state.canvasLock)),
    bindShortcut("input-lock", () => cx.inputLock.toggle()),
    bindShortcut("split-right", (e) => windowKey(e, (w) => cx.win.split(w, "right", true))),
    bindShortcut("split-down", (e) => windowKey(e, (w) => cx.win.split(w, "down", true))),
    bindShortcut("new-window-right", (e) => windowKey(e, (w) => cx.win.newWindow(w, "right", true))),
    bindShortcut("new-window-below", (e) => windowKey(e, (w) => cx.win.newWindow(w, "below", true))),
    // One press, one window: a repeat is ignored, and the window closes before the next press can see it.
    bindShortcut("close-window", (e) => { if (e.repeat) return; const w = state.activeWin; if (w && !cx.inputLock.state && w.model.kind !== "node" && w.model.kind !== "settings") cx.win.closeKey(w); }),
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
