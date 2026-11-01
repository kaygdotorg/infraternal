/**
 * Option (Alt) turns a window header's split buttons into "new window" (#280): the key watching and the icon morph.
 *
 * The window card loads this module the first time the pointer enters a window that has such buttons, or keyboard
 * focus reaches its actions (D188, `*.on-demand.ts`). Until then the card carries two cheap trigger listeners and no
 * morph code; the buttons show their plain split icons, which are exactly the morph's start (`icon-morph.test.ts`),
 * so nothing changes on screen when the module takes over. Hovering a window is far earlier than pressing a modifier
 * over its buttons, and the module is cached after the first load.
 *
 * The modifier is Option on a Mac and Alt on Windows and Linux; the browser reports both as `key === "Alt"` and
 * `altKey`, so one code path serves every platform (AltGr reports "AltGraph" and never counts). The pointer being near
 * the actions pill, or keyboard focus being on one of its buttons, is what counts: the key alone, far away, changes
 * nothing. The key listeners exist only while the pointer is over the window or focus is in its actions, so an idle
 * canvas has none running.
 */
import { createIconMorph, SPLIT_MORPH, type IconMorph } from "./icon-morph";
import { refreshTip } from "./tooltip";
import type { WindowAction } from "./window-card";

export type AltAction = WindowAction & { alt: NonNullable<WindowAction["alt"]> };
export interface AltButton { button: HTMLButtonElement; action: AltAction }
/** Where the pointer was when the card woke this module, and whether Option was already held. */
export interface AltSeed { x: number; y: number; altKey: boolean }

const NEAR = 28;

export function createWindowAlt(root: HTMLElement, actions: HTMLElement, buttons: AltButton[], seed: AltSeed): { dispose(): void } {
  // The morph replaces the button's drawing with its own shapes, which at rest are the same icon.
  const alts: Array<AltButton & { morph: IconMorph }> = buttons.map((entry) => ({ ...entry, morph: createIconMorph(entry.button.querySelector("svg")!, SPLIT_MORPH[entry.action.alt.morph]) }));
  let altOn = false;
  let pointer = { x: seed.x, y: seed.y };
  // The load took a moment: the pointer may already have left, so ask the browser, not the event that woke us.
  let pointerIn = root.matches(":hover");
  let focusIn = actions.contains(document.activeElement);
  let listening = false;
  const nearActions = (): boolean => {
    // Keyboard focus (shown by the focus ring) on a button counts as "near": Tab to the button, hold Alt, press Enter.
    if (focusIn && actions.querySelector(":focus-visible")) return true;
    if (!pointerIn) return false;
    const r = actions.getBoundingClientRect();
    return pointer.x >= r.left - NEAR && pointer.x <= r.right + NEAR && pointer.y >= r.top - NEAR && pointer.y <= r.bottom + NEAR;
  };
  const setAlt = (next: boolean): void => {
    if (next === altOn) return;
    altOn = next;
    for (const { button, action, morph } of alts) {
      const label = next ? action.alt.label : action.label;
      morph.set(next);
      button.dataset.tip = label;
      button.setAttribute("aria-label", label);
      if (next) button.dataset.alt = ""; else delete button.dataset.alt;
      refreshTip(button, true);
    }
  };
  const onKey = (event: KeyboardEvent): void => {
    if (event.key !== "Alt") return;
    const near = nearActions();
    setAlt(event.altKey && near);
    // On Windows and Linux a bare Alt press that is released alone moves focus to the browser's menu. Near the buttons the
    // key means something else, so it is ours; any other time (and every Alt+key chord) it goes on as before.
    if (near) event.preventDefault();
  };
  const onBlur = (): void => setAlt(false);
  /** Key listeners exist exactly while the pointer is over the window or focus is in the actions. */
  const listen = (): void => {
    const want = pointerIn || focusIn;
    if (want === listening) return;
    listening = want;
    const toggle = want ? window.addEventListener.bind(window) : window.removeEventListener.bind(window);
    toggle("keydown", onKey as EventListener);
    toggle("keyup", onKey as EventListener);
    toggle("blur", onBlur);
    if (!want) setAlt(false);
  };
  const onEnter = (event: PointerEvent): void => {
    if (event.pointerType !== "mouse" && event.pointerType !== "pen") return;
    pointer = { x: event.clientX, y: event.clientY };
    pointerIn = true;
    listen();
    setAlt(event.altKey && nearActions());
  };
  const onMove = (event: PointerEvent): void => {
    pointer = { x: event.clientX, y: event.clientY };
    if (event.altKey || altOn) setAlt(event.altKey && nearActions());
  };
  // Leaving the window or the focus turns the buttons back, unless the other of the two still holds them.
  const onLeave = (): void => { pointerIn = false; if (altOn && !nearActions()) setAlt(false); listen(); };
  const onFocusIn = (): void => { focusIn = true; listen(); };
  const onFocusOut = (event: FocusEvent): void => {
    if (event.relatedTarget instanceof Node && actions.contains(event.relatedTarget)) return;
    focusIn = false;
    if (altOn && !nearActions()) setAlt(false);
    listen();
  };
  root.addEventListener("pointerenter", onEnter);
  root.addEventListener("pointermove", onMove, { passive: true });
  root.addEventListener("pointerleave", onLeave);
  actions.addEventListener("focusin", onFocusIn);
  actions.addEventListener("focusout", onFocusOut);
  listen();
  setAlt(pointerIn && seed.altKey && nearActions());
  return {
    dispose() {
      root.removeEventListener("pointerenter", onEnter);
      root.removeEventListener("pointermove", onMove);
      root.removeEventListener("pointerleave", onLeave);
      actions.removeEventListener("focusin", onFocusIn);
      actions.removeEventListener("focusout", onFocusOut);
      pointerIn = false;
      focusIn = false;
      listen();
      setAlt(false);
      for (const { morph } of alts) morph.dispose();
    },
  };
}
