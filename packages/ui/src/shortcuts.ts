/**
 * The shortcut registry (D160): every area of the product registers its own section of
 * shortcuts, and the `?` view (shortcuts-view.ts) lists the current area's sections first and
 * the global ones after them. Containers, LXC and Kubernetes areas add theirs later by calling
 * `registerShortcuts` when they mount; nothing here knows them.
 *
 *   const remove = registerShortcuts({
 *     id: "canvas", title: "Canvas", area: "canvas",
 *     shortcuts: [{ id: "lock", label: "Lock or unlock window", keys: "Ctrl+Shift+L" }],
 *   });
 *
 * One shortcut per action: `keys` is a single string, or one string per platform
 * (`{ mac: "⌘K", other: "Ctrl+Shift+K" }`), and only the one that works here is ever shown.
 */
import { isMacPlatform, shortcutLabel, type PlatformKeys } from "./platform";
import { readLocal, writeLocal } from "./local-pref";

/**
 * A key combination, platform-neutral: `mod` is Command on macOS and Control elsewhere.
 *
 * Two ways to name the key (D222). A printable shortcut names the character it types: `key` is what the
 * person's layout produces ("k", "/", "?", "]", "Enter"), so "Ctrl+Shift+/" means the slash on a German
 * keyboard too, and the label reads from the same character. A shortcut without `key` matches the physical
 * key `code` (`ArrowLeft`, `Digit1`, or a letter on a Mac chord with Option, where Option rewrites the
 * character). `code` is always set: it is the physical key a key-named combo also stands for, and what
 * terminalNeeds reads.
 *
 * `shift` is compared exactly when set. A key-named combo with `shift` left unset ignores Shift, which is how
 * "Ctrl++" accepts both "+" and "=" on a US keyboard.
 */
export interface Combo {
  code: string; key?: string; mod?: boolean; shift?: boolean; alt?: boolean;
  /** The Control key itself on macOS, where `mod` is Command (so Control+Option chords can be written). Ignored elsewhere. */
  ctrl?: boolean;
}

/** One action a person can trigger by key. `id` is stable (it keys the saved override); `label` is what the `?` view shows. */
export interface Shortcut {
  id: string;
  label: string;
  /** What to show when the shortcut has no `combo` (a fixed, built-in key or a pattern such as 1 to 3). */
  keys: PlatformKeys | string;
  /**
   * The default binding of a shortcut the user can change (Settings, Shortcuts). The registry is the
   * single source: `?`, the palette hints, tooltips and the toolbar all read the binding from here.
   */
  combo?: Combo;
  /** Further default bindings that run the same action. Labels and tooltips show `combo`, the primary one. */
  alternates?: Combo[];
}

/** A titled group of shortcuts that one area registers with {@link registerShortcuts}. */
export interface ShortcutSection {
  id: string;
  title: string;
  /** The area this section belongs to; `"global"` sections show in every area. */
  area: string;
  shortcuts: Shortcut[];
}

/** True for keystrokes that belong to something being typed into (a terminal, a field). */
export function isTypingTarget(target: EventTarget | null): boolean {
  return !!(target as Element | null)?.closest?.("input, textarea, select, [contenteditable], .terminal-host, [role='textbox'], [role='searchbox']");
}

/** The area whose sections are always shown, after the current area's. */
export const GLOBAL_AREA = "global";

/**
 * The command palette key, written once. Every surface that names it (the top pill, the view popover,
 * the palette hints, the shortcuts panel) takes it from here so Mac and PC always agree.
 */
export const PALETTE_KEYS: PlatformKeys = { mac: "⌘K", other: "Ctrl+Shift+K" };

/**
 * The palette's default chords (D222). Plain Ctrl+K on PC is the terminal's (kill line, clear), so the palette takes
 * Ctrl+Shift+K there; a Mac keeps ⌘K, which never reaches a terminal. ⌘⇧P and Ctrl+Shift+P are the alternates.
 */
export const paletteCombo = (): Combo => platformCombo({ code: "KeyK", key: "k", mod: true, shift: false }, { code: "KeyK", key: "k", mod: true, shift: true });
/** The second palette chord, ⌘⇧P on a Mac and Ctrl+Shift+P elsewhere. */
export const paletteAlternate = (): Combo => ({ code: "KeyP", key: "p", mod: true, shift: true });

/** The registered sections by id; registering the same id again replaces the section. */
const registered = new Map<string, ShortcutSection>();

/** Registers (or replaces) a section; returns a remover. */
export function registerShortcuts(section: ShortcutSection): () => void {
  registered.set(section.id, section);
  return () => { if (registered.get(section.id) === section) registered.delete(section.id); };
}

/** Sections of the given areas in the order given, then the global ones, each in registration order. */
export function shortcutSections(areas: string[]): ShortcutSection[] {
  const all = [...registered.values()].map((section) => ({ ...section, shortcuts: section.shortcuts.map((shortcut) => { const combo = bindingOf(shortcut); return combo ? { ...shortcut, keys: comboLabel(combo) } : shortcut; }) }));
  return [...areas, GLOBAL_AREA].flatMap((area) => all.filter((section) => section.area === area));
}

/** The caps of one shortcut: "Ctrl+Shift+L" → Ctrl, Shift, L; "⌘K" → ⌘, K; "Esc" → Esc. */
export function keyCaps(keys: PlatformKeys | string): string[] {
  const label = shortcutLabel(keys);
  // A label that ends in the plus key ("Ctrl++", "⌘+") keeps that key as its own cap, not an empty one between separators.
  if (label.length > 1 && label.endsWith("+")) {
    const head = label.slice(0, -1);
    const body = head.endsWith("+") ? head.slice(0, -1) : head;
    const mods = body.includes("+") ? body.split("+") : /^[⌃⌥⌘⇧]+$/.test(body) ? [...body] : body ? [body] : [];
    return [...mods, "+"];
  }
  if (label.length > 1 && label.includes("+")) return label.split("+");
  // Mac modifier glyphs are one cap each (⌘K → ⌘, K); any other single label (Esc, F6) is one cap.
  const modifiers = /^[⌘⌥⌃⇧]+/.exec(label)?.[0] ?? "";
  return modifiers ? [...modifiers, ...(label.slice(modifiers.length) ? [label.slice(modifiers.length)] : [])] : [label];
}

// ---- user bindings (one source for every surface) ---------------------------------------------------------
/** The browser-local key under which the user's rebindings are saved as JSON. */
const STORE = "tracer.shortcuts";
/** Callbacks told when any binding changes. */
const listeners = new Set<() => void>();
/** Reads the saved rebindings; a missing, unreadable or malformed value gives none. */
const loadOverrides = (): Record<string, Combo> => {
  try { const raw = JSON.parse(readLocal(STORE) ?? "{}") as Record<string, Combo>; return raw && typeof raw === "object" ? raw : {}; } catch { return {}; }
};
/** The user's bindings by shortcut id, replacing the defaults. */
let overrides = loadOverrides();

/** The letter keys a shell uses with Ctrl, which a PC shortcut may not take. */
const CTRL_LETTERS = new Set("ABCDEFGHJKLNPRTUWXYZ".split("").map((l) => `Key${l}`));
/**
 * Why a combination cannot be a shortcut because the terminal needs it, or undefined. Plain keys and
 * Shift-only keys are typing; on a PC, Ctrl with most letters is shell line editing (Ctrl+Shift with a
 * letter is fine). On a Mac Command is not the terminal's, so Command combinations are free.
 */
export function terminalNeeds(combo: Combo): string | undefined {
  if (!combo.mod && !combo.alt) return "The terminal needs plain keys.";
  if (!combo.mod && combo.alt && !combo.shift) return "The terminal needs Alt with a key (word movement).";
  if (!isMacPlatform() && combo.mod && !combo.shift && !combo.alt && CTRL_LETTERS.has(combo.code)) return `The terminal needs Ctrl+${keyName(combo.code)}.`;
  return undefined;
}

const KEY_NAMES: Record<string, string> = { ArrowLeft: "←", ArrowRight: "→", ArrowUp: "↑", ArrowDown: "↓", Escape: "Esc", Enter: "Enter", Space: "Space", Backslash: "\\", Slash: "/", Comma: ",", Period: ".", Minus: "-", Equal: "=", BracketLeft: "[", BracketRight: "]", Tab: "Tab" };
/** The name of a physical key as shown on a key cap ("←", "Esc", "K", "1"). */
export const keyName = (code: string): string => KEY_NAMES[code] ?? code.replace(/^Key/, "").replace(/^Digit/, "");

/**
 * The character a shifted key types on a US keyboard. Shift changes `event.key` ("]" becomes "}", "/" becomes
 * "?"), so a chord written with the unshifted character still matches when Shift is held. Other layouts type
 * their own shifted characters; the combo then names the one the layout types with Shift.
 */
const SHIFTED: Record<string, string> = { "/": "?", "]": "}", "[": "{", "=": "+", "-": "_", "0": ")" };
/** Characters that already carry Shift: a label shows "?" and not "⇧?". */
const SHIFT_CHARACTERS = new Set(Object.values(SHIFTED).concat("?"));

/**
 * Whether a keystroke is AltGr (the Ctrl+Alt pair some layouts use to type characters such as @ or €). AltGr
 * never triggers a shortcut: on those layouts it is how the person types, and Ctrl+Alt is never a default (D206, D222).
 */
export const isAltGraph = (event: KeyboardEvent): boolean => event.getModifierState?.("AltGraph") === true;

/** The key label of a combo as people read it: "K", "+", "Enter" ("↩" on a Mac), or the physical key's name. */
function keyLabelOf(combo: Combo): string {
  if (combo.key === undefined) return keyName(combo.code);
  if (combo.key === "Enter") return isMacPlatform() ? "↩" : "Enter";
  return combo.key.length === 1 ? combo.key.toUpperCase() : combo.key;
}

/** The label of a combination on this platform: ⌘⇧G on a Mac, Ctrl+Shift+G elsewhere. */
export function comboLabel(combo: Combo): string {
  // A legacy combo that names "/" with Shift alone is the "?" key; it is shown as the glyph people type.
  if (combo.code === "Slash" && combo.shift && !combo.mod && !combo.alt && !combo.ctrl && combo.key === undefined) return "?";
  const key = keyLabelOf(combo);
  // Shift is written only when the key itself does not already carry it ("?" is typed with Shift, shown without).
  const shift = combo.shift && !(combo.key !== undefined && SHIFT_CHARACTERS.has(combo.key));
  // Mac glyphs in the order the reference table writes them: ⌘⇧D, ⌥⌘W, ⌘⇧↩.
  if (isMacPlatform()) return `${combo.ctrl ? "⌃" : ""}${combo.alt ? "⌥" : ""}${combo.mod ? "⌘" : ""}${shift ? "⇧" : ""}${key}`;
  // Written in the order the reference table uses on PC: Ctrl+Shift+Alt+Enter.
  return [combo.mod ? "Ctrl" : "", shift ? "Shift" : "", combo.alt ? "Alt" : "", key].filter(Boolean).join("+");
}
/** Whether two combos are the same chord (key and all modifiers). */
export const sameCombo = (a: Combo, b: Combo): boolean => a.code === b.code && Boolean(a.mod) === Boolean(b.mod) && Boolean(a.shift) === Boolean(b.shift) && Boolean(a.alt) === Boolean(b.alt) && Boolean(a.ctrl) === Boolean(b.ctrl);
/** The combination a keystroke makes, read by physical key (how a rebinding is recorded). */
export const comboOf = (event: KeyboardEvent): Combo => ({ code: event.code, mod: isMacPlatform() ? event.metaKey : event.ctrlKey, shift: event.shiftKey, alt: event.altKey, ctrl: isMacPlatform() && event.ctrlKey });

/** Whether the keystroke is the combo. AltGr never matches; key-named combos compare the character, others the physical key. */
export function matchesCombo(event: KeyboardEvent, combo: Combo): boolean {
  if (isAltGraph(event)) return false;
  const mac = isMacPlatform();
  if (Boolean(combo.mod) !== (mac ? event.metaKey : event.ctrlKey)) return false;
  if (Boolean(combo.alt) !== event.altKey) return false;
  if (Boolean(combo.ctrl) !== (mac && event.ctrlKey)) return false;
  if (combo.key === undefined) return event.code === combo.code && Boolean(combo.shift) === event.shiftKey;
  if (combo.shift !== undefined && combo.shift !== event.shiftKey) return false;
  const typed = event.key.toLowerCase();
  return typed === combo.key.toLowerCase() || (combo.shift === true && SHIFTED[combo.key] === event.key);
}

/** The Mac chord or the PC chord, whichever this platform uses. Read where a binding is registered, never cached. */
export const platformCombo = (mac: Combo, other: Combo): Combo => (isMacPlatform() ? mac : other);

/** The binding in force: the user's, else the default. */
export function bindingOf(shortcut: Shortcut): Combo | undefined { return overrides[shortcut.id] ?? shortcut.combo; }
/** Whether the user has rebound the shortcut with this id. */
export const isOverridden = (id: string): boolean => id in overrides;
/** Saves `combo` as the binding of shortcut `id` on this device and tells the listeners. Pass `undefined` to go back to the default. */
export function setBinding(id: string, combo: Combo | undefined): void {
  if (combo) overrides = { ...overrides, [id]: combo }; else { const { [id]: _removed, ...rest } = overrides; overrides = rest; }
  writeLocal(STORE, JSON.stringify(overrides));
  for (const l of listeners) l();
}
/** Drops every rebinding and tells the listeners. */
export function resetBindings(): void { overrides = {}; writeLocal(STORE, "{}"); for (const l of listeners) l(); }
/** Calls `listener` after each change to the bindings. Returns the function that stops it. */
export function onBindingsChange(listener: () => void): () => void { listeners.add(listener); return () => { listeners.delete(listener); }; }

/** The label of a shortcut's current binding ("⌘/", "Ctrl+Shift+/"), or "" when it has none. */
export function bindingLabel(id: string): string {
  const found = allShortcuts().find((entry) => entry.shortcut.id === id);
  const combo = found && bindingOf(found.shortcut);
  return combo ? comboLabel(combo) : "";
}

/** Every registered shortcut, with the user's binding applied to what is shown (`keys`). */
export function allShortcuts(): Array<{ section: ShortcutSection; shortcut: Shortcut }> {
  return [...registered.values()].flatMap((section) => section.shortcuts.map((shortcut) => ({ section, shortcut })));
}

/**
 * Runs `handler` when the binding of shortcut `id` is pressed (capture phase, before a terminal sees it),
 * honouring the user's rebinding live. Returns a remover. `when` may decline a press (a locked window, a
 * closed panel): a declined press is not consumed, so it reaches the terminal as it would without the shortcut.
 */
export function bindShortcut(id: string, handler: (event: KeyboardEvent) => void, when?: (event: KeyboardEvent) => boolean): () => void {
  const onKey = (event: KeyboardEvent): void => {
    if (document.querySelector("[data-capturing]")) return; // Settings, Shortcuts is listening for a new binding
    const found = allShortcuts().find((entry) => entry.shortcut.id === id);
    const combo = found && bindingOf(found.shortcut);
    // A rebinding replaces the primary combo; the alternates stay only while the shortcut still has its default.
    const spare = found && !isOverridden(id) ? found.shortcut.alternates ?? [] : [];
    const hit = combo && [combo, ...spare].find((c) => matchesCombo(event, c));
    if (!hit) return;
    // A key that is typed (no Command, Control or Option: "?", a plain letter) belongs to a text field or a terminal
    // that has focus. Only a chord reaches the shortcut from inside them, so ⌘/ works in a terminal and "?" does not.
    if (!hit.mod && !hit.alt && !hit.ctrl && isTypingTarget(event.target)) return;
    if (when && !when(event)) return;
    event.preventDefault();
    event.stopPropagation();
    handler(event);
  };
  window.addEventListener("keydown", onKey, true);
  return () => window.removeEventListener("keydown", onKey, true);
}

/**
 * Runs `handler` for one fixed combination that is not a rebindable shortcut: a keyboard-lock alternate (D222),
 * for example. Same capture-phase and `when` rules as bindShortcut.
 */
export function bindCombo(combo: Combo, handler: (event: KeyboardEvent) => void, when?: (event: KeyboardEvent) => boolean): () => void {
  const onKey = (event: KeyboardEvent): void => {
    if (!matchesCombo(event, combo)) return;
    if (when && !when(event)) return;
    event.preventDefault();
    event.stopPropagation();
    handler(event);
  };
  window.addEventListener("keydown", onKey, true);
  return () => window.removeEventListener("keydown", onKey, true);
}
