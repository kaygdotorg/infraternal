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
 * (`{ mac: "⌘K", other: "Ctrl+K" }`), and only the one that works here is ever shown.
 */
import { isMacPlatform, shortcutLabel, type PlatformKeys } from "./platform";
import { readLocal, writeLocal } from "./local-pref";

/**
 * A key combination, platform-neutral: `mod` is Command on macOS and Control elsewhere, `code` is the
 * physical key (`KeyG`, `ArrowLeft`, `Digit1`), so a binding means the same key on every layout.
 */
export interface Combo {
  code: string; mod?: boolean; shift?: boolean; alt?: boolean;
  /** The Control key itself on macOS, where `mod` is Command (so Control+Option chords can be written). Ignored elsewhere. */
  ctrl?: boolean;
}

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

export interface ShortcutSection {
  id: string;
  title: string;
  /** The area this section belongs to; `"global"` sections show in every area. */
  area: string;
  shortcuts: Shortcut[];
}

/** The area whose sections are always shown, after the current area's. */
export const GLOBAL_AREA = "global";

/**
 * The command palette key, written once. Every surface that names it (the top pill, the view popover,
 * the palette hints, the shortcuts panel) takes it from here so Mac and PC always agree.
 */
export const PALETTE_KEYS: PlatformKeys = { mac: "⌘K", other: "Ctrl+K" };

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
  if (label.length > 1 && label.includes("+")) return label.split("+");
  // Mac modifier glyphs are one cap each (⌘K → ⌘, K); any other single label (Esc, F6) is one cap.
  const modifiers = /^[⌘⌥⌃⇧]+/.exec(label)?.[0] ?? "";
  return modifiers ? [...modifiers, ...(label.slice(modifiers.length) ? [label.slice(modifiers.length)] : [])] : [label];
}

// ---- user bindings (one source for every surface) ---------------------------------------------------------
const STORE = "tracer.shortcuts";
const listeners = new Set<() => void>();
const loadOverrides = (): Record<string, Combo> => {
  try { const raw = JSON.parse(readLocal(STORE) ?? "{}") as Record<string, Combo>; return raw && typeof raw === "object" ? raw : {}; } catch { return {}; }
};
let overrides = loadOverrides();

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
export const keyName = (code: string): string => KEY_NAMES[code] ?? code.replace(/^Key/, "").replace(/^Digit/, "");

/** The label of a combination on this platform: ⌘⇧G on a Mac, Ctrl+Shift+G elsewhere. */
export function comboLabel(combo: Combo): string {
  const key = keyName(combo.code);
  if (isMacPlatform()) return `${combo.ctrl ? "⌃" : ""}${combo.alt ? "⌥" : ""}${combo.shift ? "⇧" : ""}${combo.mod ? "⌘" : ""}${key}`.replace(/^(⌥?⇧?)(⌘)/, "$1$2");
  return [combo.mod ? "Ctrl" : "", combo.alt ? "Alt" : "", combo.shift ? "Shift" : "", key].filter(Boolean).join("+");
}
export const sameCombo = (a: Combo, b: Combo): boolean => a.code === b.code && Boolean(a.mod) === Boolean(b.mod) && Boolean(a.shift) === Boolean(b.shift) && Boolean(a.alt) === Boolean(b.alt) && Boolean(a.ctrl) === Boolean(b.ctrl);
export const comboOf = (event: KeyboardEvent): Combo => ({ code: event.code, mod: isMacPlatform() ? event.metaKey : event.ctrlKey, shift: event.shiftKey, alt: event.altKey, ctrl: isMacPlatform() && event.ctrlKey });
export const matchesCombo = (event: KeyboardEvent, combo: Combo): boolean => sameCombo(comboOf(event), combo);

/** The binding in force: the user's, else the default. */
export function bindingOf(shortcut: Shortcut): Combo | undefined { return overrides[shortcut.id] ?? shortcut.combo; }
export const isOverridden = (id: string): boolean => id in overrides;
export function setBinding(id: string, combo: Combo | undefined): void {
  if (combo) overrides = { ...overrides, [id]: combo }; else { const { [id]: _removed, ...rest } = overrides; overrides = rest; }
  writeLocal(STORE, JSON.stringify(overrides));
  for (const l of listeners) l();
}
export function resetBindings(): void { overrides = {}; writeLocal(STORE, "{}"); for (const l of listeners) l(); }
export function onBindingsChange(listener: () => void): () => void { listeners.add(listener); return () => { listeners.delete(listener); }; }

/** Every registered shortcut, with the user's binding applied to what is shown (`keys`). */
export function allShortcuts(): Array<{ section: ShortcutSection; shortcut: Shortcut }> {
  return [...registered.values()].flatMap((section) => section.shortcuts.map((shortcut) => ({ section, shortcut })));
}

/**
 * Runs `handler` when the binding of shortcut `id` is pressed (capture phase, before a terminal sees it),
 * honouring the user's rebinding live. Returns a remover.
 */
export function bindShortcut(id: string, handler: (event: KeyboardEvent) => void): () => void {
  const onKey = (event: KeyboardEvent): void => {
    if (document.querySelector("[data-capturing]")) return; // Settings, Shortcuts is listening for a new binding
    const found = allShortcuts().find((entry) => entry.shortcut.id === id);
    const combo = found && bindingOf(found.shortcut);
    // A rebinding replaces the primary combo; the alternates stay only while the shortcut still has its default.
    const spare = found && !isOverridden(id) ? found.shortcut.alternates ?? [] : [];
    if (!combo || ![combo, ...spare].some((c) => matchesCombo(event, c))) return;
    event.preventDefault();
    event.stopPropagation();
    handler(event);
  };
  window.addEventListener("keydown", onKey, true);
  return () => window.removeEventListener("keydown", onKey, true);
}
