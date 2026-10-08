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
import { shortcutLabel, type PlatformKeys } from "./platform";

export interface Shortcut {
  id: string;
  label: string;
  keys: PlatformKeys | string;
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

const registered = new Map<string, ShortcutSection>();

/** Registers (or replaces) a section; returns a remover. */
export function registerShortcuts(section: ShortcutSection): () => void {
  registered.set(section.id, section);
  return () => { if (registered.get(section.id) === section) registered.delete(section.id); };
}

/** Sections of the given areas in the order given, then the global ones, each in registration order. */
export function shortcutSections(areas: string[]): ShortcutSection[] {
  const all = [...registered.values()];
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
