/**
 * The one guarantee about palette rows: every row has a title. A row is a label, a hint and an action; a row whose
 * label is empty is a blank line in the list that cannot be told from its neighbours (a settings section whose
 * name was lost on its way in). `titled` is the single gate every row passes through when the palette indexes it.
 *
 * In a development or preview build (`strict`) a missing label throws, so the source that produced it is fixed
 * where it is written. In a production build the row is repaired from its action ("canvas:settings:about" reads as
 * "Settings: About") so the person never sees a blank row.
 */
import type { PaletteEntry } from "./core-screen";
import { SETTINGS_SECTIONS } from "./canvas/views/settings";

/** A readable title for a row that has none: the settings section it opens, else the words of its action. */
export function fallbackLabel(entry: Pick<PaletteEntry, "group" | "action">): string {
  const [, kind, value] = (entry.action ?? "").split(":");
  if (kind === "settings" && value) {
    const section = SETTINGS_SECTIONS.find((s) => s.id === value);
    return `Settings: ${section?.title ?? value}`;
  }
  return entry.group || "Untitled";
}

/** Returns the entry with a non-empty label; throws in a strict (development) build when it had none. */
export function titled<T extends PaletteEntry>(entry: T, strict: boolean): T {
  if (entry.label.trim()) return entry;
  if (strict) throw new Error(`palette row without a title: group "${entry.group}", action "${entry.action ?? ""}"`);
  return { ...entry, label: fallbackLabel(entry) };
}
