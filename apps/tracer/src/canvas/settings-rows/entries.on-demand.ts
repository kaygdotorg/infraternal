// SPDX-License-Identifier: AGPL-3.0-only
/**
 * The ⌘K rows of Settings (issue #304), on demand (D188): they name every setting and so need its wording (`definitions.on-demand.ts`).
 * The palette asks for them once it is open; until they arrive it shows the group rows.
 */
import { formatValue, type SettingValue } from "../../../../../packages/ui/src/setting-value";
import type { OutlineEntry } from "../views/settings-outline";
import type { ComponentDef } from "./catalog";
import { SETTING_DEFS, defaultOf, type SettingDef } from "./definitions.on-demand";

/** The definitions travel with the rows: one on-demand root, so the page never has an edge into the definitions themselves. */
export { SETTING_DEFS, defaultOf };
import { ICON_OF, spots } from "./model";

/**
 * ⌘K rows. A group is found by its names; a setting by its title, what it does, its technical names and its group. Only a setting
 * that is backed is offered: ⌘K must not fly to a window that has no control for it.
 */
export function entriesOf(map: readonly ComponentDef[], valueOf: (s: SettingDef, standard: SettingValue) => SettingValue, backed: (settingId: string) => boolean): OutlineEntry[] {
  const out: OutlineEntry[] = [];
  for (const { comp, group } of spots(map)) {
    const icon = ICON_OF[comp.icon];
    out.push({ label: `${comp.title} › ${group.title}`, hint: "settings", icon, action: `canvas:settings:${comp.id}.${group.id}` });
    for (const s of (group.settings ?? []).filter(backed).map((id) => SETTING_DEFS[id]!)) {
      out.push({ label: s.title, hint: `${comp.title} › ${group.title} · ${formatValue(s.spec, valueOf(s, defaultOf(s)))} · ${s.explain} ${s.keywords ?? ""}`, icon, action: `canvas:settings:${comp.id}.${group.id}.${s.id}` });
    }
  }
  return out;
}

