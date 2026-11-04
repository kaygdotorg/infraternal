// SPDX-License-Identifier: AGPL-3.0-only
/**
 * What the table (`catalog.ts`) means for the canvas, with no DOM: which rows and windows a viewer sees, the id of each
 * window, where an old Settings section now lives, the ⌘K rows, and the Settings view itself.
 *
 * One component is ONE ROW of windows (owner, D212 amendment 2026-11-03: "Settings - Appearance is one row which scrolls down to ... Access,
 * no per window scrolling. they scroll up and down as groups"). The view is one grid of row groups: a column (track) for each window of the longest
 * row, every track the layout's default width (`defaultWidth`, Settings -> Window Sizes: what a terminal window gets), one band for each component,
 * every window at its track and its band, the layout's height (`h: 1`: one screen). No window spans columns: a row with fewer windows than the longest one
 * simply ends early. A row's further windows are reached by scrolling sideways (the canvas's stop for each column); scrolling down moves to the next
 * component's row as a group (a step for each band), the whole row together. A window keeps its size and scrolls its own content (one finger, or a wheel over
 * content that can scroll, D275; two fingers, or the wheel at the content's end, move the canvas): it never grows to fit what is in it.
 *
 * The breadcrumb and the sidebar read the same table, so they say Settings > Component > Window.
 */
import type { ColumnModel, ViewModel, WindowModel } from "../model/types";
import type { Metrics } from "../layout/geometry";
import { defaultWidth } from "../layout/geometry";
import { ICON, SECTION_ICON } from "../views/icons";
import type { OutlineEntry, OutlineRow } from "../views/settings-outline";
import { formatValue, type SettingValue } from "../../../../../packages/ui/src/setting-value";
import { SETTINGS_MAP, type ComponentDef, type GroupDef, type SettingDef } from "./catalog";

export const winId = (comp: string, group: string): string => `s-${comp}-${group}`;
export interface Spot { comp: ComponentDef; group: GroupDef }

/** The rows a viewer may see: administrators see everything, others only what is not marked `admin`. */
export function visibleMap(admin: boolean): ComponentDef[] {
  return SETTINGS_MAP
    .filter((c) => admin || !c.admin)
    .map((c) => ({ ...c, groups: c.groups.filter((g) => admin || !g.admin) }))
    .filter((c) => c.groups.length > 0);
}

export const spots = (map: readonly ComponentDef[]): Spot[] => map.flatMap((comp) => comp.groups.map((group) => ({ comp, group })));
export const spotByWindow = (map: readonly ComponentDef[], id: string): Spot | undefined => spots(map).find((s) => winId(s.comp.id, s.group.id) === id);
/** A settings window's section is its id without the `s-`: `mesh-keys`. */
export const spotBySection = (map: readonly ComponentDef[], section: string): Spot | undefined => spots(map).find((s) => `${s.comp.id}-${s.group.id}` === section);

/** Where each of the old Settings sections went (⌘K, the person's card and the core screen still ask for them by name). */
export const LEGACY: Readonly<Record<string, string>> = {
  appearance: "appearance.theme", windows: "appearance.layout", hosts: "terminal.hosts", toolbar: "terminal.typing", shortcuts: "terminal.typing",
  about: "about.version", account: "you.profile", devices: "you.devices", grants: "mesh.access", users: "you.profile", discovery: "machines.new-machines",
};

const section = (id: string): string => SECTION_ICON[id] ?? ICON.host;
export const ICON_OF: Record<ComponentDef["icon"], string> = {
  appearance: section("appearance"), terminal: ICON.terminal, you: section("account"), machines: ICON.host, mesh: ICON.node, sharing: ICON.port, about: section("about"),
};

/** Resolves an action target (`mesh.keys`, `mesh.keys.connection-keys`, or an old section id) to a window and a setting. */
export function locate(map: readonly ComponentDef[], target: string): { windowId: string; settingId?: string } | undefined {
  const [comp, group, setting] = (LEGACY[target] ?? target).split(".");
  const spot = spots(map).find((s) => s.comp.id === comp && (group === undefined || s.group.id === group));
  if (!spot) return undefined;
  const settingId = setting && spot.group.settings?.some((s) => s.id === setting) ? setting : undefined;
  return { windowId: winId(spot.comp.id, spot.group.id), ...(settingId ? { settingId } : {}) };
}

export function rowsOf(map: readonly ComponentDef[]): OutlineRow[] {
  return map.map((c) => ({ id: c.id, title: c.title, icon: ICON_OF[c.icon], groups: c.groups.map((g) => ({ id: g.id, title: g.title, windowId: winId(c.id, g.id) })) }));
}

/**
 * ⌘K rows. A group is found by its names; a setting by its title, what it does, its technical names and its group. Only a setting
 * that is backed is offered: ⌘K must not fly to a window that has no control for it.
 */
export function entriesOf(map: readonly ComponentDef[], valueOf: (s: SettingDef) => SettingValue, backed: (settingId: string) => boolean): OutlineEntry[] {
  const out: OutlineEntry[] = [];
  for (const { comp, group } of spots(map)) {
    const icon = ICON_OF[comp.icon];
    out.push({ label: `${comp.title} › ${group.title}`, hint: "settings", icon, action: `canvas:settings:${comp.id}.${group.id}` });
    for (const s of (group.settings ?? []).filter((x) => backed(x.id))) {
      out.push({ label: s.title, hint: `${comp.title} › ${group.title} · ${formatValue(s.spec, valueOf(s))} · ${s.explain} ${s.keywords ?? ""}`, icon, action: `canvas:settings:${comp.id}.${group.id}.${s.id}` });
    }
  }
  return out;
}

const settingsWindow = (comp: ComponentDef, group: GroupDef, extra: Partial<WindowModel> = {}): WindowModel =>
  ({ id: winId(comp.id, group.id), kind: "settings", host: group.title, session: comp.title, ...extra });

/** The name the columns of the Settings view share: the canvas groups columns that name the same group into one grid (layout/grid.ts `runsOf`). */
export const SETTINGS_ROWS = "settings-rows";

/** The Settings view for a viewer, keeping the place `base` (the view the caller laid out) has on the canvas. */
export function buildSettingsMapView(map: readonly ComponentDef[], m: Metrics, base: ViewModel): ViewModel {
  // One column for each window of the longest row, in the default width: nothing here depends on the screen or on a window's content.
  const tracks = Math.max(1, ...map.map((comp) => comp.groups.length));
  const w = defaultWidth(m, tracks);
  const cols: ColumnModel[] = Array.from({ length: tracks }, (_, t) => ({ id: `t${t}`, w, group: SETTINGS_ROWS, wins: [] as WindowModel[] }));
  map.forEach((comp, band) => comp.groups.forEach((g, k) => cols[k]!.wins.push(settingsWindow(comp, g, { row: band, h: 1 }))));
  return { ...base, cols };
}
