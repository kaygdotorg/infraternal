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
import type { OutlineRow } from "../views/settings-outline";
import { SETTINGS_MAP, type ComponentDef, type GroupDef } from "./catalog";

export const winId = (comp: string, group: string): string => `s-${comp}-${group}`;
export interface Spot { comp: ComponentDef; group: GroupDef }

/**
 * Whether a window has anything to show, asked of a viewer's source (#568). The owner chose to hide a window with nothing in it
 * (and its place in the sidebar, the breadcrumb and ⌘K) rather than draw an empty one, and to bring it back when its source can
 * show something. It is a pure question of the table and the source, so the unit test needs no browser.
 */
export interface Showing {
  /** Whether a setting of the table has a store behind it. */
  backed(settingId: string): boolean;
  /** Whether the source fills the group with lists of facts or keys. */
  hasData(comp: string, group: string): boolean;
  /** Whether the Devices panel is offered. */
  devices: boolean;
  /** Whether the server lists subnet routes to this person (its owner): the Mesh Networks window is shown only then (D197 M3). */
  networks?: boolean;
}

/** True when the window has a themes editor, a panel the source offers, a backed setting, or data to list. */
export function hasContent(comp: ComponentDef, group: GroupDef, showing: Showing): boolean {
  if (group.themes) return true;
  if (group.networks) return showing.networks === true;
  const panels = group.panel === undefined ? [] : typeof group.panel === "string" ? [group.panel] : group.panel;
  if (panels.some((id) => id !== "devices" || showing.devices)) return true;
  if ((group.settings ?? []).some((id) => showing.backed(id))) return true;
  return showing.hasData(comp.id, group.id);
}

/**
 * The rows a viewer may see: administrators see everything, others only what is not marked `admin`. With `showing`, a window
 * with nothing to show is left out, and a row left with no windows goes too; without it the whole table is returned.
 */
export function visibleMap(admin: boolean, showing?: Showing): ComponentDef[] {
  return SETTINGS_MAP
    .filter((c) => admin || !c.admin)
    .map((c) => ({ ...c, groups: c.groups.filter((g) => (admin || !g.admin) && (!showing || hasContent(c, g, showing))) }))
    .filter((c) => c.groups.length > 0);
}

export const spots = (map: readonly ComponentDef[]): Spot[] => map.flatMap((comp) => comp.groups.map((group) => ({ comp, group })));
export const spotByWindow = (map: readonly ComponentDef[], id: string): Spot | undefined => spots(map).find((s) => winId(s.comp.id, s.group.id) === id);
/** A settings window's section is its id without the `s-`: `mesh-keys`. */
export const spotBySection = (map: readonly ComponentDef[], section: string): Spot | undefined => spots(map).find((s) => `${s.comp.id}-${s.group.id}` === section);

const section = (id: string): string => SECTION_ICON[id] ?? ICON.host;
export const ICON_OF: Record<ComponentDef["icon"], string> = {
  appearance: section("appearance"), terminal: ICON.terminal, you: section("account"), machines: ICON.host, mesh: ICON.node, sharing: ICON.port, about: section("about"),
};

export function rowsOf(map: readonly ComponentDef[]): OutlineRow[] {
  return map.map((c) => ({ id: c.id, title: c.title, icon: ICON_OF[c.icon], groups: c.groups.map((g) => ({ id: g.id, title: g.title, windowId: winId(c.id, g.id) })) }));
}

const settingsWindow = (comp: ComponentDef, group: GroupDef, extra: Partial<WindowModel> = {}): WindowModel =>
  ({ id: winId(comp.id, group.id), kind: "settings", host: group.title, session: comp.title, ...extra });

/** The name the columns of the Settings view share: the canvas groups columns that name the same group into one grid (layout/grid.ts `runsOf`). */
export const SETTINGS_ROWS = "settings-rows";

/** The ids of the windows a map draws, in order: two maps with the same ids draw the same Settings view. */
export const windowIds = (map: readonly ComponentDef[]): string => spots(map).map((s) => winId(s.comp.id, s.group.id)).join(" ");

/** The Settings view for a viewer, keeping the place `base` (the view the caller laid out) has on the canvas. */
export function buildSettingsMapView(map: readonly ComponentDef[], m: Metrics, base: ViewModel): ViewModel {
  // One column for each window of the longest row, in the default width: nothing here depends on the screen or on a window's content.
  const tracks = Math.max(1, ...map.map((comp) => comp.groups.length));
  const w = defaultWidth(m, tracks);
  const cols: ColumnModel[] = Array.from({ length: tracks }, (_, t) => ({ id: `t${t}`, w, group: SETTINGS_ROWS, wins: [] as WindowModel[] }));
  map.forEach((comp, band) => comp.groups.forEach((g, k) => cols[k]!.wins.push(settingsWindow(comp, g, { row: band, h: 1 }))));
  return { ...base, cols };
}
