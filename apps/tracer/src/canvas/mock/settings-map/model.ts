// SPDX-License-Identifier: AGPL-3.0-only
/**
 * What the table (`catalog.ts`) means for the canvas, with no DOM: which rows and windows a viewer sees, the id of each
 * window, where an old Settings section now lives, the ⌘K rows, and the Settings view itself.
 *
 * Desktop: ONE grid, as wide as the screen, and one band tall per component. A component with n windows splits the width into n equal windows, so every row is as wide as the screen whatever it
 * holds and the windows of a row are level. The canvas already knows this grid (D212: a window that spans columns); the tracks
 * are sized from the rows' seams (`trackPlan`), and nothing here changes the layout code.
 *
 * Phone: the same windows as plain columns, one column per component and the groups stacked in it, because a window that spans
 * several columns would be wider than a phone. A swipe sideways moves between components and up and down inside one moves
 * between its groups, the way every phone view works; the breadcrumb and the sidebar read the same table, so they stay right.
 */
import type { ColumnModel, ViewModel, WindowModel } from "../../model/types";
import type { Metrics } from "../../layout/geometry";
import { CELL, COLUMN_GAP, boxOf, defaultWidth } from "../../layout/geometry";
import { ICON, SECTION_ICON } from "../../views/icons";
import type { OutlineEntry, OutlineRow } from "../../views/settings-outline";
import { formatValue, defaultValue, type SettingValue } from "../../../../../../packages/ui/src/setting-value";
import { SETTINGS_MAP, type ComponentDef, type GroupDef, type SettingDef } from "./catalog";

/** The padding a grid of windows keeps on its two sides together (14 px each, `SIDE` in layout/groups.on-demand.ts). */
const GROUP_SIDE = 28;
/** The room kept between a row and the screen's edge on each side. */
const GUTTER = 16;
/** The most windows a row may hold: the desktop grid is planned for rows of 1 to 5 (`trackPlan`). */
export const MAX_WINDOWS = 5;

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
  appearance: "appearance.theme", windows: "appearance.layout", hosts: "machines.new-machines", toolbar: "terminal.typing", shortcuts: "terminal.typing",
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

/** ⌘K rows. A group is found by its names; a setting by its title, what it does, its technical names and its group. */
export function entriesOf(map: readonly ComponentDef[], valueOf: (s: SettingDef) => SettingValue): OutlineEntry[] {
  const out: OutlineEntry[] = [];
  for (const { comp, group } of spots(map)) {
    const icon = ICON_OF[comp.icon];
    out.push({ label: `${comp.title} › ${group.title}`, hint: "settings", icon, action: `canvas:settings:${comp.id}.${group.id}` });
    for (const s of group.settings ?? []) {
      out.push({ label: s.title, hint: `${comp.title} › ${group.title} · ${formatValue(s.spec, valueOf(s))} · ${s.explain} ${s.keywords ?? ""}`, icon, action: `canvas:settings:${comp.id}.${group.id}.${s.id}` });
    }
  }
  return out;
}

/** Every setting's saved value, kept for the session so a window that is rebuilt (a role change) keeps what was typed. */
const values = new Map<string, SettingValue>();
export const valueOf = (s: SettingDef): SettingValue => values.get(s.id) ?? defaultValue(s.spec);
export const saveValue = (s: SettingDef, v: SettingValue): void => { if (v === defaultValue(s.spec)) values.delete(s.id); else values.set(s.id, v); };

const settingsWindow = (comp: ComponentDef, group: GroupDef, extra: Partial<WindowModel> = {}): WindowModel =>
  ({ id: winId(comp.id, group.id), kind: "settings", host: group.title, session: comp.title, ...extra });

/**
 * The tracks of the desktop grid, sized from the seams. A row of n windows puts its seams at k / n of the row's width; the
 * canvas drops a track in which no window starts, so the tracks are exactly the intervals between the seams of the rows that
 * are present (for 1 to 5 windows: nine seams, ten tracks), and each window spans the tracks between its two seams.
 * With `gap` between tracks, the k-th window of a row of n ends at `(k + 1) * W + k * gap` where `W = (total - (n - 1) * gap) / n`;
 * each track ends where some window ends, so every window of every row has exactly the width W, whatever the other rows hold.
 * `total` is the widest width at or below the target that makes every seam a whole pixel (so no window is blurred by a fraction).
 */
export function trackPlan(counts: readonly number[], target: number, gap: number): { widths: number[]; place(n: number, k: number): { start: number; span: number } } {
  // The widest total at or below the target for which every window width is a whole number of pixels (a window of a row of n is
  // (total - (n - 1) * gap) / n wide); at worst the target itself, rounded down.
  const sizes = [...new Set(counts)];
  let total = Math.floor(target);
  for (let t = total; t > total - 120; t--) if (sizes.every((n) => (t - (n - 1) * gap) % n === 0)) { total = t; break; }
  const width = (n: number): number => (total - (n - 1) * gap) / n;
  const end = (n: number, k: number): number => (k + 1) * width(n) + k * gap;
  const ends: number[] = [];
  for (const n of sizes) for (let k = 0; k < n - 1; k++) ends.push(end(n, k));
  ends.sort((a, b) => a - b);
  const unique = ends.filter((e, i) => i === 0 || e - ends[i - 1]! > 0.01);
  unique.push(total);
  const widths = unique.map((e, t) => e - (t === 0 ? 0 : unique[t - 1]! + gap));
  const at = (px: number, from: "start" | "end"): number => unique.findIndex((e, t) => Math.abs((from === "end" ? e : t === 0 ? 0 : unique[t - 1]! + gap) - px) < 0.01);
  return {
    widths,
    place(n, k) {
      const start = at(k === 0 ? 0 : k * (width(n) + gap), "start"), last = at(end(n, k), "end");
      return { start, span: last - start + 1 };
    },
  };
}

/** The Settings view for a viewer, keeping the place `base` (the view the caller laid out) has on the canvas. */
export function buildSettingsMapView(map: readonly ComponentDef[], m: Metrics, screenW: number, base: ViewModel): ViewModel {
  let cols: ColumnModel[];
  if (m.narrow) {
    const w = defaultWidth(m, map.length);
    cols = map.map((comp) => ({ id: `c-${comp.id}`, w, wins: comp.groups.map((g) => settingsWindow(comp, g, comp.groups.length > 1 ? { h: 1 } : {})) }));
  } else {
    // One screen wide, so every window of a row is on screen at once: the screen less a gutter on each side, less the grid's own
    // side padding (groups.on-demand.ts). A strip of ordinary columns is wider than the screen (a column is a third of it, scaled by
    // the UI size) and the camera moves along it; a row of settings is read as a whole, so it does not.
    const plan = trackPlan(map.map((c) => c.groups.length), screenW - 2 * GUTTER - GROUP_SIDE, COLUMN_GAP);
    cols = plan.widths.map((w, t) => ({ id: `t${t}`, w, wins: [] as WindowModel[] }));
    map.forEach((comp, band) => comp.groups.forEach((g, k) => {
      const { start, span } = plan.place(comp.groups.length, k);
      cols[start]!.wins.push(settingsWindow(comp, g, { span, row: band, rows: 1, h: 1 }));
    }));
  }
  return { ...base, cols };
}
