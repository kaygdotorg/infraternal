// SPDX-License-Identifier: AGPL-3.0-only
/**
 * The shape of Settings when it is a cluster of rows (issue #304): a ROW is a component (Mesh), a WINDOW in the row is one
 * group of it (Keys). A settings source that has this `outline` lets the rest of the canvas show the same nesting without
 * knowing what the settings are: the sidebar lists Settings › Mesh › Keys, the top breadcrumb names the focused window the
 * same way, and ⌘K jumps to a group or to one setting. A source without it (the product today) changes nothing anywhere.
 */

export interface OutlineGroup { id: string; title: string; windowId: string }
export interface OutlineRow { id: string; title: string; /** Inner SVG on the 24 grid. */ icon: string; groups: OutlineGroup[] }
export interface OutlineEntry { label: string; hint: string; icon: string; /** A `canvas:settings:<target>` action. */ action: string }

export interface SettingsOutline {
  /** The rows the viewer may see, top to bottom. */
  rows(): OutlineRow[];
  /** ⌘K rows: one per group and one per setting. */
  entries(): OutlineEntry[];
  /** Where an action target points: the window to bring into view and, for one setting, the row to show in it. */
  locate(target: string): { windowId: string; settingId?: string } | undefined;
  /** Shows a setting's row inside its window (scrolled into view, with a faint fill that fades). */
  reveal(windowId: string, settingId: string): void;
}
