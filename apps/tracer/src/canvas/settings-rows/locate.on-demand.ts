// SPDX-License-Identifier: AGPL-3.0-only
/**
 * Where an action points in Settings (issue #304), on demand (D188): only the palette's "open this setting" action needs it, so it loads
 * with that action and never with the page.
 */
import type { ComponentDef } from "./catalog";
import { spots, winId } from "./model";

/** Where each of the old Settings sections went (⌘K, the person's card and the core screen still ask for them by name). */
export const LEGACY: Readonly<Record<string, string>> = {
  appearance: "appearance.theme", windows: "appearance.layout", hosts: "terminal.hosts", toolbar: "terminal.typing", shortcuts: "terminal.typing",
  about: "about.version", account: "you.profile", devices: "you.devices", grants: "mesh.access", users: "you.profile", discovery: "machines.new-machines",
};

/** Resolves an action target (`mesh.keys`, `mesh.keys.connection-keys`, or an old section id) to a window and a setting. */
export function locate(map: readonly ComponentDef[], target: string): { windowId: string; settingId?: string } | undefined {
  const [comp, group, setting] = (LEGACY[target] ?? target).split(".");
  const spot = spots(map).find((s) => s.comp.id === comp && (group === undefined || s.group.id === group));
  if (!spot) return undefined;
  const settingId = setting && spot.group.settings?.includes(setting) ? setting : undefined;
  return { windowId: winId(spot.comp.id, spot.group.id), ...(settingId ? { settingId } : {}) };
}

