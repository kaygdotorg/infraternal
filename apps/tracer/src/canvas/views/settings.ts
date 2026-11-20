/**
 * The Settings view (D179): a view like the others, one window per section, tiled in columns. Admin sections exist
 * only for people whose grants allow them (D164, D172).
 */
import type { Metrics } from "../layout/geometry";
import type { ViewModel } from "../model/types";

export const SETTINGS_SECTIONS: Array<{ id: string; title: string; admin?: boolean }> = [
  { id: "appearance", title: "Appearance" },
  { id: "windows", title: "Window Sizes" },
  { id: "hosts", title: "Hosts" },
  { id: "toolbar", title: "Toolbar" },
  { id: "shortcuts", title: "Shortcuts" },
  { id: "devices", title: "Devices" },
  { id: "account", title: "Account" },
  { id: "about", title: "About" },
  { id: "users", title: "Users", admin: true },
  { id: "grants", title: "Access", admin: true },
  { id: "discovery", title: "Found hosts", admin: true },
];

/** Sections the app renders itself (the rest come from a `SettingsSource`). */
export const BUILTIN_SECTIONS = ["windows", "hosts", "toolbar", "shortcuts", "account", "about"] as const;

/** Settings is a view like the others: one window per section, tiled in columns. */
export function buildSettingsView(admin: boolean, m: Metrics, available: readonly string[] = SETTINGS_SECTIONS.map((s) => s.id)): ViewModel {
  const sections = SETTINGS_SECTIONS.filter((s) => (!s.admin || admin) && available.includes(s.id));
  return {
    id: "settings", name: "Settings", layout: "tiled", nodes: [], x: 0, y: 0,
    cols: sections.map((s) => ({ id: `s-${s.id}`, w: m.colW, wins: [{ id: `s-${s.id}`, kind: "settings" as const, host: s.title }] })),
  };
}