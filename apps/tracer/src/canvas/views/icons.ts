/**
 * Icons of the canvas: one source for the glyphs the labels, the pills, the view list, the sidebar and the
 * palette share. Inner SVG markup on the shared 24 px grid (stroke styles come from packages/ui).
 */
import { ICONS } from "../../../../../packages/ui/src/icons";
import { hostIconMarkup } from "../../../../../packages/ui/src/host-icons";
import type { WindowModel } from "../model/types";

export const ICON = {
  close: '<path d="m7 7 10 10M17 7 7 17"/>',
  splitRight: ICONS.splitRight,
  splitDown: ICONS.splitDown,
  terminal: '<path d="m5 8 4 4-4 4M12 16h7"/>',
  containers: '<path d="M12 3 4 7v10l8 4 8-4V7z"/><path d="m4 7 8 4 8-4M12 11v10"/>',
  logs: '<path d="M5 6h14M5 10h10M5 14h14M5 18h8"/>',
  node: '<circle cx="12" cy="12" r="2.6"/><circle cx="5.5" cy="6" r="1.8"/><circle cx="18.5" cy="7" r="1.8"/><circle cx="17.5" cy="18" r="1.8"/><path d="m10 10.4-3-3M14.4 11l2.6-2.7M13.8 13.9l2.6 2.8"/>',
  tag: '<path d="M4 4h7l9 9-7 7-9-9z"/><circle cx="8" cy="8" r="1.2"/>',
  console: '<rect x="3" y="4" width="18" height="16" rx="3"/><path d="m7 10 3 2-3 2M13 14h4"/>',
  chevron: '<path d="m9 6 6 6-6 6"/>',
  port: '<path d="M6 12h10m-4-4 4 4-4 4"/>',
  plus: '<path d="M12 5v14M5 12h14"/>',
  views: ICONS.views,
} as const;
export const lineIcon = (path: string): string => `<svg viewBox="0 0 24 24" class="is-line" aria-hidden="true">${path}</svg>`;
export const VIEW_ICON: Record<string, string> = { console: ICON.console, containers: ICON.containers, mesh: ICON.node, settings: '<circle cx="12" cy="12" r="3"/><path d="M12 3v2.5M12 18.5V21M3 12h2.5M18.5 12H21M5.6 5.6l1.8 1.8M16.6 16.6l1.8 1.8M5.6 18.4l1.8-1.8M16.6 7.4l1.8-1.8"/>' };
/** A shared or custom view has the generic layout icon. */
export const viewIcon = (id: string): string => VIEW_ICON[id] ?? ICON.views;
export const SECTION_ICON: Record<string, string> = {
  appearance: '<circle cx="12" cy="12" r="4"/><path d="M12 3v2M12 19v2M3 12h2M19 12h2M5.6 5.6 7 7M17 17l1.4 1.4M5.6 18.4 7 17M17 7l1.4-1.4"/>',
  toolbar: '<rect x="3" y="14" width="18" height="6" rx="3"/><path d="M7 17h.01M12 17h.01M17 17h.01"/><path d="M8 9h8M10 5h4"/>',
  shortcuts: '<rect x="3" y="6" width="18" height="12" rx="3"/><path d="M7 10h.01M11 10h.01M15 10h.01M8 14h8"/>',
  devices: '<rect x="7" y="3" width="10" height="18" rx="2.5"/><path d="M11 18h2"/>',
  account: '<circle cx="12" cy="8" r="3.5"/><path d="M5 20c1-4 4-5.5 7-5.5s6 1.5 7 5.5"/>',
  about: '<circle cx="12" cy="12" r="9"/><path d="M12 11v5M12 8h.01"/>',
  users: '<circle cx="9" cy="8" r="3"/><path d="M3 19c.8-3.4 3.2-5 6-5s5.2 1.6 6 5M16 5.5a3 3 0 0 1 0 5.5M18 14.5c1.7.6 2.7 2 3 4.5"/>',
  grants: '<circle cx="8" cy="12" r="3.5"/><path d="M11.5 12H21M18 12v3M15 12v2"/>',
  discovery: '<circle cx="11" cy="11" r="6.5"/><path d="m16 16 4 4M11 8v3l2 1.5"/>',
};

/** The icon in a window's pill: the host's OS mark for a terminal, a glyph for the other kinds. */
export const iconFor = (m: WindowModel): string =>
  m.kind === "terminal" ? (m.os ? hostIconMarkup(m.os, "ui-host-mark") : lineIcon(ICON.terminal))
    : m.kind === "settings" ? lineIcon(SECTION_ICON[m.id.slice(2)] ?? viewIcon("settings")) : m.kind === "containers" ? lineIcon(ICON.containers) : m.kind === "logs" ? lineIcon(ICON.logs) : lineIcon(ICON.node);
