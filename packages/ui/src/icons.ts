import { TICK_PATH } from "./tick";

/**
 * The shared line icons for toolbars and canvas controls (24 px grid, drawn with the shared 1.5
 * to 1.75 stroke by whoever mounts them). Each value is the inner SVG markup, so an icon can sit in
 * a button, a tab or a palette row without a second copy of its geometry.
 */
export const ICONS = {
  search: '<circle cx="11" cy="11" r="6.5"/><path d="m16 16 4 4"/>',
  views: '<rect x="3.5" y="4" width="17" height="6" rx="2"/><rect x="3.5" y="14" width="7.5" height="6" rx="2"/><rect x="14" y="14" width="6.5" height="6" rx="2"/>',
  previous: '<path d="M15 5l-7 7 7 7"/>',
  next: '<path d="M9 5l7 7-7 7"/>',
  // The canvas: a rounded plane with the dots of its backdrop. The canvas lock toggle draws it, and adds the lock badge when on.
  canvas: '<rect x="3.5" y="4.5" width="17" height="15" rx="3"/><path d="M8.5 9.5h.01M15.5 9.5h.01M8.5 14.5h.01M15.5 14.5h.01"/>',
  // A terminal window with its prompt: the glyph of Console and of the input lock toggle (badged when locked).
  terminal: '<rect x="3" y="4" width="18" height="16" rx="3"/><path d="m7 10 3 2-3 2M13 14h4"/>',
  overview: '<path d="M4 9V4h5M20 9V4h-5M4 15v5h5M20 15v5h-5"/><rect x="9" y="9" width="6" height="6" rx="1.5"/>',
  more: '<path d="M5 12h.01M12 12h.01M19 12h.01"/>',
  lock: '<rect x="5" y="11" width="14" height="9.5" rx="2.5"/><path d="M8.5 11V8a3.5 3.5 0 0 1 7 0v3"/>',
  unlock: '<rect x="5" y="11" width="14" height="9.5" rx="2.5"/><path d="M8.5 11V7.5a3.5 3.5 0 0 1 6.6-1.6"/>',
  // Split right: the new window opens beside (a vertical divider). Split down: it opens below (a horizontal one).
  splitRight: '<rect x="4" y="4" width="16" height="16" rx="3"/><path d="M12 4v16"/>',
  splitDown: '<rect x="4" y="4" width="16" height="16" rx="3"/><path d="M4 12h16"/>',
  // New window right and below (D212): a full-size window with a plus, beside or under the current one.
  newRight: '<rect x="3.5" y="4.5" width="8" height="15" rx="2.5"/><path d="M17 9.5v5M14.5 12h5"/>',
  newBelow: '<rect x="4.5" y="3.5" width="15" height="8" rx="2.5"/><path d="M12 16.5v5M9.5 19h5"/>',
  plus: '<path d="M12 5v14M5 12h14"/>',
  // A caution triangle: a failure or a lost connection (the shared toast shows it for its error tone).
  warning: '<path d="M10.3 4.6 2.9 17.5A2 2 0 0 0 4.6 20.5h14.8a2 2 0 0 0 1.7-3L13.7 4.6a2 2 0 0 0-3.4 0z"/><path d="M12 9.5v4M12 17h.01"/>',
  sidebar: '<rect x="3.5" y="4.5" width="17" height="15" rx="3"/><path d="M9.5 4.5v15"/>',
  close: '<path d="m7 7 10 10M17 7 7 17"/>',
  // Open the whole thing: two corner arrows pointing out (the "?" preview's expand icon, #304).
  expandPage: '<path d="M14 4h6v6M10 20H4v-6M20 4l-7 7M4 20l7-7"/>',
  expand: '<path d="M4 9V4h5M20 9V4h-5M4 15v5h5M20 15v5h-5"/>',
  // Settings: the gear of the sidebar footer and of the profile menu.
  gear: '<circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.7 1.7 0 0 0 .3 1.9l.1.1a2 2 0 1 1-2.8 2.8l-.1-.1a1.7 1.7 0 0 0-1.9-.3 1.7 1.7 0 0 0-1 1.5V21a2 2 0 1 1-4 0v-.1a1.7 1.7 0 0 0-1.1-1.5 1.7 1.7 0 0 0-1.9.3l-.1.1a2 2 0 1 1-2.8-2.8l.1-.1a1.7 1.7 0 0 0 .3-1.9 1.7 1.7 0 0 0-1.5-1H3a2 2 0 1 1 0-4h.1a1.7 1.7 0 0 0 1.5-1.1 1.7 1.7 0 0 0-.3-1.9l-.1-.1a2 2 0 1 1 2.8-2.8l.1.1a1.7 1.7 0 0 0 1.9.3h0a1.7 1.7 0 0 0 1-1.5V3a2 2 0 1 1 4 0v.1a1.7 1.7 0 0 0 1 1.5 1.7 1.7 0 0 0 1.9-.3l.1-.1a2 2 0 1 1 2.8 2.8l-.1.1a1.7 1.7 0 0 0-.3 1.9v0a1.7 1.7 0 0 0 1.5 1H21a2 2 0 1 1 0 4h-.1a1.7 1.7 0 0 0-1.5 1Z"/>',
  // Sign out: a door with an arrow leaving it. Used by the profile menu and the Account section.
  signOut: '<path d="M10 5H6.5A1.5 1.5 0 0 0 5 6.5v11A1.5 1.5 0 0 0 6.5 19H10M14 8l4 4-4 4M18 12H9"/>',
} as const;

export type IconName = keyof typeof ICONS;

/**
 * The lock toggles (TASTE: lock icons are the thing plus a lock): a toggle shows the plain icon of what it locks when off,
 * and the same icon with this badge when on. One drawing for every toggle: a small padlock at the top right of the 24 px
 * grid, and a knock-out around it so the icon's own lines stop short of the badge and it reads on any fill behind
 * (the selection circle, a pill). The knock-out is a mask held once in the document (`ensureKnockout`): a mask defined inside
 * an svg that is later hidden would stop applying to every other svg that refers to it.
 */
export const LOCK_BADGE = '<rect x="14.2" y="6.2" width="8" height="6.3" rx="1.6" fill="currentColor" stroke="none"/><path d="M16.2 6.2V5a2 2 0 0 1 4 0v1.2" stroke-width="1.5"/>';
const KNOCKOUT = "ui-lock-knockout";
function ensureKnockout(): void {
  if (typeof document === "undefined" || !document.body || document.getElementById(KNOCKOUT)) return;
  const holder = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  holder.setAttribute("width", "0"); holder.setAttribute("height", "0"); holder.setAttribute("aria-hidden", "true"); holder.setAttribute("focusable", "false");
  holder.style.cssText = "position:absolute;width:0;height:0;overflow:hidden";
  holder.innerHTML = `<defs><mask id="${KNOCKOUT}" maskUnits="userSpaceOnUse" x="0" y="0" width="24" height="24"><rect width="24" height="24" fill="#fff"/><circle cx="18.2" cy="8" r="6.8" fill="#000"/></mask></defs>`;
  document.body.append(holder);
}
/** `inner` (an icon of this set) with the lock badge on top and the knock-out behind it. */
export function withLockBadge(inner: string): string {
  ensureKnockout();
  return `<g mask="url(#${KNOCKOUT})">${inner}</g>${LOCK_BADGE}`;
}
export const iconSvg = (name: IconName): string => `<svg viewBox="0 0 24 24" aria-hidden="true">${ICONS[name]}</svg>`;

/**
 * Small stroke icons shared by flows and notices. Each export is the inner markup of a
 * 24 x 24 viewBox (stroke only, no fill), in the same style as `CLIPBOARD` and `DOWNLOAD`
 * in copy-feedback.ts. `icon()` wraps one in an svg that takes its colour from the text
 * and its size from the surrounding class (16 px on desktop, 18 px on touch, see
 * `.ui-icon` in styles.css).
 */
export const ICON_X = `<path d="M6.5 6.5l11 11M17.5 6.5l-11 11"/>`;
export const ICON_CHECK = `<path d="${TICK_PATH}"/>`;
export const ICON_CLOCK = `<circle cx="12" cy="12" r="8.5"/><path d="M12 7.5V12l3 2"/>`;
export const ICON_INFO = `<circle cx="12" cy="12" r="8.5"/><path d="M12 11v5M12 7.8v.01"/>`;
/** A question mark in a circle: "what is this?", opens the docs for the thing beside it. */
export const ICON_HELP = `<circle cx="12" cy="12" r="8.5"/><path d="M9.7 9.7a2.4 2.4 0 1 1 3.4 2.2c-.7.4-1.1.9-1.1 1.7M12 16.8v.01"/>`;
export const ICON_ALERT = `<circle cx="12" cy="12" r="8.5"/><path d="M12 7.8v5M12 16.2v.01"/>`;
export const ICON_CIRCLE_CHECK = `<circle cx="12" cy="12" r="8.5"/><path d="M8.2 12.4l2.7 2.7 5-5.6"/>`;
/** A chain whose two links have come apart: a session that keeps running with no window showing it (detached). */
export const ICON_DETACHED = `<path d="M10.5 8.5H8.5a3.5 3.5 0 0 0 0 7h2M13.5 8.5h2a3.5 3.5 0 0 1 0 7h-2"/>`;
export const ICON_KEY =`<circle cx="8" cy="12" r="3.5"/><path d="M11.5 12H21M17 12v3M20 12v2"/>`;

/** An inline svg for one of the icon constants; `className` extends `ui-icon`. */
export const icon = (paths: string, className = ""): string =>
  `<svg class="ui-icon ${className}" viewBox="0 0 24 24" aria-hidden="true">${paths}</svg>`;
