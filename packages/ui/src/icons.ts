/**
 * Small stroke icons shared by flows and notices. Each export is the inner markup of a
 * 24 x 24 viewBox (stroke only, no fill), in the same style as `CLIPBOARD` and `DOWNLOAD`
 * in copy-feedback.ts. `icon()` wraps one in an svg that takes its colour from the text
 * and its size from the surrounding class (16 px on desktop, 18 px on touch, see
 * `.ui-icon` in styles.css).
 */
import { TICK_PATH } from "./tick";

export const ICON_X = `<path d="M6.5 6.5l11 11M17.5 6.5l-11 11"/>`;
export const ICON_CHECK = `<path d="${TICK_PATH}"/>`;
export const ICON_CLOCK = `<circle cx="12" cy="12" r="8.5"/><path d="M12 7.5V12l3 2"/>`;
export const ICON_INFO = `<circle cx="12" cy="12" r="8.5"/><path d="M12 11v5M12 7.8v.01"/>`;
export const ICON_ALERT = `<circle cx="12" cy="12" r="8.5"/><path d="M12 7.8v5M12 16.2v.01"/>`;
export const ICON_CIRCLE_CHECK = `<circle cx="12" cy="12" r="8.5"/><path d="M8.2 12.4l2.7 2.7 5-5.6"/>`;
export const ICON_KEY = `<circle cx="8" cy="12" r="3.5"/><path d="M11.5 12H21M17 12v3M20 12v2"/>`;

/** An inline svg for one of the icon constants; `className` extends `ui-icon`. */
export const icon = (paths: string, className = ""): string =>
  `<svg class="ui-icon ${className}" viewBox="0 0 24 24" aria-hidden="true">${paths}</svg>`;
