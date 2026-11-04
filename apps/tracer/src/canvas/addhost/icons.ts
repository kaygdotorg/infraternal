// SPDX-License-Identifier: AGPL-3.0-only
/** Line icons for the add-host wizard on a 24 px grid, drawn with currentColor at a 1.5 stroke. */
export const ICON = {
  plus: `<path d="M12 5v14M5 12h14"/>`,
  close: `<path d="m7 7 10 10M17 7 7 17"/>`,
  servers: `<rect x="3.5" y="4" width="17" height="7" rx="2"/><rect x="3.5" y="13" width="17" height="7" rx="2"/><path d="M7.5 7.5h.01M7.5 16.5h.01"/>`,
  key: `<circle cx="8" cy="15" r="4"/><path d="m10.9 12.1 8.6-8.6M16.5 6l2.5 2.5M14 8.5l1.5 1.5"/>`,
  shield: `<path d="M12 3.2 5 6v5.2c0 4.4 2.9 8.1 7 9.6 4.1-1.5 7-5.2 7-9.6V6z"/>`,
  shieldCheck: `<path d="M12 3.2 5 6v5.2c0 4.4 2.9 8.1 7 9.6 4.1-1.5 7-5.2 7-9.6V6z"/><path d="m9 12 2.2 2.2L15.2 10"/>`,
  warning: `<path d="M10.3 4.6 2.9 17.5A2 2 0 0 0 4.6 20.5h14.8a2 2 0 0 0 1.7-3L13.7 4.6a2 2 0 0 0-3.4 0z"/><path d="M12 9.5v4M12 17h.01"/>`,
  info: `<circle cx="12" cy="12" r="8.5"/><path d="M12 11v5M12 8h.01"/>`,
  ready: `<circle cx="12" cy="12" r="8.5"/><path d="m8.5 12.2 2.4 2.4 4.6-4.8"/>`,
  blocked: `<path d="M12 3.2 5 6v5.2c0 4.4 2.9 8.1 7 9.6 4.1-1.5 7-5.2 7-9.6V6z"/><path d="M9.6 10.2l4.8 4.8M14.4 10.2l-4.8 4.8"/>`,
  silent: `<circle cx="12" cy="12" r="8.5"/><path d="M6 18 18 6"/>`,
  added: `<path d="m5.5 12.5 4 4 9-9"/>`,
  pending: `<circle cx="12" cy="12" r="8.5"/><path d="M12 7.5V12l3 2"/>`,
  typed: `<rect x="3" y="6" width="18" height="12" rx="2"/><path d="M7 10h.01M11 10h.01M15 10h.01M8 14h8"/>`,
  caret: `<path d="m9 6 6 6-6 6"/>`,
  retry: `<path d="M19.5 12a7.5 7.5 0 1 1-2.2-5.3"/><path d="M19.5 4.5v4h-4"/>`,
  rocket: `<path d="M12 15.5 8.5 12c1-4 3.5-7.2 8.5-8.5-1.3 5-4.5 7.5-5 12z"/><path d="M8.5 12 5.5 11.5 8 8.5h3M12 15.5l.5 3 3-2.5v-3M6.5 17.5c-1 .5-1.5 1.5-1.5 2.5 1 0 2-.5 2.5-1.5"/>`,
  terminal: `<rect x="3.5" y="4.5" width="17" height="15" rx="2.5"/><path d="m7.5 10 3 2.5-3 2.5M13 15h4"/>`,
  fingerprint: `<path d="M6 9.5a6 6 0 0 1 12 0v1.8M9 20c.5-1.4.8-3 .8-4.7v-4a2.2 2.2 0 0 1 4.4 0v4c0 2 .4 3.4 1.2 4.7M12 14v3.5c0 1 .2 1.9.5 2.5M6 13c0 2.2-.3 4.2-1 5.5M18 14.5c0 1.5.1 3.2.7 4.5"/>`,
} as const;

/** Wraps icon path markup from `ICON` in an `<svg>` on the 24 px grid. The svg is `aria-hidden`: the control around it carries the name. */
export const svg = (paths: string, className = "ah-icon"): string => `<svg class="${className}" viewBox="0 0 24 24" aria-hidden="true">${paths}</svg>`;
/** Escapes `& < > " '` so text can be put safely into an HTML string. */
export const escapeHtml = (value: string): string => value.replace(/[&<>"']/g, (char) => ({
  "&": "&amp;", "<": "&lt;", ">": "&gt;", "\"": "&quot;", "'": "&#39;",
}[char]!));
