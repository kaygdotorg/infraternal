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
  snap: '<path d="M4 4h6v6H4zM14 4h6v6h-6zM4 14h6v6H4zM14 14h6v6h-6z"/>',
  overview: '<path d="M4 9V4h5M20 9V4h-5M4 15v5h5M20 15v5h-5"/><rect x="9" y="9" width="6" height="6" rx="1.5"/>',
  lock: '<rect x="5" y="11" width="14" height="9.5" rx="2.5"/><path d="M8.5 11V8a3.5 3.5 0 0 1 7 0v3"/>',
  unlock: '<rect x="5" y="11" width="14" height="9.5" rx="2.5"/><path d="M8.5 11V7.5a3.5 3.5 0 0 1 6.6-1.6"/>',
  split: '<rect x="4" y="4" width="16" height="16" rx="3"/><path d="M4 12h16"/>',
  plus: '<path d="M12 5v14M5 12h14"/>',
  sidebar: '<rect x="3.5" y="4.5" width="17" height="15" rx="3"/><path d="M9.5 4.5v15"/>',
  close: '<path d="m7 7 10 10M17 7 7 17"/>',
  expand: '<path d="M4 9V4h5M20 9V4h-5M4 15v5h5M20 15v5h-5"/>',
} as const;

export type IconName = keyof typeof ICONS;
export const iconSvg = (name: IconName): string => `<svg viewBox="0 0 24 24" aria-hidden="true">${ICONS[name]}</svg>`;
