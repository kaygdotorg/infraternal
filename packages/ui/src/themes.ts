/** Curated UI and terminal palettes; one theme keeps both color systems coherent. */
import { entityPaletteCss } from "./entity-palette";

import { contrastRatio } from "./color";

export type Ansi = [string, string, string, string, string, string, string, string];

export interface Theme {
  name: string;
  dark: boolean;
  bg: string;
  fg: string;
  fg2: string;
  fg3: string;
  accent: string;
  ok: string;
  ansi: Ansi;
  bright: Ansi;
}

const theme = (
  name: string,
  dark: boolean,
  bg: string,
  fg: string,
  fg2: string,
  fg3: string,
  accent: string,
  ok: string,
  ansi: Ansi,
  bright: Ansi,
): Theme => ({ name, dark, bg, fg, fg2, fg3, accent, ok, ansi, bright });

/** Theme values are the approved mockup palettes; community ANSI colors stay published. */
export const THEMES: Record<string, Theme> = {
  paper: theme("Paper", false, "#f6f6f4", "#1d1d1f", "#65656a", "#8d8d92", "#3d63dd", "#1f9d55",
    ["#2a2a2d", "#bf3228", "#00773b", "#8c5d00", "#2f5fd0", "#8a3fc0", "#007182", "#8d8d93"],
    ["#65656a", "#bb3731", "#007632", "#8e5d00", "#3660cc", "#8e44bf", "#007185", "#1d1d1f"]),
  ink: theme("Ink", true, "#0d0e10", "#ececee", "#8d8d93", "#5f5f65", "#7a9cff", "#3ccf7e",
    ["#1b1c1f", "#ff7b72", "#7ee2a8", "#f2cc60", "#8ab4ff", "#d2a8ff", "#76e3ea", "#c9c9ce"],
    ["#5c5c62", "#ffa198", "#a6f0c4", "#f8e3a1", "#b3ccff", "#e2c5ff", "#b3f0f4", "#ffffff"]),
  latte: theme("Catppuccin Latte", false, "#eff1f5", "#484b65", "#616379", "#878b9a", "#8839ef", "#3e9e29",
    ["#5c5f77", "#c90032", "#017400", "#9c5000", "#0e57e5", "#a6378c", "#006e75", "#acb0be"],
    ["#616379", "#ca022e", "#007500", "#995200", "#3255e4", "#a83689", "#006e77", "#bcc0cc"]),
  mocha: theme("Catppuccin Mocha", true, "#1e1e2e", "#cdd6f4", "#a6adc8", "#6c7086", "#cba6f7", "#a6e3a1",
    ["#45475a", "#f38ba8", "#a6e3a1", "#f9e2af", "#89b4fa", "#f5c2e7", "#94e2d5", "#bac2de"],
    ["#585b70", "#f37799", "#89d88b", "#ebd391", "#74a8fc", "#f2aede", "#6bd7ca", "#a6adc8"]),
  dawn: theme("Rosé Pine Dawn", false, "#faf4ed", "#4f4a71", "#676381", "#908b9d", "#ca7672", "#56949f",
    ["#f2e9e1", "#9c4d64", "#286983", "#9b5400", "#306f7a", "#735d8a", "#9e4f4d", "#575279"],
    ["#9893a5", "#9c4d64", "#286983", "#9b5400", "#306f7a", "#735d8a", "#9e4f4d", "#575279"]),
  rosepine: theme("Rosé Pine", true, "#191724", "#e0def4", "#908caa", "#6e6a86", "#ebbcba", "#9ccfd8",
    ["#26233a", "#eb6f92", "#5294b0", "#f6c177", "#9ccfd8", "#c4a7e7", "#ebbcba", "#e0def4"],
    ["#6e6a86", "#eb6f92", "#5294b0", "#f6c177", "#9ccfd8", "#c4a7e7", "#ebbcba", "#e0def4"]),
  nord: theme("Nord", true, "#2e3440", "#eceff4", "#d8dee9", "#7b88a1", "#88c0d0", "#a3be8c",
    ["#3b4252", "#ef8b93", "#a3be8c", "#ebcb8b", "#8caccc", "#c39cbc", "#88c0d0", "#e5e9f0"],
    ["#4c566a", "#ef8b93", "#a3be8c", "#ebcb8b", "#8caccc", "#c39cbc", "#8fbcbb", "#eceff4"]),
  tokyo: theme("Tokyo Night", true, "#1a1b26", "#c0caf5", "#a9b1d6", "#5c658f", "#7aa2f7", "#9ece6a",
    ["#15161e", "#f7768e", "#9ece6a", "#e0af68", "#7aa2f7", "#bb9af7", "#7dcfff", "#a9b1d6"],
    ["#414868", "#f7768e", "#9ece6a", "#e0af68", "#7aa2f7", "#bb9af7", "#7dcfff", "#c0caf5"]),
  gruvbox: theme("Gruvbox", true, "#282828", "#ebdbb2", "#bdae93", "#7c6f64", "#fabd2f", "#b8bb26",
    ["#282828", "#ff6a59", "#a09f27", "#d79921", "#64a4a7", "#d381a6", "#72a874", "#a89984"],
    ["#928374", "#ff6a52", "#b8bb26", "#fabd2f", "#83a598", "#d3869b", "#8ec07c", "#ebdbb2"]),
  dracula: theme("Dracula", true, "#282a36", "#f8f8f2", "#bfbfd0", "#6272a4", "#bd93f9", "#50fa7b",
    ["#21222c", "#ff6f6c", "#50fa7b", "#f1fa8c", "#bd93f9", "#ff79c6", "#8be9fd", "#f8f8f2"],
    ["#6272a4", "#ff6e6e", "#69ff94", "#ffffa5", "#d6acff", "#ff92df", "#a4ffff", "#ffffff"]),
};

/** Mixes one curated hex color toward another to derive theme-matched surfaces. */
function mix(left: string, right: string, amount: number): string {
  const channels = (hex: string) => [1, 3, 5].map((index) => parseInt(hex.slice(index, index + 2), 16));
  const [from, to] = [channels(left), channels(right)];
  return `#${from.map((value, index) => Math.round(value + ((to[index] ?? value) - value) * amount).toString(16).padStart(2, "0")).join("")}`;
}

export interface OverlayMaterial {
  overlay: string;
  /** The tint at 0.9: a soft halo behind text on the material, so contrast comes from the halo and not from more tint. */
  halo: string;
  /** Large floating panels (the sidebar): thinner than pills so content visibly blurs through. */
  overlayPanel: string;
  overlaySolid: string;
  overlayLine: string;
  shadow: string;
  largeShadow: string;
  /** The shadow of a window inside a scrolling column: it must end inside the column's 14 px padding and the viewport's edge (2 px on a full-width phone window), because the scroller clips whatever lies beyond it and a clipped shadow shows as a square backing behind the rounded card. */
  columnShadow: string;
  surface: string;
}

/** Keeps dark glass close to its palette and computes the same alpha composite used by the contrast audit. */
/**
 * How much of what is behind shows through, in four named levels, for the two kinds of surface (the owner's
 * approved values). Cards are the floating material (popovers, palette, sidebar, pills, toasts); windows are the
 * terminal and other window cards. `dark` and `light` are the fill's opacity on a dark and on a light theme;
 * `blur` is the backdrop blur in CSS pixels. Only Frosted blurs windows (many large blurred windows cost frames
 * and memory), and only the windows on screen (see canvas/memory.ts). Solid paints no transparency and no blur at
 * all. Levels apply through one token write (`applyTheme`); nothing runs per frame.
 */
export const LEVEL_NAMES = ["Solid", "Tinted", "Clear", "Frosted"] as const;
export interface Level { dark: number; light: number; blur: number }
export const CARD_LEVELS: Record<number, Level> = {
  1: { dark: 1, light: 1, blur: 0 },
  2: { dark: 0.7, light: 0.78, blur: 8 },
  3: { dark: 0.4, light: 0.5, blur: 24 },
  4: { dark: 0.2, light: 0.3, blur: 32 },
};
export const WINDOW_LEVELS: Record<number, Level> = {
  1: { dark: 1, light: 1, blur: 0 },
  2: { dark: 0.85, light: 0.9, blur: 0 },
  3: { dark: 0.65, light: 0.75, blur: 0 },
  4: { dark: 0.45, light: 0.55, blur: 24 },
};
/** Cards default to Tinted, windows to Solid. */
export const DEFAULT_CARD = 2;
export const DEFAULT_WINDOW = 1;
export const levelName = (level: number): string => LEVEL_NAMES[level - 1] ?? LEVEL_NAMES[0];

export function overlayMaterial(active: Theme, level = DEFAULT_CARD): OverlayMaterial {
  const tinted = mix(active.bg, "#ffffff", active.dark ? 0.06 : 0.6);
  // The one floating-card material (popover, flow card, confirmation, sidebar, toast): the page
  // behind must visibly show through, softly blurred. Secondary text over the busiest terminal
  // state stays above 4.5:1 (a text shadow carries it at the thin levels, never more tint).
  const glass = CARD_LEVELS[level] ?? CARD_LEVELS[DEFAULT_CARD]!;
  const opacity = active.dark ? glass.dark : glass.light;
  const channels = (hex: string) => [1, 3, 5].map((index) => Number.parseInt(hex.slice(index, index + 2), 16));
  const rgb = (hex: string) => channels(hex).join(" ");
  const tint = channels(tinted);
  const background = channels(active.bg);
  const surface = `#${tint.map((channel, index) => Math.round(channel * opacity + background[index]! * (1 - opacity)).toString(16).padStart(2, "0")).join("")}`;

  return {
    overlay: `rgb(${rgb(tinted)} / ${opacity})`,
    halo: `rgb(${rgb(tinted)} / 1)`,
    overlayPanel: `rgb(${rgb(tinted)} / ${opacity})`,
    overlaySolid: mix(active.bg, "#ffffff", active.dark ? 0.07 : 0.7),
    overlayLine: `rgb(${rgb(active.fg)} / 0.09)`,
    shadow: active.dark
      ? "0 1px 1px rgb(0 0 0 / 0.3), 0 12px 32px -8px rgb(0 0 0 / 0.6)"
      : "0 1px 1px rgb(0 0 0 / 0.04), 0 8px 24px -6px rgb(0 0 0 / 0.12)",
    columnShadow: active.dark
      ? "0 1px 1px rgb(0 0 0 / 0.3), 0 6px 12px -10px rgb(0 0 0 / 0.6)"
      : "0 1px 1px rgb(0 0 0 / 0.04), 0 6px 12px -10px rgb(0 0 0 / 0.12)",
    largeShadow: active.dark
      ? "0 2px 3px rgb(0 0 0 / 0.34), 0 24px 56px -10px rgb(0 0 0 / 0.72)"
      : "0 2px 4px rgb(0 0 0 / 0.08), 0 20px 48px -8px rgb(0 0 0 / 0.24)",
    surface,
  };
}

/**
 * The glass levels as literal rules keyed by `data-card` / `data-window-level` / `data-scheme` on the root, written once.
 * A level change is then one attribute write that restyles only the elements these rules match. The same numbers as
 * custom properties on the root restyled every element of the page (measured: 10-26 ms against about 1 ms with
 * 1,800 elements), because every descendant inherits a changed custom property. Specificity is zero (`:where`), so
 * an instance that sets its own blur (the sign-in card) or the reduced-transparency rule still wins.
 */
let levelRules = false;
/** Every element that reads the card tint (see styles.css, tooltip.ts and the key tray's lock mark). */
const TINT_USERS = ".ui-overlay-surface, .ui-panel, .ui-pill, .ui-window-actions, .tip, .tip-arrow, .keybar button";
function installLevelRules(): void {
  if (levelRules || typeof CSSStyleSheet === "undefined") return;
  levelRules = true;
  const css: string[] = [];
  // The card tint (`--overlay`, `--ui-overlay-halo`) depends on theme and level. It is set on the elements that read it,
  // not on the root, so a theme or level change restyles those few elements and not every element of the page.
  for (const [id, active] of Object.entries(THEMES)) {
    for (const level of Object.keys(CARD_LEVELS)) {
      const m = overlayMaterial(active, Number(level));
      css.push(`:where(:root[data-theme="${id}"][data-card="${levelName(Number(level)).toLowerCase()}"]) :where(${TINT_USERS}) { --overlay: ${m.overlay}; --ui-overlay-halo: ${m.halo}; }`);
      css.push(`:root[data-theme="${id}"][data-card="${levelName(Number(level)).toLowerCase()}"] .keybar button::after { --overlay: ${m.overlay}; }`);
    }
  }
  for (const [level, glass] of Object.entries(CARD_LEVELS)) {
    css.push(`:where(:root[data-card="${levelName(Number(level)).toLowerCase()}"]) :where(.ui-overlay-surface, .ui-panel, .ui-pill) { --ui-overlay-blur: ${glass.blur}px; }`);
  }
  for (const [level, glass] of Object.entries(WINDOW_LEVELS)) {
    const name = levelName(Number(level)).toLowerCase();
    if (name === "solid") continue;
    for (const scheme of ["dark", "light"] as const) {
      css.push(`:root[data-window-level="${name}"][data-scheme="${scheme}"] .ui-window { background: color-mix(in srgb, var(--bg) ${Math.round(glass[scheme] * 100)}%, transparent); }`);
    }
    if (glass.blur) css.push(`:root[data-window-level="${name}"] .ui-window[data-onscreen] { -webkit-backdrop-filter: blur(${glass.blur}px); backdrop-filter: blur(${glass.blur}px); }`);
  }
  css.push(...entityPaletteCss());
  const sheet = new CSSStyleSheet();
  sheet.replaceSync(css.join("\n"));
  document.adoptedStyleSheets = [...document.adoptedStyleSheets, sheet];
}

/** Applies UI tokens and mesh source hues; derived surfaces stay coherent with the theme. */
export function applyTheme(active: Theme, root: HTMLElement, cardLevel = DEFAULT_CARD, windowLevel = DEFAULT_WINDOW): void {
  const style = root.style;
  const rgb = (hex: string) => [1, 3, 5].map((index) => parseInt(hex.slice(index, index + 2), 16)).join(" ");
  const overlay = overlayMaterial(active, cardLevel);
  // Windows: a translucent fill (no blur except at Frosted). The data attributes let CSS skip the filter and the
  // alpha entirely at Solid, so the default paints exactly what an opaque card paints.
  installLevelRules();
  root.dataset.scheme = active.dark ? "dark" : "light";
  root.dataset.card = levelName(cardLevel).toLowerCase();
  root.dataset.windowLevel = levelName(windowLevel).toLowerCase();
  style.setProperty("--bg", active.bg);
  style.setProperty("--fg", active.fg);
  style.setProperty("--fg-2", active.fg2);
  style.setProperty("--fg-3", active.fg3);
  style.setProperty("--accent", active.accent);
  style.setProperty("--accent-soft", `rgb(${rgb(active.accent)} / 0.16)`);
  style.setProperty("--accent-fg", active.dark ? active.bg : "#ffffff");
  style.setProperty("--ok", active.ok);
  // The canvas backdrop: the gradient shows everywhere at this strength, and the dots are light marks (a brighter
  // tint of the gradient on dark themes, a deeper one on light themes) at a low opacity.
  style.setProperty("--gradient-opacity", active.dark ? "0.46" : "0.32");
  style.setProperty("--dot-opacity", active.dark ? "0.4" : "0.34");
  style.setProperty("--dot-color", active.dark ? "color-mix(in oklab, var(--mesh-3) 40%, white)" : "color-mix(in oklab, var(--mesh-3) 55%, black)");
  style.setProperty("--warn", active.ansi[3]); // the theme's amber: slow links, approximate screens
  style.setProperty("--danger", active.ansi[1]);
  const themeId = Object.keys(THEMES).find((key) => THEMES[key] === active);
  if (themeId) root.dataset.theme = themeId;
  style.setProperty("--overlay-solid", overlay.overlaySolid);
  style.setProperty("--overlay-line", overlay.overlayLine);
  style.setProperty("--shadow", overlay.shadow);
  style.setProperty("--overlay-shadow-large", overlay.largeShadow);
  style.setProperty("--shadow-column", overlay.columnShadow);
  // Elevation for lifted in-page cards (a flow card over its window): a tight contact
  // shadow plus a wide ambient one. Not glass: no highlight, no blur.
  style.setProperty("--elevation", active.dark
    ? "0 0 0 1px rgb(0 0 0 / 0.35), 0 1px 2px rgb(0 0 0 / 0.5), 0 8px 20px -6px rgb(0 0 0 / 0.5), 0 36px 90px -18px rgb(0 0 0 / 0.8)"
    : "0 0 0 1px rgb(0 0 0 / 0.05), 0 1px 2px rgb(0 0 0 / 0.1), 0 8px 20px -6px rgb(0 0 0 / 0.14), 0 36px 90px -18px rgb(0 0 0 / 0.32)");
  style.setProperty("--overlay-highlight", `rgb(255 255 255 / ${active.dark ? "0.32" : "0.78"})`);
  style.setProperty("--line", `rgb(${rgb(active.fg)} / 0.07)`);
  style.setProperty("--hover", `rgb(${rgb(active.fg)} / 0.06)`);
  root.style.colorScheme = active.dark ? "dark" : "light";
  style.setProperty("--mesh-1", active.accent);
  style.setProperty("--mesh-2", active.ansi[4]);
  style.setProperty("--mesh-3", active.ansi[5]);
  style.setProperty("--mesh-4", active.ansi[6]);
}

/** A colour a fraction of the way from `from` to `to`, in sRGB, as six-digit hex. */
function mixHex(from: string, to: string, amount: number): string {
  const channel = (hex: string, index: number): number => parseInt(hex.slice(index, index + 2), 16);
  return `#${[1, 3, 5].map((index) => Math.round(channel(from, index) + (channel(to, index) - channel(from, index)) * amount).toString(16).padStart(2, "0")).join("")}`;
}

/**
 * The terminal's selection colours for a theme (#426, D365). The highlight is the accent mixed into the background. On a light
 * theme it stays the soft third it always was, with the theme's text on it. On a dark theme a third of the accent is nearly
 * invisible and the renderer's default selected text (dark) was unreadable on it, so the mix grows until the highlight stands
 * out from the cell (3:1) while the selected text, the theme's own, still reads on it (4.5:1); if no mix does both, the one
 * that comes closest is used. Where the theme's own text cannot do it, the text is white, or the theme's background on a lighter highlight.
 */
export function selectionColors(active: Theme): { background: string; foreground: string } {
  const soft = mixHex(active.bg, active.accent, 0x55 / 255);
  if (!active.dark) return { background: soft, foreground: active.fg };
  let best = { background: soft, foreground: active.fg }, bestScore = -1;
  // The theme's own text first; then plain white, then the theme's background colour as dark text on a lighter highlight,
  // where no mix gives the theme's own text enough room (a dark theme whose accent is light or dim).
  for (const foreground of [active.fg, "#ffffff", active.bg]) {
    for (let step = 66; step <= 190; step++) {
      const background = mixHex(active.bg, active.accent, step / 200);
      const score = Math.min(contrastRatio(background, active.bg) / 3, contrastRatio(foreground, background) / 4.5);
      if (score >= 1) return { background, foreground };
      if (score > bestScore) { bestScore = score; best = { background, foreground }; }
    }
  }
  return best;
}

/** Builds the Ghostty ANSI palette; translucent mode reveals the still backdrop. */
export function terminalTheme(active: Theme, translucent: boolean) {
  const [black, red, green, yellow, blue, magenta, cyan, white] = active.ansi;
  const [brightBlack, brightRed, brightGreen, brightYellow, brightBlue, brightMagenta, brightCyan, brightWhite] = active.bright;
  const selection = selectionColors(active);
  return {
    background: translucent ? "rgba(0,0,0,0)" : active.bg,
    foreground: active.fg,
    cursor: active.accent,
    selectionBackground: selection.background,
    selectionForeground: selection.foreground,
    black,
    red,
    green,
    yellow,
    blue,
    magenta,
    cyan,
    white,
    brightBlack,
    brightRed,
    brightGreen,
    brightYellow,
    brightBlue,
    brightMagenta,
    brightCyan,
    brightWhite,
  };
}
