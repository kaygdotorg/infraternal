/** Curated UI and terminal palettes; one theme keeps both color systems coherent. */
import { entityPaletteCss } from "./entity-palette";

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

/**
 * Theme values are the approved mockup palettes; community ANSI colors stay published. The schemes after Dracula are D329's additions: each is the
 * upstream's published palette with every colour that was under D80's lines repaired by OKLab lightness only (`theme-audit.ts`; the generator is
 * `scripts/theme-palettes.ts` and the log of each change is docs/design/THEME-AUDIT.md). Their sources and licences are in THIRD_PARTY_NOTICES.md.
 */
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
  // Solarized (Ethan Schoonover), base3 background
  "solarized-light": theme("Solarized Light", false, "#fdf6e3", "#3e535a", "#5f747c", "#839191", "#268bd2", "#667800",
    ["#073642", "#d72d2b", "#667800", "#946900", "#0075bb", "#cd2f7d", "#007f77", "#eee8d5"],
    ["#5f747c", "#c6131a", "#677800", "#936900", "#0075bb", "#be1c70", "#007f77", "#3e535a"]),
  // Solarized (Ethan Schoonover), base03 background
  "solarized-dark": theme("Solarized Dark", true, "#002b36", "#b1c0bf", "#899a9c", "#5e747b", "#268bd2", "#859900",
    ["#073642", "#fa5149", "#859900", "#b58900", "#3194db", "#ef5299", "#2aa198", "#eee8d5"],
    ["#5e747b", "#fa5149", "#97ac29", "#c89c29", "#3d9ee6", "#ef539a", "#43b4ab", "#b1c0bf"]),
  // Everforest (sainnhe), light medium
  "everforest-light": theme("Everforest Light", false, "#fdf6e3", "#45535a", "#667565", "#889182", "#839700", "#677800",
    ["#5c6a72", "#d43034", "#677800", "#9f6300", "#1378a7", "#b74495", "#008159", "#e6e2cc"],
    ["#667565", "#d43235", "#667800", "#9f6400", "#1378a8", "#b74596", "#008158", "#45535a"]),
  // Everforest (sainnhe), dark medium
  "everforest-dark": theme("Everforest Dark", true, "#2d353b", "#dccfb3", "#9da9a0", "#7a8478", "#a7c080", "#a7c080",
    ["#475258", "#e67e80", "#a7c080", "#dbbc7f", "#7fbbb3", "#d699b6", "#83c092", "#d3c6aa"],
    ["#7a8478", "#fb9192", "#bad393", "#efcf92", "#92cec6", "#eaacc9", "#96d3a5", "#dccfb3"]),
  // Kanagawa (rebelot), Lotus
  "kanagawa-lotus": theme("Kanagawa Lotus", false, "#f2ecbc", "#4b4b5b", "#43436c", "#87867d", "#4d699b", "#587137",
    ["#1f1f28", "#bf374c", "#587137", "#716b39", "#4d699b", "#a34d6b", "#4e706a", "#c7d7e0"],
    ["#43436c", "#b32b42", "#587137", "#66602e", "#3d5888", "#9f4968", "#486a64", "#4b4b5b"]),
  // Kanagawa (rebelot), Wave
  "kanagawa-wave": theme("Kanagawa Wave", true, "#1f1f28", "#dcd7ba", "#c8c093", "#727169", "#7e9cd8", "#98bb6c",
    ["#16161d", "#e46876", "#98bb6c", "#e6c384", "#7e9cd8", "#957fb8", "#7aa89f", "#c8c093"],
    ["#727169", "#fb3d36", "#98bb6c", "#e6c384", "#7fb4ca", "#938aa9", "#7aa89f", "#dcd7ba"]),
  // Ayu (ayu-theme), light
  "ayu-light": theme("Ayu Light", false, "#fafafa", "#50555a", "#707378", "#8a9199", "#c48303", "#567f00",
    ["#000000", "#d13c3f", "#567f00", "#a46400", "#0078bd", "#8a61b1", "#008361", "#c7c7c7"],
    ["#707378", "#d13b3f", "#567f00", "#a46500", "#0078be", "#8a61b1", "#008360", "#50555a"]),
  // Ayu (ayu-theme), dark
  "ayu-dark": theme("Ayu Dark", true, "#0b0e14", "#bfbdb6", "#8a9199", "#5b606b", "#e6b450", "#aad94c",
    ["#11151c", "#d95757", "#aad94c", "#e6b450", "#59c2ff", "#d2a6ff", "#95e6cb", "#c7c7c7"],
    ["#5b606b", "#ee6a69", "#bded62", "#fac764", "#6ed6ff", "#e6b9ff", "#a9fadf", "#bfbdb6"]),
  // GitHub Primer, light
  "github-light": theme("GitHub Light", false, "#ffffff", "#1f2328", "#59636e", "#818b98", "#0969da", "#1a7f37",
    ["#24292f", "#cf222e", "#1a7f37", "#9a6700", "#0969da", "#8250df", "#1b7c83", "#6e7781"],
    ["#59636e", "#b9001b", "#006d25", "#875600", "#0056c6", "#713cca", "#006a71", "#1f2328"]),
  // GitHub Primer, dark
  "github-dark": theme("GitHub Dark", true, "#0d1117", "#e6edf3", "#9198a1", "#6e7681", "#4493f8", "#3fb950",
    ["#484f58", "#ff7b72", "#3fb950", "#d29922", "#58a6ff", "#bc8cff", "#39c5cf", "#b1bac4"],
    ["#6e7681", "#ffa198", "#56d364", "#e3b341", "#79c0ff", "#d2a8ff", "#56d4dd", "#e6edf3"]),
  // Flexoki (Steph Ango), light (the 600 steps on paper)
  "flexoki-light": theme("Flexoki Light", false, "#fffcf0", "#100f0f", "#6f6e69", "#94928a", "#205ea6", "#637d03",
    ["#100f0f", "#af3029", "#637d03", "#966d00", "#205ea6", "#a02f6f", "#22817a", "#6f6e69"],
    ["#6f6e69", "#9a1916", "#556e00", "#966d00", "#094c93", "#8c195e", "#00716a", "#100f0f"]),
  // Flexoki (Steph Ango), dark (the 400 steps on black)
  "flexoki-dark": theme("Flexoki Dark", true, "#100f0f", "#cecdc3", "#878580", "#61605d", "#4385be", "#879a39",
    ["#1c1b1a", "#d34f42", "#879a39", "#d0a215", "#4385be", "#ce5d97", "#3aa99f", "#cecdc3"],
    ["#61605d", "#e66053", "#99ad4d", "#e4b536", "#5597d2", "#e370aa", "#50bcb2", "#cecdc3"]),
  // Gruvbox (morhetz), light medium
  "gruvbox-light": theme("Gruvbox Light", false, "#fbf1c7", "#3c3836", "#665c54", "#7c6f64", "#b57614", "#757005",
    ["#fbf1c7", "#9d0006", "#757005", "#9c5f00", "#076678", "#8f3f71", "#407956", "#7c6f64"],
    ["#665c54", "#cc241d", "#737100", "#9b6000", "#36777a", "#a25478", "#467948", "#3c3836"]),
  // Tokyo Night (folke/tokyonight.nvim), day
  "tokyo-day": theme("Tokyo Night Day", false, "#e1e2e7", "#1b3f9b", "#51619e", "#777ea7", "#2e7de9", "#506d31",
    ["#b4b5b9", "#c90043", "#506d31", "#7e5f31", "#0961cb", "#833bd8", "#006c92", "#6172b0"],
    ["#51619e", "#c90043", "#476428", "#7a5b2d", "#0861cb", "#823ad8", "#005f85", "#1b3f9b"]),
  // Catppuccin, Frappé
  frappe: theme("Catppuccin Frappé", true, "#303446", "#c6d0f5", "#a5adce", "#777d98", "#ca9ee6", "#a6d189",
    ["#51576d", "#e78284", "#a6d189", "#e5c890", "#8caaee", "#f4b8e4", "#81c8be", "#b5bfe2"],
    ["#777d98", "#fc9596", "#b9e59c", "#f9dca3", "#9ebdff", "#ffcbf8", "#94dcd1", "#c6d0f5"]),
  // Catppuccin, Macchiato
  macchiato: theme("Catppuccin Macchiato", true, "#24273a", "#cad3f5", "#a5adcb", "#6e738d", "#c6a0f6", "#a6da95",
    ["#494d64", "#ed8796", "#a6da95", "#eed49f", "#8aadf4", "#f5bde6", "#8bd5ca", "#b8c0e0"],
    ["#6e738d", "#ff9aa9", "#b9eea8", "#ffe8b2", "#9cc0ff", "#ffd0fa", "#9ee9dd", "#cad3f5"]),
  // Night Owl (Sarah Drasner), Light Owl
  "owl-light": theme("Light Owl", false, "#fbfbfb", "#403f53", "#5d5f77", "#8a91a3", "#4876d6", "#00845e",
    ["#403f53", "#d73535", "#00845e", "#996b00", "#4270cf", "#994cc3", "#008186", "#d9d9d9"],
    ["#5d5f77", "#c82429", "#007f59", "#996b00", "#3764c2", "#8739af", "#008186", "#403f53"]),
  // Night Owl (Sarah Drasner), Night Owl
  "owl-night": theme("Night Owl", true, "#011627", "#d6deeb", "#a1b0c3", "#5f7e97", "#82aaff", "#addb67",
    ["#011627", "#ef5350", "#addb67", "#ecc48d", "#82aaff", "#c792ea", "#7fdbca", "#ffffff"],
    ["#5f7e97", "#ff6762", "#c0ef7b", "#ffd8a0", "#94bdff", "#dba5fe", "#93efdd", "#d6deeb"]),
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

/** Builds the Ghostty ANSI palette; translucent mode reveals the still backdrop. */
export function terminalTheme(active: Theme, translucent: boolean) {
  const [black, red, green, yellow, blue, magenta, cyan, white] = active.ansi;
  const [brightBlack, brightRed, brightGreen, brightYellow, brightBlue, brightMagenta, brightCyan, brightWhite] = active.bright;
  return {
    background: translucent ? "rgba(0,0,0,0)" : active.bg,
    foreground: active.fg,
    cursor: active.accent,
    selectionBackground: `${active.accent}55`,
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
