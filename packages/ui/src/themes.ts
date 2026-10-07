/** Curated UI and terminal palettes; one theme keeps both color systems coherent. */

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
  overlaySolid: string;
  overlayLine: string;
  shadow: string;
  largeShadow: string;
  surface: string;
}

/** Keeps dark glass close to its palette and computes the same alpha composite used by the contrast audit. */
export function overlayMaterial(active: Theme): OverlayMaterial {
  const tinted = mix(active.bg, "#ffffff", active.dark ? 0.06 : 0.6);
  const opacity = active.dark ? 0.68 : 0.66;
  const channels = (hex: string) => [1, 3, 5].map((index) => Number.parseInt(hex.slice(index, index + 2), 16));
  const rgb = (hex: string) => channels(hex).join(" ");
  const tint = channels(tinted);
  const background = channels(active.bg);
  const surface = `#${tint.map((channel, index) => Math.round(channel * opacity + background[index]! * (1 - opacity)).toString(16).padStart(2, "0")).join("")}`;

  return {
    overlay: `rgb(${rgb(tinted)} / ${opacity})`,
    overlaySolid: mix(active.bg, "#ffffff", active.dark ? 0.07 : 0.7),
    overlayLine: `rgb(${rgb(active.fg)} / 0.09)`,
    shadow: active.dark
      ? "0 1px 1px rgb(0 0 0 / 0.3), 0 12px 32px -8px rgb(0 0 0 / 0.6)"
      : "0 1px 1px rgb(0 0 0 / 0.04), 0 8px 24px -6px rgb(0 0 0 / 0.12)",
    largeShadow: active.dark
      ? "0 2px 3px rgb(0 0 0 / 0.34), 0 24px 56px -10px rgb(0 0 0 / 0.72)"
      : "0 2px 4px rgb(0 0 0 / 0.08), 0 20px 48px -8px rgb(0 0 0 / 0.24)",
    surface,
  };
}

/** Applies UI tokens and mesh source hues; derived surfaces stay coherent with the theme. */
export function applyTheme(active: Theme, root: HTMLElement): void {
  const style = root.style;
  const rgb = (hex: string) => [1, 3, 5].map((index) => parseInt(hex.slice(index, index + 2), 16)).join(" ");
  const overlay = overlayMaterial(active);
  style.setProperty("--bg", active.bg);
  style.setProperty("--fg", active.fg);
  style.setProperty("--fg-2", active.fg2);
  style.setProperty("--fg-3", active.fg3);
  style.setProperty("--accent", active.accent);
  style.setProperty("--accent-soft", `rgb(${rgb(active.accent)} / 0.16)`);
  style.setProperty("--accent-fg", active.dark ? active.bg : "#ffffff");
  style.setProperty("--ok", active.ok);
  style.setProperty("--danger", active.ansi[1]);
  style.setProperty("--overlay", overlay.overlay);
  style.setProperty("--overlay-solid", overlay.overlaySolid);
  style.setProperty("--overlay-line", overlay.overlayLine);
  style.setProperty("--shadow", overlay.shadow);
  style.setProperty("--overlay-shadow-large", overlay.largeShadow);
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
