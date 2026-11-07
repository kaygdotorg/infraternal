// SPDX-License-Identifier: AGPL-3.0-only
/**
 * Themes (D322, D338, D341, #323): what a theme is and the few rules around it. No DOM here, so the rules can be tested alone.
 *
 * - A theme bundles **tint**, **blur**, **grain**, **font**, **Colour**, **background** and **UI size**. Tint, blur and grain are
 *   percentages and the UI never shows pixels: 0% blur is 0 px and 100% is 24 px.
 * - There are three built-in themes: Solid (100% tint, 0% blur), Tinted (75%, 25%) and Frosted (50%, 50%). The person may change
 *   any of them; **Reset** puts a built-in theme's numbers back and exists only while it differs from them.
 * - **Colour** is a version of a scheme: dark shows dark cards, light shows light ones (D322 round 2, D338).
 * - **Add** makes a new theme as a copy of the selected one (D341). Its name can change; the built-in names cannot.
 * - A theme also holds its **background**: Solid (the scheme's own colour, or another solid), one of the scheme's gradients, or the
 *   person's own (`gradients.ts`).
 * - The default theme for a person who has never chosen is **Tinted**.
 *
 * The store keeps the list in memory and tells its listeners after every change. {@link snapshot} and {@link createThemeStore}'s `saved`
 * argument are how a list leaves and comes back (`persist.ts` writes it to the device and to the account); anything read back is
 * checked by {@link restore}, so a damaged or hand-edited copy can never put a theme out of range.
 */
import { CUSTOM_ID, DEFAULT_CUSTOM, DEFAULT_CUSTOM_SOLID, DEFAULT_GRADIENT, GRADIENT_IDS, MAX_STOPS, MIN_STOPS, SOLID_CUSTOM_ID, SOLID_IDS, type CustomGradient } from "./backgrounds";
import { fontById } from "../../../../../packages/ui/src/fonts";
import { THEMES } from "../../../../../packages/ui/src/themes";
import { MAX_THEMES } from "./limits";

/** Blur at 100%: the scale is linear from 0 px (0%) to this many pixels (D322: "0 px = 0% and 24 px = 100%"). */
export const BLUR_AT_FULL_PX = 24;
/** The blur in pixels for a percentage. */
export const blurPx = (percent: number): number => (percent * BLUR_AT_FULL_PX) / 100;
/** The percentage for a blur in pixels (the reverse of {@link blurPx}). */
export const blurPercent = (px: number): number => Math.round((px * 100) / BLUR_AT_FULL_PX);

/** The smallest and largest UI size a theme may hold, in percent of the standard size (the UI-size setting's own bounds). */
export const UI_SIZE_RANGE = { min: 50, max: 150 } as const;
/** The longest name a person may give a theme. */
export const NAME_MAX = 24;
/** How many themes one account may keep: the canvas document holds the whole list in one edit, which the server bounds (`model/schema.ts`). */
export { MAX_THEMES };

/** One theme: everything the Themes window edits and every card of the strip shows. */
export interface AppearanceTheme {
  id: string;
  name: string;
  /** 0 to 100: how much of the window's own colour covers what is behind it. */
  tint: number;
  /** 0 to 100: 0% is no blur, 100% is 24 px. */
  blur: number;
  /** 0 to 100: how much film grain (noise) lies on the windows. 0% is none (`grain.ts` for the scale). */
  grain: number;
  /** A font id from `packages/ui/src/fonts.ts`. */
  font: string;
  /** A Colour: the version of a scheme (a theme id of `packages/ui/src/themes.ts`), light or dark. The list shows a scheme once with a circle for each version (`colors.ts`). */
  colors: string;
  /** Percent of the standard size (50 to 150). */
  uiSize: number;
  /** "solid" (the scheme's own colour), "solid-<role>" or "solid-custom" (then `customSolid` is the colour), a gradient id of `gradients.ts`, or "custom" (then `custom` is the gradient). */
  background: string;
  /** The person's own solid colour. Kept while another background is chosen, like `custom`. */
  customSolid: string;
  /** The person's own gradient. Kept even while another background is chosen, so choosing "custom" again finds it. */
  custom: CustomGradient;
}

/** The ids of the three built-in themes, in the order the strip lists them. */
export const BUILT_IN_IDS = ["solid", "tinted", "frosted"] as const;
/** The theme a person who has never chosen starts on. */
export const DEFAULT_THEME = "tinted";
/** Solid starts on a solid background; Tinted and Frosted start on a gradient, because tint and blur only show over something. */
const BUILT_IN_NUMBERS: Record<(typeof BUILT_IN_IDS)[number], { name: string; tint: number; blur: number; background: string }> = {
  solid: { name: "Solid", tint: 100, blur: 0, background: "solid" },
  tinted: { name: "Tinted", tint: 75, blur: 25, background: DEFAULT_GRADIENT },
  frosted: { name: "Frosted", tint: 50, blur: 50, background: DEFAULT_GRADIENT },
};

/** What every built-in theme starts with: the Colour, font and UI size the person already has (a new person: the product's own defaults). */
export interface Basics { colors: string; font: string; uiSize: number }

export { CUSTOM_ID };

/** A copy of a custom gradient that shares nothing with the original (stops are an array). */
const copyCustom = (c: CustomGradient): CustomGradient => ({ ...c, stops: [...c.stops] });
/** A copy of a theme that shares nothing with the original. */
const copyTheme = (t: AppearanceTheme): AppearanceTheme => ({ ...t, custom: copyCustom(t.custom) });

/** A built-in theme as it starts: its own numbers, no grain, and the `basics`. */
export function builtIn(id: (typeof BUILT_IN_IDS)[number], basics: Basics): AppearanceTheme {
  return { id, ...BUILT_IN_NUMBERS[id], grain: 0, ...basics, custom: copyCustom(DEFAULT_CUSTOM), customSolid: DEFAULT_CUSTOM_SOLID };
}

/** What is saved: the starting point the built-in themes were made from, every theme as it is now, and which one is selected. */
export interface SavedThemes { v: 1; selected: string; basics: Basics; themes: AppearanceTheme[] }

/** The list of themes and the selected one. Everything the Themes window and the page's look read and change goes through it. */
export interface ThemeStore {
  themes(): readonly AppearanceTheme[];
  selected(): AppearanceTheme;
  selectedId(): string;
  /** Whether a built-in theme differs from its defaults. A theme the person made is never "changed": there is nothing to go back to. */
  changed(id: string): boolean;
  isBuiltIn(id: string): boolean;
  defaults(id: string): AppearanceTheme | undefined;
  select(id: string): void;
  /** Edits the selected theme. A built-in theme's name is fixed, so a `name` in the patch is ignored for it. */
  edit(patch: Partial<Omit<AppearanceTheme, "id">>): void;
  reset(id: string): void;
  /** A new theme, a copy of the selected one, selected. Returns it. At the most themes an account may keep, it adds nothing and returns the selected theme. */
  add(): AppearanceTheme;
  /** Takes a theme the person made out of the list; the built-in themes stay. When the removed theme was selected, Tinted is (a copy does not remember where it came from). */
  remove(id: string): void;
  /** Everything that is saved, as plain data (see {@link SavedThemes}). */
  snapshot(): SavedThemes;
  /** Replaces the list with a saved one (checked by {@link restore}); false when it is unusable and nothing changed. */
  load(saved: unknown): boolean;
  onChange(listener: () => void): () => void;
}

/** Compares every saved field to detect a real theme edit. */
const same = (a: AppearanceTheme, b: AppearanceTheme): boolean => a.tint === b.tint && a.blur === b.blur && a.grain === b.grain && a.font === b.font && a.colors === b.colors && a.uiSize === b.uiSize && a.background === b.background && a.custom.angle === b.custom.angle && a.custom.stops.join() === b.custom.stops.join() && a.customSolid === b.customSolid;

/** Rounds a finite value into its supported range or uses the supplied fallback. */
const clamp = (v: unknown, lo: number, hi: number, fallback: number): number => (typeof v === "number" && Number.isFinite(v) ? Math.max(lo, Math.min(hi, Math.round(v))) : fallback);
/** Accepts one six-digit CSS hex colour. */
const isHex = (v: unknown): v is string => typeof v === "string" && /^#[0-9a-fA-F]{6}$/.test(v);
/** Checks whether a saved background id belongs to a built-in option. */
const isBackground = (v: unknown): v is string => typeof v === "string" && (v === CUSTOM_ID || v === SOLID_CUSTOM_ID || SOLID_IDS.includes(v) || GRADIENT_IDS.includes(v));

/**
 * Reads a saved list back, field by field, so a damaged or edited copy can never put a theme out of range: a number outside its range is
 * moved into it, an unknown font, Colour or background falls back to the theme's base, and a built-in theme that is missing comes back
 * with its defaults. Returns undefined only when there is nothing usable (not an object, or no version 1).
 */
export function restore(saved: unknown): SavedThemes | undefined {
  if (typeof saved !== "object" || saved === null) return undefined;
  const raw = saved as Partial<Record<keyof SavedThemes, unknown>>;
  if (raw.v !== 1 || typeof raw.basics !== "object" || raw.basics === null || !Array.isArray(raw.themes)) return undefined;
  const b = raw.basics as Partial<Basics>;
  const basics: Basics = {
    colors: typeof b.colors === "string" && b.colors in THEMES ? b.colors : "mocha",
    font: fontById(typeof b.font === "string" ? b.font : null) ? (b.font as string) : "maple-mono-nf",
    uiSize: clamp(b.uiSize, UI_SIZE_RANGE.min, UI_SIZE_RANGE.max, 100),
  };
  const themes: AppearanceTheme[] = [];
  for (const item of raw.themes.slice(0, MAX_THEMES) as Array<Partial<Record<keyof AppearanceTheme, unknown>>>) {
    if (typeof item !== "object" || item === null || typeof item.id !== "string" || !item.id || themes.some((t) => t.id === item.id)) continue;
    const builtId = (BUILT_IN_IDS as readonly string[]).includes(item.id) ? (item.id as (typeof BUILT_IN_IDS)[number]) : undefined;
    const base = builtId ? builtIn(builtId, basics) : { ...builtIn("tinted", basics), id: item.id, name: "Theme" };
    const custom = item.custom as Partial<CustomGradient> | undefined;
    const stops = Array.isArray(custom?.stops) ? custom.stops.filter(isHex).slice(0, MAX_STOPS) : [];
    themes.push({
      id: item.id,
      name: builtId ? base.name : typeof item.name === "string" && item.name.trim() ? item.name.trim().slice(0, NAME_MAX) : base.name,
      tint: clamp(item.tint, 0, 100, base.tint),
      blur: clamp(item.blur, 0, 100, base.blur),
      grain: clamp(item.grain, 0, 100, base.grain),
      font: typeof item.font === "string" && fontById(item.font) ? item.font : base.font,
      colors: typeof item.colors === "string" && item.colors in THEMES ? item.colors : base.colors,
      uiSize: clamp(item.uiSize, UI_SIZE_RANGE.min, UI_SIZE_RANGE.max, base.uiSize),
      background: isBackground(item.background) ? item.background : base.background,
      customSolid: isHex(item.customSolid) ? item.customSolid : base.customSolid,
      custom: { angle: clamp(custom?.angle, 0, 360, base.custom.angle), stops: stops.length >= MIN_STOPS ? stops : [...base.custom.stops] },
    });
  }
  for (const id of BUILT_IN_IDS) if (!themes.some((t) => t.id === id)) themes.push(builtIn(id, basics));
  // The built-in themes come first and in their own order, then the person's own in the order they were made.
  themes.sort((x, y) => { const i = BUILT_IN_IDS.indexOf(x.id as never), j = BUILT_IN_IDS.indexOf(y.id as never); return (i < 0 ? 99 : i) - (j < 0 ? 99 : j); });
  const selected = typeof raw.selected === "string" && themes.some((t) => t.id === raw.selected) ? raw.selected : DEFAULT_THEME;
  return { v: 1, selected, basics, themes };
}

/** The number to put after "Theme" in the name of the next theme made, and in its id: one more than any in use. */
function nextSerial(list: readonly AppearanceTheme[]): number {
  let max = 0;
  for (const t of list) { const m = /^custom-(\d+)$/.exec(t.id); if (m) max = Math.max(max, Number(m[1])); }
  return max + 1;
}

/** Makes the store. `basics` is what the built-in themes start from; `saved` (if usable, see {@link restore}) is the list the person had. */
export function createThemeStore(basics: Basics, saved?: unknown, start: string = DEFAULT_THEME): ThemeStore {
  const restored = saved === undefined ? undefined : restore(saved);
  // The saved starting point wins over today's: a built-in theme's "changed" is measured against what it started as, not against whatever the product shows now.
  const base: Basics = restored ? restored.basics : basics;
  const defaults = new Map(BUILT_IN_IDS.map((id) => [id, builtIn(id, base)] as const));
  let list: AppearanceTheme[] = restored ? restored.themes : [...defaults.values()].map(copyTheme);
  let current = list.some((t) => t.id === (restored?.selected ?? start)) ? (restored?.selected ?? start) : DEFAULT_THEME;
  const listeners = new Set<() => void>();
  const emit = (): void => { for (const listener of [...listeners]) listener(); };
  const find = (id: string): AppearanceTheme | undefined => list.find((t) => t.id === id);
  const store: ThemeStore = {
    themes: () => list,
    selected: () => find(current)!,
    selectedId: () => current,
    isBuiltIn: (id) => defaults.has(id as (typeof BUILT_IN_IDS)[number]),
    defaults: (id) => defaults.get(id as (typeof BUILT_IN_IDS)[number]),
    changed(id) {
      const was = defaults.get(id as (typeof BUILT_IN_IDS)[number]), now = find(id);
      return Boolean(was && now && !same(was, now));
    },
    select(id) {
      if (!find(id) || id === current) return;
      current = id;
      emit();
    },
    edit(patch) {
      const theme = find(current)!;
      const { name, ...numbers } = patch;
      Object.assign(theme, numbers);
      if (name !== undefined && !store.isBuiltIn(current)) theme.name = name.slice(0, NAME_MAX);
      emit();
    },
    reset(id) {
      const was = defaults.get(id as (typeof BUILT_IN_IDS)[number]);
      if (!was) return;
      list = list.map((t) => (t.id === id ? copyTheme(was) : t));
      emit();
    },
    add() {
      // The account keeps at most MAX_THEMES (the document holds the list in one edit): at the limit nothing is added and the selected theme stays.
      if (list.length >= MAX_THEMES) return find(current)!;
      const serial = nextSerial(list);
      const source = find(current)!;
      const made: AppearanceTheme = { ...copyTheme(source), id: `custom-${serial}`, name: `Theme ${list.length + 1}` };
      list = [...list, made];
      current = made.id;
      emit();
      return made;
    },
    remove(id) {
      if (store.isBuiltIn(id) || !find(id)) return;
      list = list.filter((t) => t.id !== id);
      if (current === id) current = DEFAULT_THEME;
      emit();
    },
    snapshot: () => ({ v: 1, selected: current, basics: { ...base }, themes: list.map(copyTheme) }),
    load(next) {
      const r = restore(next);
      if (!r) return false;
      list = r.themes;
      current = r.selected;
      emit();
      return true;
    },
    onChange(listener) { listeners.add(listener); return () => { listeners.delete(listener); }; },
  };
  return store;
}
