/**
 * The font registry: every font the interface and the terminal can use, and the text weight
 * each one reads best at (D87, D175).
 *
 * One font changes the whole product: the UI, the sign-in card and the terminal take the
 * same family. A family is not equally heavy at the same numeric weight, so each entry
 * declares its own weights instead of the CSS hard-coding 450 for everybody:
 *
 *  - `bodyWeight`: the UI body role. Every other UI role derives from it (see `uiWeights`),
 *    so a heavier family keeps the same hierarchy: secondary < body < label < title.
 *  - `terminalWeight`: the terminal's regular text.
 *  - `boldWeight`: the terminal's bold text; it stays clearly heavier than regular.
 *
 * The values were chosen by measuring ink coverage per glyph at 14 px, DPR 1 and 2, against
 * the Geist Mono 450 text the owner approved, then checking 2x crops (see the weight commit).
 *
 * Loading: the default family is declared in style.css and preloaded, because it paints the
 * sign-in card. Every other family is fetched the first time it is previewed or picked, by
 * `loadFont`, and never sits on the critical path. Nerd Font symbols are not part of any
 * family: the "Nerd Symbols" face in style.css sits second in every stack, so prompt icons
 * draw whichever font is chosen.
 */

/**
 * Unicode ranges every subset contains. MUST match fonts/subset.py and the `unicode-range`
 * descriptors in apps/tracer/style.css: a face that claims a range it does not hold makes the
 * browser fall back to another font in the middle of a line.
 */
export const LATIN_RANGE =
  "U+0020-007E,U+00A0-00FF,U+0131,U+0152-0153,U+0160-0161,U+0178,U+017D-017E,U+02C6,U+02DC,U+2000-206F,U+20AC,U+2122,U+2190-21FF,U+2212,U+2215,U+221A,U+221E,U+2248,U+2260-2265,U+2303,U+2318,U+2325-2326,U+232B,U+238B,U+23CE,U+2500-25FF,U+2713-2717,U+2800-28FF";

/** One woff2 file and the style and weight range it answers to. */
export interface FontFaceSource {
  /** Path under the `fonts/` directory of the build. */
  file: string;
  style: "normal" | "italic";
  /** CSS weight descriptor: "400 700" for a variable face, "400" for a static one. */
  weight: string;
}

/**
 * One selectable font: its id, label, CSS family, files (`faces`) and the weights it reads best at. See the module
 * comment for what each weight field means. `id` is what is saved in the browser as the user's choice.
 */
export interface MonoFont {
  id: string;
  /** Name shown in the palette. */
  label: string;
  /** The family name its faces answer to in CSS and in the terminal canvas. */
  family: string;
  /** Short note on the right of the palette row. */
  hint: string;
  bodyWeight: number;
  terminalWeight: number;
  boldWeight: number;
  /** Lightest and heaviest weight the faces provide; a role weight is clamped into it. */
  range: readonly [number, number];
  /** Set when the family has only these weights (static faces): roles snap to the nearest. */
  discrete?: readonly number[];
  /** True when style.css already declares the faces (the default family). */
  declared?: boolean;
  /** Fallback face scaled to this family's metrics, to keep layout still while it loads. */
  metricFallback?: string;
  faces: readonly FontFaceSource[];
  /**
   * Set when the terminal must put every glyph on its cell itself. The renderer normally draws a
   * run of text with one call and stretches the font's advance onto the cell with letter
   * spacing, which assumes the browser advances every glyph by the same amount. Chrome without
   * subpixel glyph positioning (Linux at DPR 1) rounds each glyph's advance on its own, and for
   * a family whose advance is not near a whole pixel it rounds some glyphs up and others down:
   * Monaspace Neon (0.62 em) drew lines up to 9% wider than their cells. One glyph per call is
   * exact on every platform, at the cost of more draw calls (measured in the metrics spec).
   */
  placeGlyphs?: boolean;
}

/** The two faces (upright and italic) of a variable-weight family whose files live in `fonts/<id>/`. */
const variable = (id: string): FontFaceSource[] => [
  { file: `${id}/roman.latin.woff2`, style: "normal", weight: "400 700" },
  { file: `${id}/italic.latin.woff2`, style: "italic", weight: "400 700" },
];

/** Static faces: a family that ships only a regular and a bold weight. */
const staticPair = (id: string): FontFaceSource[] => [
  { file: `${id}/roman-400.latin.woff2`, style: "normal", weight: "400" },
  { file: `${id}/roman-700.latin.woff2`, style: "normal", weight: "700" },
  { file: `${id}/italic-400.latin.woff2`, style: "italic", weight: "400" },
  { file: `${id}/italic-700.latin.woff2`, style: "italic", weight: "700" },
];

/** The faces of a static family from the styles it ships; a style it lacks is drawn by the browser from the nearest one (0xProto has no bold italic). */
const staticFaces = (id: string, styles: ReadonlyArray<"roman-400" | "roman-700" | "italic-400" | "italic-700">): FontFaceSource[] =>
  styles.map((style) => ({ file: `${id}/${style}.latin.woff2`, style: style.startsWith("italic") ? "italic" : "normal", weight: style.endsWith("700") ? "700" : "400" }));

/** The upright face only: a family with no italic design, whose italic the browser slants from the upright. */
const uprightOnly = (id: string): FontFaceSource[] => [{ file: `${id}/roman.latin.woff2`, style: "normal", weight: "400 700" }];

/**
 * The curated fonts (D87), default first, then in the order the palette lists them.
 *
 * Weights come from ink measurements: ink per glyph at 14 px (canvas text, mean of DPR 1 and
 * 2), against Geist Mono at 450, the text the owner approved (21.2). Each family takes the
 * weight whose ink is closest, nudged up one step where hairlines read lighter than coverage
 * says (Maple Mono) and held at 450 where a heavier regular would leave bold less than a
 * clear step above it (JetBrains Mono, 500 would put 700 only 13% heavier). Source Code Pro is
 * capped at 550 so label and title weights keep room below its heaviest face.
 */
export const FONTS: readonly MonoFont[] = [
  { id: "maple-mono-nf", label: "Maple Mono NF", family: "Maple Mono NF", hint: "default",
    bodyWeight: 500, terminalWeight: 500, boldWeight: 700, range: [400, 700], declared: true,
    metricFallback: "Maple Mono NF Fallback", faces: variable("maple-mono-nf") },
  { id: "geist-mono", label: "Geist Mono", family: "Geist Mono", hint: "",
    bodyWeight: 450, terminalWeight: 450, boldWeight: 700, range: [400, 700], faces: variable("geist-mono") },
  { id: "jetbrains-mono", label: "JetBrains Mono", family: "JetBrains Mono", hint: "",
    bodyWeight: 450, terminalWeight: 450, boldWeight: 700, range: [400, 700], faces: variable("jetbrains-mono") },
  { id: "commit-mono", label: "Commit Mono", family: "Commit Mono", hint: "",
    bodyWeight: 400, terminalWeight: 400, boldWeight: 700, range: [400, 700], discrete: [400, 700], faces: staticPair("commit-mono") },
  // Terminal weight 500, not 450: at 450 Chrome measures the advance as 8 px against a true 8.68, so
  // the cell would be narrower than the glyphs; at 500 it measures 9.
  { id: "monaspace-neon", label: "Monaspace Neon", family: "Monaspace Neon", hint: "",
    bodyWeight: 450, terminalWeight: 500, boldWeight: 700, range: [400, 700], placeGlyphs: true, faces: variable("monaspace-neon") },
  { id: "ibm-plex-mono", label: "IBM Plex Mono", family: "IBM Plex Mono", hint: "",
    bodyWeight: 450, terminalWeight: 450, boldWeight: 700, range: [400, 700], faces: variable("ibm-plex-mono") },
  { id: "cascadia-code", label: "Cascadia Code", family: "Cascadia Code", hint: "",
    bodyWeight: 400, terminalWeight: 400, boldWeight: 700, range: [400, 700], faces: variable("cascadia-code") },
  { id: "fira-code", label: "Fira Code", family: "Fira Code", hint: "",
    bodyWeight: 450, terminalWeight: 450, boldWeight: 700, range: [400, 700],
    // Upstream has no italic design; the browser slants the upright face.
    faces: [{ file: "fira-code/roman.latin.woff2", style: "normal", weight: "400 700" }] },
  { id: "source-code-pro", label: "Source Code Pro", family: "Source Code Pro", hint: "",
    bodyWeight: 550, terminalWeight: 550, boldWeight: 700, range: [400, 700], faces: variable("source-code-pro") },
  // D329 (#323): fourteen more families, all fetched only when previewed or picked (never on the first load). Their weights are the common
  // defaults, not ink measurements: variable families at 450 like most of the list, static families at their regular (400) with bold at 700.
  { id: "iosevka", label: "Iosevka", family: "Iosevka", hint: "",
    bodyWeight: 400, terminalWeight: 400, boldWeight: 700, range: [400, 700], discrete: [400, 700], faces: staticPair("iosevka") },
  { id: "victor-mono", label: "Victor Mono", family: "Victor Mono", hint: "",
    bodyWeight: 400, terminalWeight: 400, boldWeight: 700, range: [400, 700], discrete: [400, 700], faces: staticPair("victor-mono") },
  { id: "recursive-mono", label: "Recursive Mono", family: "Recursive Mono", hint: "",
    bodyWeight: 400, terminalWeight: 400, boldWeight: 700, range: [400, 700], faces: variable("recursive-mono") },
  { id: "martian-mono", label: "Martian Mono", family: "Martian Mono", hint: "wide",
    bodyWeight: 400, terminalWeight: 400, boldWeight: 700, range: [400, 700], faces: uprightOnly("martian-mono") },
  { id: "intel-one-mono", label: "Intel One Mono", family: "Intel One Mono", hint: "",
    bodyWeight: 400, terminalWeight: 400, boldWeight: 700, range: [400, 700], discrete: [400, 700], faces: staticPair("intel-one-mono") },
  { id: "fantasque-sans-mono", label: "Fantasque Sans Mono", family: "Fantasque Sans Mono", hint: "",
    bodyWeight: 400, terminalWeight: 400, boldWeight: 700, range: [400, 700], discrete: [400, 700], faces: staticPair("fantasque-sans-mono") },
  { id: "hack", label: "Hack", family: "Hack", hint: "",
    bodyWeight: 400, terminalWeight: 400, boldWeight: 700, range: [400, 700], discrete: [400, 700], faces: staticPair("hack") },
  { id: "inconsolata", label: "Inconsolata", family: "Inconsolata", hint: "",
    bodyWeight: 500, terminalWeight: 500, boldWeight: 700, range: [400, 700], faces: uprightOnly("inconsolata") },
  { id: "0xproto", label: "0xProto", family: "0xProto", hint: "",
    bodyWeight: 400, terminalWeight: 400, boldWeight: 700, range: [400, 700], discrete: [400, 700], faces: staticFaces("0xproto", ["roman-400", "roman-700", "italic-400"]) },
  { id: "lilex", label: "Lilex", family: "Lilex", hint: "",
    bodyWeight: 450, terminalWeight: 450, boldWeight: 700, range: [400, 700], faces: variable("lilex") },
  // The other four Monaspace faces share Neon's metrics, so they take its terminal weight and per-glyph placement (see `placeGlyphs`).
  { id: "monaspace-argon", label: "Monaspace Argon", family: "Monaspace Argon", hint: "",
    bodyWeight: 450, terminalWeight: 500, boldWeight: 700, range: [400, 700], placeGlyphs: true, faces: variable("monaspace-argon") },
  { id: "monaspace-xenon", label: "Monaspace Xenon", family: "Monaspace Xenon", hint: "",
    bodyWeight: 450, terminalWeight: 500, boldWeight: 700, range: [400, 700], placeGlyphs: true, faces: variable("monaspace-xenon") },
  { id: "monaspace-radon", label: "Monaspace Radon", family: "Monaspace Radon", hint: "",
    bodyWeight: 450, terminalWeight: 500, boldWeight: 700, range: [400, 700], placeGlyphs: true, faces: variable("monaspace-radon") },
  { id: "monaspace-krypton", label: "Monaspace Krypton", family: "Monaspace Krypton", hint: "",
    bodyWeight: 450, terminalWeight: 500, boldWeight: 700, range: [400, 700], placeGlyphs: true, faces: variable("monaspace-krypton") },
];

/** The font used when nothing is saved. It is the one preloaded for the sign-in card. */
export const DEFAULT_FONT_ID = "maple-mono-nf";

/** The registered font with this `id`, or `undefined` for an unknown or missing id. */
export function fontById(id: string | null | undefined): MonoFont | undefined {
  return FONTS.find((font) => font.id === id);
}

/** The four UI text weights derived from a font by {@link uiWeights}. */
export interface UiWeights { secondary: number; body: number; label: number; title: number }

/**
 * The four UI text roles from the font's body weight. The offsets are the ones the product
 * already used (400 / 450 / 500 / 600 around a 450 body); a family whose body sits higher
 * keeps the same steps, clamped into the weights its faces provide.
 */
export function uiWeights(font: MonoFont): UiWeights {
  const [low, high] = font.range;
  const place = (weight: number): number => {
    const clamped = Math.min(high, Math.max(low, weight));
    if (!font.discrete) return clamped;
    // Equal distance goes to the heavier face, so a title never collapses onto body text.
    return font.discrete.reduce((best, candidate) =>
      Math.abs(candidate - clamped) < Math.abs(best - clamped) || (Math.abs(candidate - clamped) === Math.abs(best - clamped) && candidate > best) ? candidate : best);
  };
  return {
    secondary: place(font.bodyWeight - 50),
    body: place(font.bodyWeight),
    label: place(font.bodyWeight + 50),
    title: place(font.bodyWeight + 150),
  };
}

/** The CSS font-family list for a font: itself, the Nerd symbols, then a metric stand-in. */
export function fontStack(font: MonoFont): string {
  return [`"${font.family}"`, `"Nerd Symbols"`, ...(font.metricFallback ? [`"${font.metricFallback}"`] : []), "ui-monospace", "monospace"].join(", ");
}

/** Sets the family and the four role weights on one element (the document root). */
export function applyFontVars(font: MonoFont, root: HTMLElement): void {
  const weights = uiWeights(font);
  root.style.setProperty("--font-face", fontStack(font));
  root.style.setProperty("--fw-secondary", String(weights.secondary));
  root.style.setProperty("--fw-body", String(weights.body));
  root.style.setProperty("--fw-label", String(weights.label));
  root.style.setProperty("--fw-title", String(weights.title));
  root.dataset.font = font.id;
}

/** Font loads already started, by font and slant, so a repeat call shares the same promise. */
const registered = new Map<string, Promise<void>>();

/**
 * Fetches the font's upright faces and resolves when they can draw. Calling it again for the
 * same font is free. The faces are registered once with the document (the same set CSS
 * @font-face rules feed), so DOM text and the terminal canvas both see them. Italic faces
 * are separate (`loadItalic`) because most sessions never draw italic text.
 */
export function loadFont(font: MonoFont, italic = false): Promise<void> {
  const key = `${font.id}:${italic ? "italic" : "normal"}`;
  const known = registered.get(key);
  if (known) return known;
  const wanted = font.faces.filter((face) => (face.style === "italic") === italic);
  const task = Promise.all(wanted.map(async (source) => {
    if (font.declared) {
      // CSS declares the face; ask for the heaviest and the lightest role weight.
      const style = source.style === "italic" ? "italic " : "";
      await Promise.all([font.range[0], font.range[1]].map((weight) => document.fonts.load(`${style}${weight} 14px "${font.family}"`)));
      return;
    }
    const face = new FontFace(font.family, `url("${new URL(`fonts/${source.file}`, document.baseURI).href}") format("woff2")`, {
      style: source.style,
      weight: source.weight,
      unicodeRange: LATIN_RANGE,
    });
    document.fonts.add(face);
    await face.load();
  })).then(() => undefined);
  // A failed fetch must not poison later attempts.
  task.catch(() => registered.delete(key));
  registered.set(key, task);
  return task;
}
