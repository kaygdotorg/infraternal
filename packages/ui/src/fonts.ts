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
}

const variable = (id: string): FontFaceSource[] => [
  { file: `${id}/roman.latin.woff2`, style: "normal", weight: "400 700" },
  { file: `${id}/italic.latin.woff2`, style: "italic", weight: "400 700" },
];

/**
 * Weights, by family. Values come from the ink measurements in the weight commit message:
 * the target is the ink per glyph of Geist Mono at 450 (21.2 px at 14 px), nudged up a
 * step where a family's thin hairlines read lighter than its coverage says.
 */
export const FONTS: readonly MonoFont[] = [
  { id: "maple-mono-nf", label: "Maple Mono NF", family: "Maple Mono NF", hint: "default · cursive italics",
    bodyWeight: 500, terminalWeight: 500, boldWeight: 700, range: [400, 700], declared: true,
    metricFallback: "Maple Mono NF Fallback", faces: variable("maple-mono-nf") },
];

export const DEFAULT_FONT_ID = "maple-mono-nf";

export function fontById(id: string | null | undefined): MonoFont | undefined {
  return FONTS.find((font) => font.id === id);
}

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
