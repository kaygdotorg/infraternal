// SPDX-License-Identifier: AGPL-3.0-only
/**
 * Figures in the user docs (#302): a screenshot of the real product, with a caption, and optionally a short clip of a flow.
 *
 * Writing one. In `docs/user/*.md`, an image whose address is `figure:<name>` standing alone in its paragraph:
 *
 *     ![Alt text for a screen reader](figure:startup-question "The caption, shown under the picture.")
 *     ![Adding a machine, step by step.](figure:add-machine+clip "Adding a machine takes a minute.")
 *
 * The alt text and the caption are both required: a figure a screen reader cannot describe, or a reader cannot place, fails the
 * build. `+clip` says the figure also has a clip; the still is then its poster.
 *
 * Where the pictures come from. They are captured from a production build of the app by `bun run docs:figures`
 * (figures/capture.ts), never drawn by hand, so they follow the UI whenever the command is run again. The capture writes
 * `docs/user/figures/<name>.<size>.<scheme>.webp` for each size (`desktop` at 2x, `phone` at 3x) and scheme (`ink`, `paper`),
 * `<name>.<size>.<scheme>.webm` for a clip, and `manifest.json` with each figure's size in CSS pixels. That folder is git-ignored:
 * where the media of the docs lives is not decided, so no picture is in the repository.
 *
 * Without the pictures a page still builds. A figure whose pictures are not there (no manifest entry, or a file missing) is shown as
 * its caption under a "Figure pending" placeholder, so the page reads in full and the place of the picture is kept. With them, this
 * file reads the manifest, so a picture is written with its width and height (no layout shift).
 *
 * Markup. A still is a `<picture>` that picks the size by window width and the scheme by the reader's setting, with the desktop
 * paper picture as the plain `<img>`. It is lazy and decodes off the main thread. A clip is not in the markup as a video: the figure
 * carries `data-clip` (an address template) and doc-enhance.ts starts a muted, looping video over the still once the figure is on
 * screen (and pauses it when it leaves), and not at all under reduced motion or a data-saving connection. Inside a canvas window,
 * where the page's width is the window's and the scheme is the app theme's, not the browser's, the same script also points the
 * picture at the matching size and scheme. Without the script the still is all there is, and it is enough.
 */
import { existsSync } from "node:fs";
import { resolve } from "node:path";

/** The two sizes captured for each figure: a wide screen and a phone. */
export const FIGURE_SIZES = ["desktop", "phone"] as const;
/** The two colour schemes captured: dark ("ink") and light ("paper"). */
export const FIGURE_SCHEMES = ["ink", "paper"] as const;
export type FigureSize = (typeof FIGURE_SIZES)[number];
export type FigureScheme = (typeof FIGURE_SCHEMES)[number];

/** The size of one captured picture in CSS pixels (its file is this wide times the capture's scale). */
export interface FigureBox { width: number; height: number }
/** What the capture recorded for one figure. */
export interface FigureEntry { desktop: FigureBox; phone: FigureBox; clip?: boolean }
/** What `manifest.json` holds: the entry of every captured figure, by figure name. */
export type FigureManifest = Record<string, FigureEntry>;

/** Page width (rem) below which the phone picture is used. */
export const PHONE_BREAKPOINT = "36rem";
/** Where the figures are served, under the docs tree. */
export const FIGURES_URL = "/docs/figures";

/** The file name of one picture, for example `startup-question.phone.ink.webp`. */
export const figureFile = (name: string, size: FigureSize, scheme: FigureScheme, extension: "webp" | "webm"): string => `${name}.${size}.${scheme}.${extension}`;

/** What {@link figures} needs: the `manifest`, the optional `directory` of the pictures, and the `page` name used in error messages. */
export interface FigureOptions {
  manifest: FigureManifest;
  /** The folder the pictures are in, checked for each file a figure uses; a figure with a file missing is pending. */
  directory?: string;
  page?: string;
}

/** What a page uses: the files to copy next to it. */
export interface FiguresResult { html: string; files: string[] }

/**
 * Replaces each paragraph that holds one `figure:` image with the figure's markup. Returns the files the page uses, so the build
 * copies those and no others.
 */
export function figures(html: string, options: FigureOptions): FiguresResult {
  const page = options.page ?? "this page";
  const files: string[] = [];
  const out = html.replace(/<p><img src="figure:([a-z0-9-]+)(\+clip)?"([^>]*?)\s*\/?><\/p>/g, (_all, name: string, clip: string | undefined, attributes: string) => {
    const alt = /\salt="([^"]*)"/.exec(attributes)?.[1];
    const caption = /\stitle="([^"]*)"/.exec(attributes)?.[1];
    if (!alt?.trim()) throw new Error(`docs page "${page}": figure "${name}" needs alt text for a screen reader (the text in the square brackets)`);
    if (!caption?.trim()) throw new Error(`docs page "${page}": figure "${name}" needs a caption (the text in quotes after the address)`);
    const entry = options.manifest[name];
    const wantsClip = Boolean(clip) && Boolean(entry?.clip);
    const needed = entry ? FIGURE_SIZES.flatMap((size) => FIGURE_SCHEMES.flatMap((scheme) => (wantsClip ? (["webp", "webm"] as const) : (["webp"] as const)).map((extension) => figureFile(name, size, scheme, extension)))) : [];
    // Pending: the place of the picture and its caption, until the capture has been run where the docs are built.
    if (!entry || (options.directory && needed.some((file) => !existsSync(resolve(options.directory!, file))))) {
      return `<figure class="figure figure-pending" data-figure="${name}">
<div class="figure-media figure-placeholder" role="img" aria-label="${alt}"><span>Figure pending</span></div>
<figcaption>${caption}</figcaption>
</figure>`;
    }
    files.push(...needed);
    const src = (size: FigureSize, scheme: FigureScheme): string => `${FIGURES_URL}/${figureFile(name, size, scheme, "webp")}`;
    const source = (size: FigureSize, scheme: FigureScheme, media: string): string => `<source media="${media}" srcset="${src(size, scheme)}" width="${entry[size].width}" height="${entry[size].height}">`;
    const phone = `(max-width: ${PHONE_BREAKPOINT})`;
    const dark = "(prefers-color-scheme: dark)";
    const clipAttribute = wantsClip ? ` data-clip="${FIGURES_URL}/${name}.{size}.{scheme}.webm"` : "";
    return `<figure class="figure" data-figure="${name}"${clipAttribute}>
<div class="figure-media"><picture>
${source("phone", "ink", `${phone} and ${dark}`)}
${source("phone", "paper", phone)}
${source("desktop", "ink", dark)}
<img src="${src("desktop", "paper")}" width="${entry.desktop.width}" height="${entry.desktop.height}" alt="${alt}" loading="lazy" decoding="async">
</picture></div>
<figcaption>${caption}</figcaption>
</figure>`;
  });
  return { html: out, files: [...new Set(files)] };
}
