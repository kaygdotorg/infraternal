/**
 * Content-hashed names for the files the page loads on every visit (J1100, #573).
 *
 * `main.js`, the page's style sheets and its fonts used to keep one name for every release, so the server had to send
 * `no-cache` and the browser paid a revalidation round trip for each of them on every warm visit. A file whose name
 * contains a hash of its bytes can never change under that name, so the server may send `immutable` and a warm visit
 * asks for nothing but `index.html`.
 *
 * The name is `<stem>.<10 hex digits>.<extension>`, for example `ui.3fa9c01b7e.css`. `crates/infraternal-server/src/web_assets.rs`
 * recognises exactly this shape (`fingerprinted`), so the two files must change together.
 *
 * Only what `index.html` (and the style sheet's own `@font-face` rules) names is renamed. Files that code loads by a fixed
 * name (the service worker's URL, the web workers, the on-demand sheets, the fonts the font picker fetches) keep their
 * names and keep revalidating.
 */
import { createHash } from "node:crypto";
import { readFile, rm, writeFile, mkdir } from "node:fs/promises";
import { dirname } from "node:path";

/** Number of hex digits of the content hash in a file name: 40 bits, so two different files colliding is not a practical concern. */
export const FINGERPRINT_DIGITS = 10;

/** Matches a file name that carries a content hash, anywhere in a path. Kept in step with `fingerprinted` in web_assets.rs. */
export const FINGERPRINTED_NAME = new RegExp(`\\.[0-9a-f]{${FINGERPRINT_DIGITS}}\\.(?:js|css|woff2)$`);

/**
 * The first {@link FINGERPRINT_DIGITS} hex digits of the SHA-256 of `bytes`.
 * @param bytes the file's final contents
 */
export function contentHash(bytes: Uint8Array | string): string {
  return createHash("sha256").update(bytes).digest("hex").slice(0, FINGERPRINT_DIGITS);
}

/**
 * The hashed name of `path`: the hash goes between the stem and the extension.
 * @param path a path or file name with an extension, for example `fonts/a/roman.latin.woff2`
 * @param hash the content hash from {@link contentHash}
 * @returns for example `fonts/a/roman.latin.<hash>.woff2`
 */
export function hashedName(path: string, hash: string): string {
  const dot = path.lastIndexOf(".");
  if (dot <= path.lastIndexOf("/") + 1) throw new Error(`${path} has no extension to put a content hash before`);
  return `${path.slice(0, dot)}.${hash}${path.slice(dot)}`;
}

/** The result of {@link fingerprintAssets}: old name to new name, both relative to the output folder. */
export type FingerprintMap = ReadonlyMap<string, string>;

/**
 * Renames the page's per-visit files to content-hashed names inside `dist`, rewriting what points at them.
 *
 * Order matters: the fonts are hashed first, because the page's main style sheet names them; the style sheet's text then
 * changes, so its own hash is taken last. A font file is *copied* (the plain name stays, for code that fetches it by
 * that name); a style sheet or `main.js` is *moved*, since nothing else refers to the plain name.
 *
 * @param dist the output folder
 * @param stylesheets the style sheets the page links, as paths relative to `dist` (`style.css` is the one with `@font-face` rules)
 * @param entry the entry script, relative to `dist`
 * @returns old name to new name for every renamed file, so the page and the chunk lists can follow
 */
export async function fingerprintAssets(dist: string, stylesheets: readonly string[], entry: string): Promise<FingerprintMap> {
  const names = new Map<string, string>();
  for (const sheet of stylesheets) {
    let text = await readFile(`${dist}/${sheet}`, "utf8");
    // `url("./fonts/x.woff2")`: the page's sheets sit in the output root, so the path is relative to it.
    const fonts = new Set([...text.matchAll(/url\("\.\/(fonts\/[^"?#]+\.woff2)"\)/g)].map((match) => match[1]!));
    for (const font of fonts) {
      if (!names.has(font)) {
        const bytes = await readFile(`${dist}/${font}`);
        const renamed = hashedName(font, contentHash(bytes));
        await mkdir(dirname(`${dist}/${renamed}`), { recursive: true });
        await writeFile(`${dist}/${renamed}`, bytes);
        names.set(font, renamed);
      }
      text = text.replaceAll(`url("./${font}")`, `url("./${names.get(font)}")`);
    }
    const renamed = hashedName(sheet, contentHash(text));
    await writeFile(`${dist}/${renamed}`, text);
    await rm(`${dist}/${sheet}`);
    names.set(sheet, renamed);
  }
  const script = await readFile(`${dist}/${entry}`);
  const renamedEntry = hashedName(entry, contentHash(script));
  await writeFile(`${dist}/${renamedEntry}`, script);
  await rm(`${dist}/${entry}`);
  names.set(entry, renamedEntry);
  return names;
}

/**
 * Points the page at the renamed files: every `href="./old"` and `src="./old"` whose target was renamed.
 * @param html the page's source
 * @param names the map from {@link fingerprintAssets}
 * @param preloadedFonts font files (relative to the output folder) the page preloads; they must be in `names`, or the page would hint a file that no longer matches what the style sheet fetches
 */
export function withHashedReferences(html: string, names: FingerprintMap, preloadedFonts: readonly string[] = []): string {
  for (const font of preloadedFonts) {
    if (!names.has(font)) throw new Error(`${font} is preloaded by the page but not renamed: the style sheets do not use it`);
  }
  return html.replace(/\b(href|src)="\.\/([^"]+)"/g, (whole, attribute: string, target: string) => {
    const renamed = names.get(target);
    return renamed ? `${attribute}="./${renamed}"` : whole;
  });
}
