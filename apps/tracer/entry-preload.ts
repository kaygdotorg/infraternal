/**
 * Lets the browser fetch the app's first-screen code in one round trip instead of three (J1069).
 *
 * `main.js` imports its shared chunks statically, and those import more chunks. A browser only learns each level
 * after it has downloaded and parsed the one above, so a cold visit pays one network round trip per level before the
 * sign-in screen can start. The build already knows the whole static import graph; this module lists it so build.ts can
 * write it into `index.html` as `<link rel="modulepreload">` hints, which the browser fetches in parallel with the page.
 *
 * Only static imports count. A dynamic `import()` (the terminal, the canvas) is code that a visit may never run, and
 * preloading it would spend the person's bandwidth on it.
 */
import type { MetaOutput } from "./chunk-classes";

/** A metafile path without a leading `./`, so paths from `outputs` and from `imports` compare equal. */
const name = (path: string): string => path.replace(/^\.\//, "");

/**
 * The entry and every chunk it reaches through static imports, entry first, then breadth-first so the chunks that
 * unlock the most code are requested first.
 * @param outputs the `outputs` object of the bundler's metafile
 * @param entry the output file name of the entry, for example `main.js`
 * @returns file names relative to the output folder; empty when the entry is not in the build
 */
export function staticClosure(outputs: Record<string, MetaOutput>, entry: string): string[] {
  const byName = new Map(Object.entries(outputs).map(([path, out]) => [name(path), out]));
  if (!byName.has(entry)) return [];
  const seen = new Set<string>([entry]);
  const queue = [entry];
  for (let index = 0; index < queue.length; index += 1) {
    for (const edge of byName.get(queue[index]!)?.imports ?? []) {
      const target = name(edge.path);
      if (edge.kind === "import-statement" && byName.has(target) && !seen.has(target)) {
        seen.add(target);
        queue.push(target);
      }
    }
  }
  return queue;
}

/**
 * Writes one `<link rel="modulepreload">` per file just before the end of `<head>`.
 * @param html the page's source
 * @param files file names relative to the page, as returned by {@link staticClosure}
 * @returns the page with the hints in it; a page without `</head>` is an error, since a silent no-op would hide a broken build
 */
export function withModulePreload(html: string, files: readonly string[]): string {
  if (!html.includes("</head>")) throw new Error("index.html has no </head> to put the module preload hints in");
  const links = files.map((file) => `    <link rel="modulepreload" href="./${file}" />\n`).join("");
  return html.replace("</head>", `${links}  </head>`);
}

/**
 * The chunks a returning person's visit needs right after the sign-in answer: the closures (through static imports) of the
 * chunks that hold `sourceSuffixes`, without what the first screen already preloads.
 * @param outputs the `outputs` object of the bundler's metafile
 * @param sourceSuffixes paths ending in the source files whose chunks are wanted, for example `src/core-screen.ts`
 * @param already file names that are preloaded for everyone, left out of the answer
 * @returns file names in request order; a source file that no chunk holds is an error, so a rename cannot silently turn the hint off
 */
export function returningVisitChunks(outputs: Record<string, MetaOutput>, sourceSuffixes: readonly string[], already: readonly string[]): string[] {
  const skip = new Set(already);
  const files: string[] = [];
  for (const suffix of sourceSuffixes) {
    const holder = Object.entries(outputs).find(([, out]) => Object.keys(out.inputs).some((input) => input.endsWith(suffix)));
    if (!holder) throw new Error(`no chunk holds ${suffix}: update the returning-visit preload list in build.ts`);
    for (const file of staticClosure(outputs, name(holder[0]))) {
      if (!skip.has(file)) { skip.add(file); files.push(file); }
    }
  }
  return files;
}

/** The `localStorage` key of the device's sign-in counter (`src/hints.ts` writes it; the same string, because index.html cannot import). */
export const SIGN_IN_COUNTER_KEY = "tracer.hints";

/**
 * Adds a small inline script that preloads `files` only on a device that has signed in before.
 *
 * A first-time visitor sees the sign-in screen and needs none of this code yet; a returning person needs it the moment the
 * session answer arrives, so fetching it alongside the page removes the round trips between that answer and the terminal.
 * The script is plain and wrapped in `try`, because storage can be refused and the page must never depend on it.
 * @param html the page's source
 * @param files file names relative to the page
 * @param fetches data files the terminal fetches (the engine's wasm), preloaded as fetches rather than modules
 * @returns the page with the script before `</head>`
 */
export function withReturningVisitPreload(html: string, files: readonly string[], fetches: readonly string[] = []): string {
  if (!html.includes("</head>")) throw new Error("index.html has no </head> to put the returning-visit preload in");
  if (files.length === 0 && fetches.length === 0) return html;
  // `as=fetch` with `crossorigin` is what `fetch()` (and so streaming compilation) matches; without the attribute the preload is fetched twice.
  const modules = `${JSON.stringify(files.map((file) => `./${file}`))}.forEach(function(f){var l=document.createElement("link");l.rel="modulepreload";l.href=f;document.head.appendChild(l)});`;
  const data = `${JSON.stringify(fetches.map((file) => `./${file}`))}.forEach(function(f){var l=document.createElement("link");l.rel="preload";l.as="fetch";l.crossOrigin="anonymous";l.href=f;document.head.appendChild(l)});`;
  const script = `try{if(JSON.parse(localStorage.getItem(${JSON.stringify(SIGN_IN_COUNTER_KEY)})||"{}").signIns>0){${files.length ? modules : ""}${fetches.length ? data : ""}}}catch(e){}`;
  return html.replace("</head>", `    <script>${script}</script>\n  </head>`);
}
