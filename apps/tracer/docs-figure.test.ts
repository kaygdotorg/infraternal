// SPDX-License-Identifier: AGPL-3.0-only
/**
 * The figure syntax of the user docs (docs-figure.ts, #302): what a page writes, what the build makes of it, and every way a
 * figure can be wrong failing the build with words for the person writing the page.
 */
import { expect, test } from "bun:test";
import { mkdir, mkdtemp, readdir, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { buildDocs, renderDoc } from "./docs-build";
import { figureFile, figures, FIGURE_SCHEMES, FIGURE_SIZES, type FigureManifest } from "./docs-figure";

const manifest: FigureManifest = {
  "startup-question": { desktop: { width: 640, height: 360 }, phone: { width: 393, height: 520 } },
  "add-machine": { desktop: { width: 640, height: 400 }, phone: { width: 393, height: 600 }, clip: true },
};
const markdown = (figure: string): string => `# Demo\n\nA demo page.\n\n## One\n\ntext\n\n${figure}\n`;
const render = (figure: string, extra: Partial<Parameters<typeof renderDoc>[3]> = {}) => renderDoc("demo", markdown(figure), undefined, { manifest, ...extra });

test("an image written as figure:name becomes a lazy picture that picks its size by width and its scheme by the reader's setting", () => {
  const doc = render('![The question over a terminal.](figure:startup-question "The question Infraternal asks.")');
  expect(doc.html).toContain('<figure class="figure" data-figure="startup-question">');
  // Phone first (most specific), then desktop; the plain image is the desktop paper picture.
  expect(doc.html).toContain('<source media="(max-width: 36rem) and (prefers-color-scheme: dark)" srcset="/docs/figures/startup-question.phone.ink.webp" width="393" height="520">');
  expect(doc.html).toContain('<source media="(max-width: 36rem)" srcset="/docs/figures/startup-question.phone.paper.webp" width="393" height="520">');
  expect(doc.html).toContain('<source media="(prefers-color-scheme: dark)" srcset="/docs/figures/startup-question.desktop.ink.webp" width="640" height="360">');
  expect(doc.html).toContain('<img src="/docs/figures/startup-question.desktop.paper.webp" width="640" height="360" alt="The question over a terminal." loading="lazy" decoding="async">');
  expect(doc.html).toContain("<figcaption>The question Infraternal asks.</figcaption>");
  // No paragraph is left around it, and a plain figure has no clip.
  expect(doc.html).not.toContain('<p><img');
  expect(doc.html).not.toContain("data-clip");
  // The four pictures the page uses, and only those.
  expect(doc.figureFiles.sort()).toEqual(FIGURE_SIZES.flatMap((size) => FIGURE_SCHEMES.map((scheme) => figureFile("startup-question", size, scheme, "webp"))).sort());
});

test("+clip adds the address of the clip for the script, with the poster being the still", () => {
  const doc = render('![Adding a machine, step by step.](figure:add-machine+clip "Adding a machine takes a minute.")');
  expect(doc.html).toContain('data-clip="/docs/figures/add-machine.{size}.{scheme}.webm"');
  expect(doc.html).not.toContain("<video");
  expect(doc.figureFiles).toContain("add-machine.phone.ink.webm");
  expect(doc.figureFiles).toContain("add-machine.desktop.paper.webp");
  expect(doc.figureFiles).toHaveLength(8);
});

test("a figure needs alt text and a caption, and must have been captured", () => {
  expect(() => render('![](figure:startup-question "Caption.")')).toThrow('figure "startup-question" needs alt text');
  expect(() => render("![Alt text.](figure:startup-question)")).toThrow('figure "startup-question" needs a caption');
  expect(() => render('![Alt text.](figure:never-made "Caption.")')).toThrow('figure "never-made" has not been captured; run "bun run docs:figures"');
  expect(() => render('![Alt text.](figure:startup-question+clip "Caption.")')).toThrow("written with +clip but the capture made no clip");
});

test("the capture's own build lets a figure that does not exist yet stand as a note", () => {
  const doc = render('![Alt text.](figure:never-made "Caption.")', { allowMissing: true });
  expect(doc.html).toContain('<p class="figure-missing">Figure never-made has not been captured yet.</p>');
});

test("an image that is not a figure, or sits inside a sentence, is left alone", () => {
  const html = '<p>Text <img src="figure:x" alt="inline"> end.</p><p><img src="https://example.com/a.png" alt="A" title="B"></p>';
  expect(figures(html, { manifest }).html).toBe(html);
});

test("every file a figure uses must exist, and only the used ones are copied into the docs tree", async () => {
  const base = await mkdtemp(join(tmpdir(), "docs-figure-"));
  try {
    const source = join(base, "user");
    const folder = join(source, "figures");
    await mkdir(folder, { recursive: true });
    await writeFile(join(source, "index.md"), "# Docs\n\nStart here.\n\n## A\n\ntext\n\n## B\n\ntext\n");
    await writeFile(join(source, "page.md"), markdown('![Alt text.](figure:startup-question "Caption.")'));
    await writeFile(join(folder, "manifest.json"), JSON.stringify(manifest));
    // One picture is missing: the build says which.
    for (const size of FIGURE_SIZES) for (const scheme of FIGURE_SCHEMES) if (!(size === "phone" && scheme === "ink")) await writeFile(join(folder, figureFile("startup-question", size, scheme, "webp")), "x");
    await writeFile(join(folder, "retired.desktop.ink.webp"), "x");
    await expect(buildDocs(join(base, "out"), source)).rejects.toThrow("startup-question.phone.ink.webp");
    await writeFile(join(folder, figureFile("startup-question", "phone", "ink", "webp")), "x");
    await buildDocs(join(base, "out"), source);
    const shipped = (await readdir(join(base, "out", "figures"))).sort();
    expect(shipped).toEqual(["startup-question.desktop.ink.webp", "startup-question.desktop.paper.webp", "startup-question.phone.ink.webp", "startup-question.phone.paper.webp"]);
    expect(await readFile(join(base, "out", "page", "fragment.html"), "utf8")).toContain('<figure class="figure"');
  } finally {
    await rm(base, { recursive: true, force: true });
  }
});
