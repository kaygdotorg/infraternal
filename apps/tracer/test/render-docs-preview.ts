/**
 * TEST DOUBLE support: renders `docs/multiplexer.md` into `<dist>/docs/multiplexer.html` so the mockup's ? button
 * (`?mock=1&proto=windows&startup-demo=1`) opens a real page. The public docs site (D44, D223) does not exist in
 * this repository yet; this is only a stand-in with the product's type and colours, never shipped in a release.
 * The preview build (`INFRATERNAL_CLUSTERS_PREVIEW=1`, build.ts) runs it, so the page is in every dist the browser specs use. To
 * refresh it alone: `bun test/render-docs-preview.ts` from apps/tracer (it writes into `TRACER_DIST`).
 */
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";

const dist = resolve(process.env.TRACER_DIST ?? resolve(import.meta.dirname, "../dist"));
const source = readFileSync(resolve(import.meta.dirname, "../../../docs/multiplexer.md"), "utf8").replace(/<!--[\s\S]*?-->\n?/g, "");
const body = (Bun as unknown as { markdown: { html(text: string): string } }).markdown.html(source);

const page = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<title>The Infraternal Multiplexer · Infraternal docs</title>
<style>
@font-face { font-family: "Maple Mono NF"; src: url("/fonts/maple-mono-nf/roman.latin.woff2") format("woff2"); font-weight: 400 700; font-display: swap; }
:root { color-scheme: dark light; --bg: #0e0e10; --fg: #ecebe8; --fg-2: #a8a7a3; --line: #2a2a2e; --code: #17171a; --accent: #8fb4ff; }
@media (prefers-color-scheme: light) { :root { --bg: #f6f5f1; --fg: #1a1915; --fg-2: #5d5c57; --line: #dcdad3; --code: #ebe9e2; --accent: #2c55c8; } }
html { background: var(--bg); color: var(--fg); }
body { margin: 0 auto; max-width: 760px; padding: max(24px, env(safe-area-inset-top)) 20px max(48px, env(safe-area-inset-bottom));
  font: 450 14px/1.65 "Maple Mono NF", ui-monospace, monospace; }
h1 { font-size: 22px; font-weight: 600; margin: 24px 0 16px; }
h2 { font-size: 16px; font-weight: 600; margin: 36px 0 10px; }
p, li { color: var(--fg); } li { margin: 6px 0; }
strong { font-weight: 600; }
a { color: var(--accent); }
code, pre { font: inherit; background: var(--code); border-radius: 6px; }
code { padding: 1px 5px; font-size: 13px; } pre { padding: 12px 14px; overflow-x: auto; } pre code { padding: 0; background: none; }
blockquote { margin: 16px 0; padding: 2px 16px; border-left: 2px solid var(--line); color: var(--fg-2); }
table { border-collapse: collapse; width: 100%; margin: 14px 0; display: block; overflow-x: auto; }
th, td { border-bottom: 1px solid var(--line); padding: 8px 10px; text-align: left; vertical-align: top; }
th { color: var(--fg-2); font-weight: 500; }
</style></head><body><main>${body}</main></body></html>
`;
mkdirSync(resolve(dist, "docs"), { recursive: true });
writeFileSync(resolve(dist, "docs/multiplexer.html"), page);
process.stdout.write(`wrote ${resolve(dist, "docs/multiplexer.html")}\n`);
