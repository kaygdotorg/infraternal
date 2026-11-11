// SPDX-License-Identifier: AGPL-3.0-only
/**
 * Builds the whole standalone site as a mockup for review (#339, D388): `bun run site <out>` writes a folder a static host can serve.
 *
 *   /                       the landing page
 *   /install/               downloads (placeholder links to builds.infraternal.com, D223)
 *   /releases/ /changelog/  empty states until the first release
 *   /docs/                  the three audiences
 *   /docs/user /admin /dev  the pages of each audience, rendered by the one renderer (docs-build.ts)
 *   /404.html, /docs/404.html
 *
 * It uses the docs renderer and nothing else: no framework, no new dependency. The user pages are the real ones from `docs/user/`.
 * The admin and developer audiences have no folder of their own yet (D388 sets the addresses, not the content), so a few existing pages
 * of `docs/` stand in: they are copied, unchanged, into a scratch folder next to the output and rendered as that audience's pages. The
 * landing page claims only what is built today (D45); it has no prices, no trackers and no waitlist (D46).
 *
 * The one screenshot of the landing page comes from the docs' figure pipeline (`figures/capture.ts`). Point `SITE_FIGURES` at the folder
 * the capture wrote (with its `manifest.json`); without it the slot shows "Figure pending", as every figure does until a capture exists.
 */
import { cp, mkdir, rm, writeFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import { resolve } from "node:path";
import { buildDocs, type DocsIndexPage } from "./docs-build";
import { figures, type FigureManifest } from "./docs-figure";
import { AUDIENCES, escapeHtml, sitePage, type Audience } from "./site-chrome";

/** The repository root, found from this file's place (`apps/tracer/`). */
const root = resolve(import.meta.dirname, "../..");

/** What the standalone-site build is told: the folder to write, whether it is a review build, and where the captured figures are. */
export interface SiteOptions { out: string; mockup?: boolean; figures?: string }

/**
 * The existing pages that stand in for the admin and developer audiences: `from` is the file in `docs/`, `name` the page's address under
 * the audience. Each audience's front page is written by `frontFor`.
 */
const STAND_INS: Record<Exclude<Audience, "user">, { from: string; name: string }[]> = {
  admin: [
    { from: "docs/operations/deploy.md", name: "10-updating-a-server" },
    { from: "docs/CLI.md", name: "20-command-line" },
    { from: "docs/operations/nix-package.md", name: "30-nix-package" },
  ],
  dev: [
    { from: "docs/ARCHITECTURE.md", name: "10-architecture" },
    { from: "docs/ENGINEERING.md", name: "20-engineering-practices" },
  ],
};

/** The front page text of an audience whose pages are stand-ins. One sentence under the title, as every page needs (docs-build.ts). */
function frontFor(audience: Exclude<Audience, "user">): string {
  return `# ${AUDIENCES[audience].label}\n\n${AUDIENCES[audience].blurb}\n`;
}

/** Copies the stand-in pages of an audience into a fresh scratch folder and returns it, ready for `buildDocs`. */
async function standInSource(audience: Exclude<Audience, "user">, scratch: string): Promise<string> {
  const dir = resolve(scratch, audience);
  await rm(dir, { recursive: true, force: true });
  await mkdir(dir, { recursive: true });
  await writeFile(resolve(dir, "index.md"), frontFor(audience));
  for (const { from, name } of STAND_INS[audience]) await cp(resolve(root, from), resolve(dir, `${name}.md`));
  return dir;
}

/** `bun` can read the committed font of the app; the second face is optional (it is only used by the `?font=sans` comparison). */
async function copyFaces(out: string): Promise<void> {
  const geist = resolve(import.meta.dirname, "node_modules/geist/dist/fonts/geist-sans/Geist-Variable.woff2");
  if (existsSync(geist)) await cp(geist, resolve(out, "docs/fonts/Geist-Variable.woff2"));
}

/** A copyable block of shell text, in the markup the docs' code blocks use, so `doc.js` copies it on a click. */
const command = (text: string): string => `<div class="doc"><div class="doc-code"><pre tabindex="0"><code>${escapeHtml(text)}</code></pre></div></div>`;

/** The landing page. Everything it says is built today (D45): terminals on every device, machines and the mesh, access and sharing. */
function landing(figureHtml: string): string {
  return `<section class="hero">
<p class="eyebrow">Open source · AGPL-3.0-only</p>
<h1>Infrastructure you fully own</h1>
<p class="lede">One server you run, on hardware you choose. Open a terminal on any of your machines from any of your devices, join the machines into a private mesh, and decide who gets in.</p>
<div class="hero-actions"><a class="button primary" href="/install/">Install</a><a class="button" href="/docs/">Read the docs</a></div>
${command("curl -fsSL https://builds.infraternal.com/install.sh | sh")}
<p class="hint">Linux, x86-64 and arm64. The install page shows how to check the download first.</p>
</section>
<section class="shot" aria-label="Screenshot"><div class="doc">${figureHtml}</div></section>
<section class="band" aria-labelledby="today">
<h2 id="today">What works today</h2>
<ul class="cards">
<li class="card"><h3>Terminals on every device</h3><p>Every terminal keeps running on its machine. Close the tab, move from your laptop to your phone, and pick it up where you left it.</p><a href="/docs/user/terminal/multiplexer/">How sessions work</a></li>
<li class="card"><h3>Machines and mesh</h3><p>Add a computer from the app and the server sets it up over SSH. Your machines then reach each other over a private WireGuard mesh whose keys renew by themselves.</p><a href="/docs/user/mesh/">About the mesh</a></li>
<li class="card"><h3>Access and sharing</h3><p>Sign in with a passkey and keep recovery words for the day you lose it. Choose which devices are signed in as you, and attach several of them to one terminal.</p><a href="/docs/user/you/">Your account</a></li>
</ul>
</section>
<ul class="facts"><li>AGPL-3.0-only</li><li>Runs on your own hardware</li><li>No trackers, no cookies</li></ul>
`;
}

/** The download rows of `/install`: one binary per architecture, with its checksum and signature next to it (D223, D184). */
function downloads(): string {
  const base = "https://builds.infraternal.com/releases/latest";
  const row = (arch: string, label: string): string => `<li><span><strong>${label}</strong><br><span>infraternal-${arch}-musl</span></span><span><a href="${base}/infraternal-${arch}-musl">Download</a> · <a href="${base}/SHA256SUMS">Checksums</a> · <a href="${base}/SHA256SUMS.sig">Signature</a></span></li>`;
  return `<ul class="downloads">${row("x86_64", "Linux, x86-64")}${row("aarch64", "Linux, arm64")}</ul>`;
}

/** The install page. The links are placeholders for the first published release; the note says so on the page. */
function install(): string {
  return `<div class="plain">
<h1>Install Infraternal</h1>
<p class="lede">One static program per architecture. It is the server, and the same program is the infraternal agent that runs on each machine you add.</p>
<div class="note"><p><strong>Placeholder links.</strong> No release is published yet. These addresses are where the first one will be (D223).</p></div>
<h2>1. Download</h2>
${downloads()}
<p>Every file has a checksum and a signature next to it. Check them before you run anything.</p>
${command("sha256sum --check --ignore-missing SHA256SUMS")}
<h2>2. Run the server</h2>
<p>Set it up as a service on the machine that will be your server. <code>--dry-run</code> prints the plan first. The server then prints a one-time setup code you use to create the first account.</p>
${command("chmod +x infraternal-x86_64-musl\n./infraternal-x86_64-musl server init --dry-run")}
<h2>3. Open the app</h2>
<p>There is nothing to install on your devices: open your server's address in a browser. On an iPhone, choose Share, then Add to Home Screen.</p>
<p>Then add your first machine. <a href="/docs/user/start/">Get started</a> · <a href="/docs/admin/">Admin guide</a></p>
</div>
`;
}

/** An empty list page (releases, changelog) until the first release exists. */
function emptyPage(title: string, lede: string, more: string): string {
  return `<div class="plain"><h1>${title}</h1><p class="lede">${lede}</p><div class="empty"><p>${more}</p><p><a href="/install/">Install</a> · <a href="/docs/">Docs</a></p></div></div>\n`;
}

/** The page at `/docs/`: the three audiences, with how many pages each holds. */
function hub(counts: Record<Audience, number>): string {
  const cards = (Object.keys(AUDIENCES) as Audience[]).map((id) => `<li><a href="/docs/${id}/"><strong>${AUDIENCES[id].label}</strong><span>${AUDIENCES[id].blurb}</span><small>${counts[id]} ${counts[id] === 1 ? "page" : "pages"}</small></a></li>`).join("");
  return `<div class="plain"><h1>Documentation</h1><p class="lede">Pick the guide that matches what you are doing. Each one is written for its readers.</p><ul class="audiences">${cards}</ul></div>\n`;
}

/** The 404 page of the site, and the one inside `/docs/`, which also points at the guides. */
function notFound(inDocs: boolean): string {
  const links = inDocs ? `<p><a href="/docs/user/">User guide</a> · <a href="/docs/admin/">Admin guide</a> · <a href="/docs/dev/">Developer docs</a></p>` : `<p><a href="/">Home</a> · <a href="/docs/">Docs</a> · <a href="/install/">Install</a></p>`;
  return `<div class="plain"><p class="code404">404</p><h1>${inDocs ? "That page is not in the docs" : "That page does not exist"}</h1><p class="lede">${inDocs ? "It may have moved, or the address has a typo. The guides below list every page." : "The address may have a typo, or the page may have moved."}</p>${links}</div>\n`;
}

/** Writes one page of the site at `path` (`install` is `/install/`); an empty path is the front page. */
async function put(out: string, path: string, html: string): Promise<void> {
  const dir = resolve(out, path);
  await mkdir(dir, { recursive: true });
  await writeFile(resolve(dir, "index.html"), html);
}

/** Builds the whole site into `options.out`. */
export async function buildSite(options: SiteOptions): Promise<void> {
  const { out, mockup } = options;
  await rm(out, { recursive: true, force: true });
  const docs = resolve(out, "docs");
  const scratch = resolve(out, "../.site-sources");
  const counts = {} as Record<Audience, number>;
  const indexes: Record<string, DocsIndexPage[]> = {};
  indexes.user = await buildDocs(docs, undefined, undefined, { audience: "user", mockup });
  for (const audience of ["admin", "dev"] as const) indexes[audience] = await buildDocs(docs, await standInSource(audience, scratch), [], { audience, mockup });
  for (const audience of Object.keys(AUDIENCES) as Audience[]) counts[audience] = indexes[audience]!.length - 1;
  await copyFaces(out);

  // The landing page's screenshot goes through the same figure code as the docs'; pending until a capture exists.
  const manifestFile = options.figures ? Bun.file(resolve(options.figures, "manifest.json")) : undefined;
  const captured = manifestFile && await manifestFile.exists() ? { manifest: (await manifestFile.json()) as FigureManifest, directory: resolve(options.figures!) } : { manifest: {} as FigureManifest };
  const shot = figures('<p><img src="figure:sessions-windows" alt="Three terminals on the canvas, each its own window: a backup on the home server, a photo index on the media server, and updates on a Raspberry Pi." title="Every session is a window on the canvas, so you move between them with the canvas, not with a prefix key."></p>', { ...captured, page: "landing" });
  if (shot.files.length > 0) {
    await mkdir(resolve(docs, "figures"), { recursive: true });
    await Promise.all(shot.files.map((file) => cp(resolve(options.figures!, file), resolve(docs, "figures", file))));
  }

  const chrome = (title: string, body: string, area: "home" | "docs" | "install" | "releases" | "changelog", main: "docs" | "site" = "site", here?: string): string => sitePage({ title, body, area, main, mockup, ...(here ? { here } : {}) });
  await put(out, "", chrome("Infrastructure you fully own", landing(shot.html), "home", "site", "Infraternal"));
  await put(out, "install", chrome("Install", install(), "install"));
  await put(out, "releases", chrome("Releases", emptyPage("Releases", "Signed builds of every release.", "The first release is not out yet. Each one will be listed here with its checksums and signature."), "releases"));
  await put(out, "changelog", chrome("Changelog", emptyPage("Changelog", "What changed in each release.", "Nothing to show yet: the first release is not out."), "changelog"));
  // `/docs/` is the hub. The audiences' own front pages were written under `/docs/<audience>/` by buildDocs.
  await put(out, "docs", chrome("Docs", hub(counts), "docs", "site", "Docs"));
  await writeFile(resolve(docs, "404.html"), chrome("Not in the docs", notFound(true), "docs", "site", "Docs / Not found"));
  await writeFile(resolve(out, "404.html"), chrome("Page not found", notFound(false), "home", "site", "Not found"));
  await rm(scratch, { recursive: true, force: true });
}

if (import.meta.main) {
  const out = resolve(process.argv[2] ?? "site-dist");
  await buildSite({ out, mockup: process.env.SITE_MOCKUP === "1", ...(process.env.SITE_FIGURES ? { figures: process.env.SITE_FIGURES } : {}) });
  console.log(`site written to ${out}`);
}
