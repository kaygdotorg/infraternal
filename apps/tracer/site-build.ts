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
import { cp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { buildDocs, INDEX_SLUG, readUserDocs, redirectPage, USER_DOCS_DIR, type DocsIndexPage } from "./docs-build";
import { figures, type FigureManifest } from "./docs-figure";
import { DEFAULT_RELEASE_ORIGIN, installCommandFor, SERVER_IMAGE_NAME } from "./install-release";
import { AUDIENCES, escapeHtml, sitePage, type Audience } from "./site-chrome";

/** The repository root, found from this file's place (`apps/tracer/`). */
const root = resolve(import.meta.dirname, "../..");

/** What the standalone-site build is told: the folder to write, and where the captured figures are. */
export interface SiteOptions { out: string; figures?: string }

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
<p class="hint">Linux, x86-64 and arm64. The installer checks the build\u2019s signature before it installs anything. To check by hand first, see <a href="/install/">Install</a>.</p>
</section>
<section class="shot" aria-label="Screenshot"><div class="doc">${figureHtml}</div></section>
<section class="band" aria-labelledby="today">
<h2 id="today">What works today</h2>
<ul class="cards">
<li class="card"><h3>Terminals on every device</h3><p>Every terminal keeps running on its machine. Close the tab, move from your laptop to your phone, and pick it up where you left it.</p><a href="/docs/user/terminal/multiplexer/">How sessions work</a></li>
<li class="card"><h3>Machines and mesh</h3><p>Add a computer from the app and the server sets it up over SSH. Your machines then reach each other over a private WireGuard mesh whose keys renew by themselves.</p><a href="/docs/user/mesh/">About the mesh</a></li>
<li class="card"><h3>Your account</h3><p>Sign in with a passkey and keep recovery words for the day you lose it. Choose which devices are signed in as you, and attach several of them to one terminal.</p><a href="/docs/user/you/">Your account</a></li>
</ul>
</section>
<ul class="facts"><li>AGPL-3.0-only</li><li>Runs on your own hardware</li><li>No trackers, no cookies</li></ul>
`;
}

/**
 * The download row of `/install`: the server image `infraternal`, with its checksum and signature next to it (D223, D184).
 * Only the server image is offered. The `infraternal-<arch>-musl` files in a release are the add-host payloads: they have no
 * `server` command, and the server installs them on each machine you add, so nobody downloads or runs them by hand.
 * The server image is built for x86-64 Linux only (docs/operations/release.md).
 *
 * Links are populated at runtime by `install-links.ts` only after fetching the channel pointer (`stable` by default; `edge`
 * only when `?channel=edge` is explicitly requested) and verifying `SHA256SUMS.sig` and `VERSION` against `release/allowed_signers`.
 */
function downloads(): string {
  return `<ul class="downloads" data-install-downloads><li><span><strong>Server, Linux x86-64</strong><br><span data-install-version>${SERVER_IMAGE_NAME}</span></span><span data-install-links>Checking signed release\u2026</span></li></ul>`;
}

/**
 * The install page. Resolves the current release through the signed channel pointer (`stable` by default;
 * `edge` only when `?channel=edge` is explicitly requested) and never hard-codes a version or pushes edge builds.
 */
function install(): string {
  return `<div class="plain" data-install-page data-origin="${DEFAULT_RELEASE_ORIGIN}" data-install-script="/docs/install-links.js">
<h1>Install Infraternal</h1>
<p class="lede">One static program is the server. It runs on a Linux x86-64 machine. When you add a machine, the server installs the infraternal agent there for you, so you never download that part.</p>
<div class="note" data-install-notice hidden></div>
<h2>1. Download</h2>
<p>The installer reads the current signed release, verifies its signature and checksum, and saves <code>${SERVER_IMAGE_NAME}</code>.</p>
<div class="doc"><div class="doc-code"><pre tabindex="0"><code data-install-cmd>${escapeHtml(installCommandFor(DEFAULT_RELEASE_ORIGIN, "stable"))}</code></pre></div></div>
<p>Or download the files by hand:</p>
${downloads()}
<p class="install-status" data-install-status aria-live="polite"></p>
<p>Every file has a checksum and a signature next to it. Check them before you run anything.</p>
${command("ssh-keygen -Y verify -f allowed_signers -I release@infraternal.com -n infraternal-release -s SHA256SUMS.sig < SHA256SUMS\nsha256sum --check --ignore-missing SHA256SUMS")}
<h2>2. Run the server</h2>
<p>Set it up as a service on the machine that will be your server. <code>--dry-run</code> prints the plan first. The server then prints a one-time setup code you use to create the first account.</p>
${command("chmod +x infraternal\n./infraternal server init --dry-run")}
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

/**
 * Leaves a redirect page at each old flat address of the user pages, `/docs/<page>/` and `/docs/<section>/<page>/`, which now live
 * under `/docs/user/` (D388). Former addresses (a page's `Former slugs` line) go straight to the page's current home, in one hop.
 * Addresses of the three audiences themselves are never overwritten, and a user page may not take one of their names.
 */
export async function writeFlatRedirects(docs: string, index: readonly DocsIndexPage[]): Promise<number> {
  const taken = new Set<string>(Object.keys(AUDIENCES));
  const titles = new Map(index.map((page) => [page.slug, page.title]));
  const targets = new Map<string, string>();
  for (const page of index) if (page.slug !== INDEX_SLUG) targets.set(page.slug, page.slug);
  for (const entry of (await readUserDocs(USER_DOCS_DIR)).pages) for (const former of entry.former) targets.set(former, entry.slug);
  for (const [from, to] of targets) {
    if (taken.has(from.split("/")[0]!)) throw new Error(`user page "${from}" would take the address of an audience`);
    await mkdir(resolve(docs, from), { recursive: true });
    await writeFile(resolve(docs, from, "index.html"), redirectPage(`user/${to}`, titles.get(to) ?? to, "/docs"));
  }
  return targets.size;
}

/** Writes one page of the site at `path` (`install` is `/install/`); an empty path is the front page. */
async function put(out: string, path: string, html: string): Promise<void> {
  const dir = resolve(out, path);
  await mkdir(dir, { recursive: true });
  await writeFile(resolve(dir, "index.html"), html);
}

/** Builds the whole site into `options.out`. */
export async function buildSite(options: SiteOptions): Promise<void> {
  const { out } = options;
  await rm(out, { recursive: true, force: true });
  const docs = resolve(out, "docs");
  const scratch = resolve(out, "../.site-sources");
  const counts = {} as Record<Audience, number>;
  const indexes: Record<string, DocsIndexPage[]> = {};
  indexes.user = await buildDocs(docs, undefined, undefined, { audience: "user" });
  await writeFlatRedirects(docs, indexes.user);
  for (const audience of ["admin", "dev"] as const) indexes[audience] = await buildDocs(docs, await standInSource(audience, scratch), [], { audience });
  for (const audience of Object.keys(AUDIENCES) as Audience[]) counts[audience] = indexes[audience]!.length - 1;

  // The landing page's screenshot goes through the same figure code as the docs'; pending until a capture exists.
  const manifestFile = options.figures ? Bun.file(resolve(options.figures, "manifest.json")) : undefined;
  const captured = manifestFile && await manifestFile.exists() ? { manifest: (await manifestFile.json()) as FigureManifest, directory: resolve(options.figures!) } : { manifest: {} as FigureManifest };
  const shot = figures('<p><img src="figure:sessions-windows" alt="Three terminals on the canvas, each its own window: a backup on the home server, a photo index on the media server, and updates on a Raspberry Pi." title="Every session is a window on the canvas, so you move between them with the canvas, not with a prefix key."></p>', { ...captured, page: "landing" });
  if (shot.files.length > 0) {
    await mkdir(resolve(docs, "figures"), { recursive: true });
    await Promise.all(shot.files.map((file) => cp(resolve(options.figures!, file), resolve(docs, "figures", file))));
  }

  // Bundle the install-page pointer resolver with the canonical trust anchors from release/allowed_signers (D184, D224).
  const allowedSigners = await readFile(resolve(root, "release/allowed_signers"), "utf8");
  const installScript = await Bun.build({
    entrypoints: [resolve(import.meta.dirname, "install-links.ts")],
    target: "browser",
    format: "esm",
    minify: true,
    outdir: docs,
    naming: { entry: "install-links.js" },
    define: { __INFRATERNAL_ALLOWED_SIGNERS__: JSON.stringify(allowedSigners) },
  });
  if (!installScript.success) throw new Error(`install script: ${installScript.logs.map(String).join("; ")}`);
  await cp(resolve(root, "scripts/release/install.sh"), resolve(out, "install.sh"));

  const chrome = (title: string, body: string, area: "home" | "docs" | "install" | "releases" | "changelog", main: "docs" | "site" = "site", here?: string): string => sitePage({ title, body, area, main, ...(here ? { here } : {}) });
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
  await buildSite({ out, ...(process.env.SITE_FIGURES ? { figures: process.env.SITE_FIGURES } : {}) });
  console.log(`site written to ${out}`);
}
