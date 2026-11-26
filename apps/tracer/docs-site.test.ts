// SPDX-License-Identifier: AGPL-3.0-only
/**
 * The standalone site's own checks (#339, D388): the old flat docs addresses must keep working now that the user pages live under
 * `/docs/user/`, the three audiences' folders must never be replaced by a redirect, and the text index and search button are written.
 */
import { expect, test } from "bun:test";
import { mkdtemp, readdir, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { buildSite, writeFlatRedirects } from "./site-build";

test("old flat /docs/<page>/ addresses redirect to /docs/user/, and audience folders stay real pages", async () => {
  const out = await mkdtemp(join(tmpdir(), "site-"));
  try {
    const site = join(out, "site");
    await buildSite({ out: site });
    const page = await readFile(join(site, "docs", "terminal", "multiplexer", "index.html"), "utf8");
    expect(page).toContain('<meta http-equiv="refresh" content="0; url=/docs/user/terminal/multiplexer/">');
    expect(page).toContain('location.replace("/docs/user/terminal/multiplexer/"+location.hash)');
    // A page's former address goes to its home in one hop, not through the previous redirect.
    const former = await readFile(join(site, "docs", "multiplexer", "index.html"), "utf8");
    expect(former).toContain('content="0; url=/docs/user/terminal/multiplexer/"');
    for (const audience of ["user", "admin", "dev"]) expect(await readFile(join(site, "docs", audience, "index.html"), "utf8")).not.toContain("http-equiv=\"refresh\"");
  } finally { await rm(out, { recursive: true, force: true }); }
});

/** A fake index entry: only the slug matters to the refusal, which happens before anything is written. */
const entry = (slug: string) => ({ slug, title: slug, summary: "x.", headings: [] });

test("a user page named like an audience is refused, at the top of a path or nested", async () => {
  const out = await mkdtemp(join(tmpdir(), "site-"));
  try {
    for (const name of ["user", "admin", "dev", "admin/keys", "dev/internals"]) {
      await expect(writeFlatRedirects(out, [entry("index"), entry(name)])).rejects.toThrow(/would take the address of an audience/);
    }
    // The refusal comes first: nothing was written for the refused page.
    expect(await readdir(out)).toEqual([]);
  } finally { await rm(out, { recursive: true, force: true }); }
});

test("a section address redirects, and the admin and dev trees are left untouched by the redirects", async () => {
  const out = await mkdtemp(join(tmpdir(), "site-"));
  try {
    const site = join(out, "site");
    await buildSite({ out: site });
    const docs = join(site, "docs");
    // /docs/terminal/ is a section's overview: it lands on the section's home under /docs/user/.
    const section = await readFile(join(docs, "terminal", "index.html"), "utf8");
    expect(section).toContain('<meta http-equiv="refresh" content="0; url=/docs/user/terminal/">');
    expect(section).toContain('location.replace("/docs/user/terminal/"+location.hash)');
    // Every file under the admin and dev trees is a real page, a fragment or an index: none is a redirect page.
    for (const audience of ["admin", "dev"]) {
      const files = (await readdir(join(docs, audience), { recursive: true })).filter((file) => file.endsWith("index.html"));
      expect(files.length).toBeGreaterThan(1);
      for (const file of files) expect(await readFile(join(docs, audience, file), "utf8")).not.toContain("http-equiv");
    }
    // And the redirects wrote nothing under the stand-in pages' flat addresses, which belong to no user page.
    for (const flat of ["updating-a-server", "command-line", "architecture"]) expect(await readdir(docs)).not.toContain(flat);
  } finally { await rm(out, { recursive: true, force: true }); }
});

test("every docs tree writes search.json, and every page of the site has the search button for all three guides", async () => {
  const out = await mkdtemp(join(tmpdir(), "site-"));
  try {
    const site = join(out, "site");
    await buildSite({ out: site });
    for (const audience of ["user", "admin", "dev"]) {
      const { pages } = JSON.parse(await readFile(join(site, "docs", audience, "search.json"), "utf8")) as { pages: { slug: string; sections: { text: string }[] }[] };
      expect(pages.length).toBeGreaterThan(1);
      expect(pages.every((page) => page.sections.length > 0)).toBe(true);
    }
    for (const page of ["", "install", "docs/user", "docs/admin/updating-a-server"]) {
      const html = await readFile(join(site, page, "index.html"), "utf8");
      expect(html).toContain('<button class="bar-kbd" type="button" data-search="/docs/user /docs/admin /docs/dev"');
    }
    expect(await readFile(join(site, "404.html"), "utf8")).toContain("data-search=");
  } finally { await rm(out, { recursive: true, force: true }); }
});

test("the install page resolves releases dynamically without hardcoded versions, placeholder links, or pushing edge", async () => {
  const out = await mkdtemp(join(tmpdir(), "site-"));
  try {
    const site = join(out, "site");
    await buildSite({ out: site });
    const landing = await readFile(join(site, "index.html"), "utf8");
    const html = await readFile(join(site, "install", "index.html"), "utf8");
    expect(html).toContain('data-install-page data-site-origin="https://infraternal.com"');
    // Both landing and /install/ advertise the installer URL on Pages, and that exact file is built into the site output.
    for (const pageHtml of [landing, html]) {
      const match = /curl -fsSL (https:\/\/[^\s<]+) \| sh/.exec(pageHtml);
      expect(match).not.toBeNull();
      const advertised = new URL(match![1]!);
      expect(advertised.origin).toBe("https://infraternal.com");
      const published = await readFile(join(site, advertised.pathname.replace(/^\/+/, "")), "utf8");
      expect(published).toContain("ssh-keygen -Y verify");
    }
    expect(JSON.parse(await readFile(join(site, "_routes.json"), "utf8"))).toEqual({
      version: 1, include: ["/releases/*"], exclude: ["/releases/"],
    });
    expect(html).toContain('href="/allowed_signers"');
    const publishedSigners = await readFile(join(site, "allowed_signers"), "utf8");
    expect(publishedSigners).toContain('namespaces="infraternal-release"');
    expect(html).not.toContain("/releases/latest");
    expect(html).not.toContain("Placeholder links");
    expect(html).not.toContain("edge-");
    expect(html).not.toContain("--channel edge");
    const bundle = await readFile(join(site, "docs", "install-links.js"), "utf8");
    expect(bundle).toContain("infraternal-release");
  } finally { await rm(out, { recursive: true, force: true }); }
});
