// SPDX-License-Identifier: AGPL-3.0-only
/**
 * The standalone site's own checks (#339, D388): the old flat docs addresses must keep working now that the user pages live under
 * `/docs/user/`, the three audiences' folders must never be replaced by a redirect, and the text index and search button are written.
 */
import { expect, test } from "bun:test";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { buildSite } from "./site-build";

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
