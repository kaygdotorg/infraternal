/**
 * The sidebar's long list (TASTE "Tree lines run to their last child", "The sidebar header owns its row"): with 30
 * sessions under one host, every guide line ends at its last child's connector at any scroll position, and the
 * round toggle never intersects a row. Review screenshots land in the external job evidence directory.
 */
import { tracerEvidencePath } from "./evidence-path";
import { resolve } from "node:path";
import { expect, test, type Page } from "playwright/test";

const OUT = tracerEvidencePath("sidebar-polish");

async function open(page: Page, theme: string): Promise<void> {
  await page.goto(`/?mock=1&proto=clusters&scene=3&theme=${theme}&shells=30`);
  await expect(page.locator(".cl-mockup")).toBeVisible({ timeout: 20_000 });
  const dismiss = page.locator(".ui-toast").getByRole("button", { name: "Dismiss" });
  if (await dismiss.count()) await dismiss.click({ timeout: 8000 }).catch(() => {});
  await page.locator("#sidebar-toggle").click();
  // Wait for the populated tree, not a transient count captured while the inventory is still arriving.
  await expect.poll(() => page.locator("#tree .bm-leaf").count()).toBeGreaterThan(30);
  await page.waitForTimeout(700);
}

/** Boxes in page coordinates of the toggle, the rows, the guide lines and each section's last connector. */
async function measure(page: Page) {
  return page.evaluate(() => {
    const box = (e: Element) => { const r = e.getBoundingClientRect(); return { top: r.top, bottom: r.bottom, left: r.left, right: r.right }; };
    const toggle = box(document.querySelector("#sidebar-toggle")!);
    const tree = document.querySelector("#tree")!;
    const treeBox = box(tree);
    // A row scrolled half under the header is clipped by the list: only its visible part can meet the toggle.
    const rows = [...tree.querySelectorAll(".bm-head, .bm-leaf, .bm-subhead")].map(box).map((r) => ({ ...r, top: Math.max(r.top, treeBox.top), bottom: Math.min(r.bottom, treeBox.bottom) })).filter((r) => r.bottom > r.top);
    const hit = rows.filter((r) => r.top < toggle.bottom && r.bottom > toggle.top && r.left < toggle.right && r.right > toggle.left && r.bottom > treeBox.top && r.top < treeBox.bottom).length;
    // The view-level line is each section's ::before; the last one must end at the last section's head centre.
    const secs = [...tree.querySelectorAll<HTMLElement>(".bm-sec")];
    const lastSec = secs.at(-1)!;
    const pseudo = getComputedStyle(lastSec, "::before");
    const trunkBottom = lastSec.getBoundingClientRect().top + Number.parseFloat(pseudo.top) + Number.parseFloat(pseudo.height);
    const lastHead = box(lastSec.querySelector(".bm-head")!);
    const trunk = { bottom: trunkBottom, lastHeadCentre: (lastHead.top + lastHead.bottom) / 2 };
    const sections = [...tree.querySelectorAll<HTMLElement>(".bm-sec")].map((sec) => {
      const leaves = [...sec.querySelectorAll(".bm-leaf")];
      const last = leaves.at(-1);
      const svg = sec.querySelector(".bm-branches");
      const paths = svg ? [...svg.querySelectorAll(".bm-dim path")] : [];
      return {
        id: sec.dataset.id, leaves: leaves.length,
        lastCentre: last ? (box(last).top + box(last).bottom) / 2 : null,
        // A connector's bottom end is its leaf's centre (the curve ends on it); the vertical run is the path's height.
        dimPaths: paths.length,
        lastPathBottom: paths.length ? Math.max(...paths.map((p) => box(p).bottom)) : null,
        svgBottom: svg ? box(svg).bottom : null,
      };
    });
    return { toggle, treeBox, hit, trunk, sections };
  });
}

for (const [name, viewport, scale] of [["phone", { width: 393, height: 852 }, 3], ["desktop", { width: 1440, height: 900 }, 2]] as const) {
  for (const theme of ["ink", "paper"]) {
    test(`long list (${name}, ${theme})`, async ({ browser }) => {
      const context = await browser.newContext({ viewport, deviceScaleFactor: scale, ...(name === "phone" ? { hasTouch: true, isMobile: true } : {}) });
      const page = await context.newPage();
      await open(page, theme);
      const max = await page.evaluate(() => { const t = document.querySelector("#tree")!; return t.scrollHeight - t.clientHeight; });
      expect(max).toBeGreaterThan(100);
      for (const [label, at] of [["top", 0], ["middle", max / 2], ["bottom", max]] as const) {
        await page.evaluate((y) => { document.querySelector("#tree")!.scrollTop = y; }, at);
        await page.waitForTimeout(150);
        const m = await measure(page);
        expect(m.hit, `toggle intersects a row at ${label}`).toBe(0);
        await page.screenshot({ path: resolve(OUT, `${label}-${name}-${theme}.png`) });
        if (label === "bottom") {
          // Every guide line ends at its last child's connector, however far the list was scrolled.
          expect(Math.abs(m.trunk.bottom - m.trunk.lastHeadCentre), "trunk end vs last view row").toBeLessThanOrEqual(1);
          for (const sec of m.sections) {
            // One stroke for the group: stacked translucent strokes made the line fade along a long list.
            expect(sec.dimPaths, `${sec.id} draws its line once`).toBe(1);
            expect(sec.lastPathBottom, `${sec.id} has connectors`).not.toBeNull();
            expect(Math.abs(sec.lastPathBottom! - sec.lastCentre!), `${sec.id} line end vs last connector`).toBeLessThanOrEqual(1);
          }
        }
      }
      await context.close();
    });
  }
}
