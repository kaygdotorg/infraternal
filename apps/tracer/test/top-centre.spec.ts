/**
 * The top pill sits on the viewport's centre line, and the add-host primary button's label is crisp and legible in
 * every state (docs/design/TASTE.md, the two rows added 2026-10-10; #121, #87). Measured against the production build:
 *
 *  - the pill's centre is within 1 px of the viewport centre at 1440, 1920 and 2000 px, with the sidebar closed and
 *    open, and with extra controls on the right (the canvas buttons beside "+"), which is the layout that used to pull
 *    the pill off-centre;
 *  - the disabled "Continue" has no filter or fractional transform in its ancestry, and its own text-shadow is none;
 *  - the disabled and enabled labels reach at least 3:1 (4.5:1 enabled) against their fill, from computed colours;
 *  - review screenshots go to the external job evidence directory (the top bar and footer at 2x in ink and paper).
 */
import { tracerEvidencePath } from "./evidence-path";
import { mkdirSync } from "node:fs";
import { resolve } from "node:path";
import { expect, test, type Page } from "playwright/test";

const OUT = tracerEvidencePath("centre-button");
mkdirSync(OUT, { recursive: true });

async function openCanvas(page: Page): Promise<void> {
  await page.request.post("/__mock/reset").catch(() => page.request.post("/__mock/reset"));
  await page.goto("/?mock=1&proto=windows&bg=none&fixture=none");
  await expect.poll(() => page.evaluate(() => (window as unknown as { __tracerCanvas?: { windows(): string[] } }).__tracerCanvas?.windows().length ?? 0)).toBeGreaterThan(2);
  await page.waitForTimeout(400);
}

/** Adds controls to the right of the pill the way the canvas toolbar does (the views and snap buttons beside "+"). */
async function addRightControls(page: Page, count: number): Promise<void> {
  await page.evaluate((n) => {
    const tabs = document.querySelector(".tabs");
    for (let i = 0; i < n; i++) { const b = document.createElement("button"); b.className = "ui-pill ui-pill-icon"; b.type = "button"; b.setAttribute("aria-label", `extra ${i}`); tabs?.prepend(b); }
  }, count);
}

const pillCentreError = (page: Page) => page.evaluate(() => {
  const r = document.querySelector<HTMLElement>("#capsule")!.getBoundingClientRect();
  return (r.left + r.right) / 2 - window.innerWidth / 2;
});

test.describe("the top pill is centred on the viewport", () => {
  for (const width of [1440, 1920, 2000]) {
    test(`${width} px: centre error is within 1 px, sidebar closed and open, with extra right controls`, async ({ page }) => {
      await page.setViewportSize({ width, height: 1000 });
      await openCanvas(page);
      await expect.poll(() => pillCentreError(page)).toBeLessThanOrEqual(1);
      expect(Math.abs(await pillCentreError(page))).toBeLessThanOrEqual(1);
      await addRightControls(page, 2);
      expect(Math.abs(await pillCentreError(page))).toBeLessThanOrEqual(1);
      await page.locator("#sidebar-toggle").click();
      await expect(page.locator(".terminal-screen[data-sidebar-open]")).toBeAttached();
      await page.waitForTimeout(400);
      expect(Math.abs(await pillCentreError(page))).toBeLessThanOrEqual(1);
      // The pill never runs under the side controls: it ends before the right group starts.
      const overlap = await page.evaluate(() => {
        const cap = document.querySelector("#capsule")!.getBoundingClientRect();
        const tabs = document.querySelector(".tabs")!.getBoundingClientRect();
        return cap.right > tabs.left && cap.left < tabs.right;
      });
      expect(overlap).toBe(false);
    });
  }

  test("the pill reads as centred on the default windows column at 2000 px", async ({ page }) => {
    await page.setViewportSize({ width: 2000, height: 1250 });
    await openCanvas(page);
    await page.waitForTimeout(600);
    await page.screenshot({ path: `${OUT}/top-bar-2000x1250-ink.png`, clip: { x: 0, y: 0, width: 2000, height: 120 } });
    expect(Math.abs(await pillCentreError(page))).toBeLessThanOrEqual(1);
  });
});

/** Converts a computed CSS colour (rgb() or oklab(), which color-mix() yields) to linear sRGB, then WCAG luminance. */
function luminance(css: string): number {
  let r: number, g: number, b: number;
  const m = /^oklab\(([\d.e-]+)\s+([-\d.e]+)\s+([-\d.e]+)(?:\s*\/\s*[\d.]+)?\)$/.exec(css);
  if (m) {
    const L = Number(m[1]), A = Number(m[2]), B = Number(m[3]);
    const l = (L + 0.3963377774 * A + 0.2158037573 * B) ** 3;
    const mm = (L - 0.1055613458 * A - 0.0638541728 * B) ** 3;
    const s = (L - 0.0894841775 * A - 1.2914855480 * B) ** 3;
    r = 4.0767416621 * l - 3.3077115913 * mm + 0.2309699292 * s;
    g = -1.2684380046 * l + 2.6097574011 * mm - 0.3413193965 * s;
    b = -0.0041960863 * l - 0.7034186147 * mm + 1.7076147010 * s;
  } else {
    const n = /rgba?\(([\d.]+),\s*([\d.]+),\s*([\d.]+)/.exec(css);
    if (!n) throw new Error(`unreadable colour ${css}`);
    const lin = (c: number) => { const v = c / 255; return v <= 0.04045 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4; };
    r = lin(Number(n[1])); g = lin(Number(n[2])); b = lin(Number(n[3]));
    return 0.2126 * r + 0.7152 * g + 0.0722 * b;
  }
  const c = (v: number) => Math.min(1, Math.max(0, v));
  return 0.2126 * c(r) + 0.7152 * c(g) + 0.0722 * c(b);
}
const contrast = (a: string, b: string): number => {
  const la = luminance(a), lb = luminance(b);
  return (Math.max(la, lb) + 0.05) / (Math.min(la, lb) + 0.05);
};

async function openWizard(page: Page, theme = "ink"): Promise<void> {
  await page.request.post("/__mock/bootstrap/reset").catch(() => undefined);
  await page.goto(`/?mock=1&proto=clusters&scene=3&theme=${theme}&bg=none`);
  await page.waitForSelector(".cl-mockup", { timeout: 20_000 });
  await page.waitForTimeout(400);
  await page.evaluate(() => window.dispatchEvent(new CustomEvent("tracer:canvas-action", { detail: { action: "canvas:addhost", source: "keyboard" } })));
  await expect(page.locator(".ah-page[data-page='discovery']")).toBeVisible();
  await atRest(page);
}

/** The card rises on a spring and carries a transform until it settles; the rest state is what the labels are judged in. */
async function atRest(page: Page): Promise<void> {
  await expect.poll(() => page.evaluate(() => getComputedStyle(document.querySelector(".ah-float")!).transform), { timeout: 5_000 }).toBe("none");
  await page.waitForTimeout(250);
}

const primary = (page: Page) => page.locator(".ah-float").getByRole("button", { name: "Continue", exact: true });

test.describe("the add-host primary label is crisp and legible", () => {
  for (const theme of ["ink", "paper"]) test(`${theme}: disabled Continue has no filter, halo or fractional transform in its ancestry; contrast at least 3:1`, async ({ page }) => {
    await page.setViewportSize({ width: 1440, height: 900 });
    await openWizard(page, theme);
    const button = primary(page);
    await expect(button).toBeDisabled();
    const computed = await button.evaluate((el) => {
      const chain: { tag: string; filter: string; transform: string; willChange: string }[] = [];
      for (let node: Element | null = el; node && node !== document.documentElement; node = node.parentElement) {
        const cs = getComputedStyle(node);
        chain.push({ tag: node.tagName, filter: cs.filter, transform: cs.transform, willChange: cs.willChange });
      }
      const cs = getComputedStyle(el);
      return { chain, textShadow: cs.textShadow, color: cs.color, background: cs.backgroundColor };
    });
    for (const node of computed.chain) {
      expect(node.filter, `filter on ${node.tag}`).toBe("none");
      expect(node.willChange, `will-change on ${node.tag}`).not.toMatch(/transform|filter/);
      if (node.transform !== "none") {
        // Any transform at rest is a failure unless it is an exact, whole-pixel translation with no scale.
        const m = /^matrix\(([^)]+)\)$/.exec(node.transform);
        const [a = NaN, b = NaN, c = NaN, d = NaN, e = NaN, f = NaN] = m?.[1]?.split(",").map(Number) ?? [];
        const whole = [e, f].every((t) => Number.isInteger(t));
        const unscaled = a === 1 && d === 1 && b === 0 && c === 0;
        expect(whole && unscaled, `transform at rest on ${node.tag}: ${node.transform}`).toBe(true);
      }
    }
    expect(computed.textShadow, "the glass halo must not reach a solid label").toBe("none");
    const ratio = contrast(computed.color, computed.background);
    console.log(`${theme} disabled Continue contrast ${ratio.toFixed(2)}:1 (${computed.color} on ${computed.background})`);
    expect(ratio).toBeGreaterThanOrEqual(3);
  });

  for (const theme of ["ink", "paper"]) test(`${theme}: enabled Continue has no halo, contrast at least 4.5:1`, async ({ page }) => {
    await page.setViewportSize({ width: 1440, height: 900 });
    await openWizard(page, theme);
    await page.locator(".ah-row[data-host='o2']").click();
    const button = primary(page);
    await expect(button).toBeEnabled();
    // The fill fades over 160 ms; the colours are read once it has landed.
    await page.waitForTimeout(400);
    const cs = await button.evaluate((el) => { const s = getComputedStyle(el); return { shadow: s.textShadow, color: s.color, background: s.backgroundColor }; });
    expect(cs.shadow).toBe("none");
    const ratio = contrast(cs.color, cs.background);
    console.log(`${theme} enabled Continue contrast ${ratio.toFixed(2)}:1`);
    expect(ratio).toBeGreaterThanOrEqual(4.5);
  });
});

test.describe("captures for review (2x)", () => {
  test.use({ deviceScaleFactor: 2 });
  for (const theme of ["ink", "paper"]) {
    test(`add-host footer, ${theme}: disabled and enabled`, async ({ page }) => {
      await page.setViewportSize({ width: 1440, height: 900 });
      await page.request.post("/__mock/bootstrap/reset").catch(() => undefined);
      await page.goto(`/?mock=1&proto=clusters&scene=3&theme=${theme}&bg=none`);
      await page.waitForSelector(".cl-mockup", { timeout: 20_000 });
      await page.waitForTimeout(400);
      await page.evaluate(() => window.dispatchEvent(new CustomEvent("tracer:canvas-action", { detail: { action: "canvas:addhost", source: "keyboard" } })));
      await expect(page.locator(".ah-page[data-page='discovery']")).toBeVisible();
      await atRest(page);
      const foot = page.locator(".ah-float .ah-foot");
      const box = await foot.boundingBox();
      expect(box).not.toBeNull();
      await page.screenshot({ path: `${OUT}/addhost-footer-disabled-${theme}.png`, clip: box! });
      await page.locator(".ah-row[data-host='o2']").click();
      await page.waitForTimeout(400);
      await page.screenshot({ path: `${OUT}/addhost-footer-enabled-${theme}.png`, clip: (await foot.boundingBox())! });
    });
  }
});
