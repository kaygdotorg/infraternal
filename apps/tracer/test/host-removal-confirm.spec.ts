/**
 * The host-removal confirmation belongs to what it acts on (TASTE: "A confirmation belongs to what it acts on"; owner,
 * 2026-11-06: "wtf?" and "it's just that the removal design is really bad!", #391).
 *
 * On the clusters prototype (scene 1) with `?removal=1`, every terminal shows a dense `ls -la` listing (the live terminal
 * is written to, the preview windows are filled), another host's window is focused, and "Remove host: <other>" is started
 * from the palette. The confirmation must: be centred and not hang on the focused window's pill, have two plain
 * buttons ("Remove", "Keep") side by side inside the card, put the full host name in the title, and be a solid card:
 * the pixels inside it are the same with the terminal text visible and with it hidden. That last check reads pixels,
 * because a computed `backdrop-filter` said "blurred" while the text stayed readable through it in a production build.
 * Pressing Enter right after the card opens keeps the host (focus starts on "Keep").
 */
import { expect, test, type Page } from "playwright/test";
import { tracerEvidencePath } from "./evidence-path";

/** The three review viewports: desktop, an iPhone and a small phone. */
const sizes = [{ id: "desktop", width: 1440, height: 900 }, { id: "phone", width: 393, height: 852 }, { id: "small-phone", width: 375, height: 667 }] as const;
/** Both card themes the owner reviews. */
const themes = ["ink", "paper"] as const;

/** A dense directory listing, long enough to fill a window on every viewport and wide enough to run under the whole card. */
function listing(): string[] {
  const names = [".bash_history", ".bashrc", ".bashrc.bak-20261102T061545", "10-lan-links.conf", "authorized_keys", "infraternal", "infraternal.toml", ".profile", "notes.md", "build.log"];
  return Array.from({ length: 80 }, (_, i) => `-rw-r--r--. ${1 + (i % 4)} root root ${String(100 + i * 137).padStart(6)} Nov ${String(1 + (i % 6)).padStart(2)} 1${i % 10}:${String(10 + (i % 50))} ${names[i % names.length]}-${i}`);
}

/**
 * Opens the clusters mockup, flies into the Console view, fills every terminal with the dense listing, and starts
 * "Remove host" for a host other than the focused window's from the palette. Returns the removed host's name.
 */
async function startRemovalFromPalette(page: Page, theme: string): Promise<string> {
  await page.context().request.post("/__mock/reset").catch(() => undefined);
  await page.goto(`/?mock=1&proto=clusters&scene=1&bg=none&removal=1&theme=${theme}`);
  await expect(page.locator(".ui-window").nth(1)).toBeVisible({ timeout: 30_000 });
  await page.keyboard.press("Control+Shift+K");
  await expect(page.locator("#palette-input")).toBeFocused();
  await page.locator("#palette-input").fill("Console");
  await page.locator('.palette .result[data-action^="canvas:view"]').first().click();
  // sleep: the camera flight into the Console view must land before text is written and the palette opens again
  await page.waitForTimeout(1500);
  // The hook appears once the live terminal has connected.
  await page.waitForFunction(() => (window as unknown as { __tracerTestDouble?: unknown }).__tracerTestDouble !== undefined, undefined, { timeout: 30_000 });
  const lines = listing();
  await page.evaluate(async (rows) => {
    const hook = (window as unknown as { __tracerTestDouble?: { writeText(text: string): Promise<void> } }).__tracerTestDouble;
    if (!hook) throw new Error("the test double's terminal hook is missing");
    await hook.writeText(`${rows.join("\r\n")}\r\n`);
    for (const pre of document.querySelectorAll<HTMLElement>(".cl-preview")) pre.textContent = rows.join("\n");
  }, lines);
  const focusedPill = (await page.locator(".ui-window").first().locator(".ui-window-pill").innerText()).toLowerCase();
  await page.keyboard.press("Control+Shift+K");
  await expect(page.locator("#palette-input")).toBeFocused();
  await page.locator("#palette-input").fill("Remove host");
  const rows = page.locator(".palette .result");
  await expect(rows.filter({ hasText: "Remove host:" }).first()).toBeVisible();
  // The palette redraws its rows while it filters, so read the names until one that is not the focused window's shows.
  let other: string | undefined;
  await expect.poll(async () => {
    const labels = await rows.allInnerTexts();
    other = labels.map((text) => /Remove host:\s*([^\s\n]+)/.exec(text)?.[1]).find((name) => name && !focusedPill.includes(name.toLowerCase()));
    return other;
  }, { message: `a host other than the focused window's is offered (focused pill: ${focusedPill})` }).toBeTruthy();
  await page.locator("#palette-input").fill(`Remove host: ${other}`);
  await page.keyboard.press("Enter");
  return other!;
}

for (const size of sizes) for (const theme of themes) test(`removal from the palette ${size.id} ${theme}: centred, plain buttons, solid over dense text`, async ({ page }) => {
  await page.setViewportSize({ width: size.width, height: size.height });
  const removed = await startRemovalFromPalette(page, theme);
  const tip = page.locator(".ui-confirm-tip");
  await expect(tip).toBeVisible();
  await expect(tip).toHaveAttribute("data-open", "true");
  // sleep: the open animation (scale 0.96 to 1) must finish before boxes and pixels are measured
  await page.waitForTimeout(400);
  const m = await page.evaluate(() => {
    const tip = document.querySelector<HTMLElement>(".ui-confirm-tip")!;
    const box = tip.getBoundingClientRect();
    const yes = tip.querySelector<HTMLElement>(".ui-confirm-yes")!, no = tip.querySelector<HTMLElement>(".ui-confirm-no")!;
    const yb = yes.getBoundingClientRect(), nb = no.getBoundingClientRect();
    const pill = document.querySelector<HTMLElement>(".ui-window .ui-window-pill")!.getBoundingClientRect();
    const spans = [yes, no].map((button) => { const s = button.querySelector<HTMLElement>("span")!; return { text: s.textContent, scroll: s.scrollWidth, client: s.clientWidth }; });
    return {
      side: tip.dataset.side, box: { l: box.left, r: box.right, t: box.top, b: box.bottom, cx: box.left + box.width / 2, cy: box.top + box.height / 2 },
      yes: { l: yb.left, r: yb.right, t: yb.top, b: yb.bottom, text: yes.textContent }, no: { l: nb.left, r: nb.right, t: nb.top, b: nb.bottom, text: no.textContent },
      pill: { l: pill.left, r: pill.right, t: pill.top, b: pill.bottom }, spans, vw: innerWidth, vh: innerHeight,
      title: tip.querySelector(".ui-confirm-tip-message")!.textContent, yesLabel: yes.getAttribute("aria-label"),
    };
  });
  expect(m.side, "started from the palette: centred, no tail").toBe("center");
  expect(Math.abs(m.box.cx - m.vw / 2), "centred horizontally").toBeLessThanOrEqual(1);
  expect(Math.abs(m.box.cy - m.vh / 2), "centred vertically").toBeLessThanOrEqual(1);
  const touchesPill = Math.abs((m.box.l + m.box.r) / 2 - (m.pill.l + m.pill.r) / 2) < 2 && Math.abs(m.box.t - m.pill.b) < 24;
  expect(touchesPill, "not hung on the focused window's pill").toBe(false);
  expect(m.title, "the full host name is in the title").toBe(`Remove ${removed}?`);
  expect(m.yes.text, "the button is the plain verb").toBe("Remove");
  expect(m.yesLabel).toBe("Remove");
  expect(m.no.text).toBe("Keep");
  expect(m.no.r, "cancel sits beside confirm").toBeLessThanOrEqual(m.yes.l + 1);
  expect(Math.abs((m.no.t + m.no.b) / 2 - (m.yes.t + m.yes.b) / 2), "same centre line").toBeLessThanOrEqual(0.5);
  for (const b of [m.yes, m.no]) {
    expect(b.l, "button inside the card, left").toBeGreaterThanOrEqual(m.box.l);
    expect(b.r, "button inside the card, right").toBeLessThanOrEqual(m.box.r + 0.5);
    expect(b.b, "button inside the card, bottom").toBeLessThanOrEqual(m.box.b);
  }
  for (const s of m.spans) expect(s.scroll, `${s.text} is not clipped`).toBeLessThanOrEqual(s.client + 1);
  expect(m.box.l, "inside the viewport").toBeGreaterThanOrEqual(0);
  expect(m.box.r).toBeLessThanOrEqual(m.vw);

  // Pixels: the card with the dense text visible, then the same card with the stage (all terminal text) hidden.
  const withText = await page.screenshot({ path: tracerEvidencePath("removal-confirm", `${size.id}-${theme}.png`), animations: "disabled" });
  await page.addStyleTag({ content: "#terminal-screen { visibility: hidden !important; }" });
  await page.evaluate(() => new Promise<void>((done) => requestAnimationFrame(() => requestAnimationFrame(() => done()))));
  const withoutText = await page.screenshot({ animations: "disabled" });
  const diff = await page.evaluate(async ({ a, b, rect }) => {
    const load = async (data: string): Promise<ImageData> => {
      const image = await createImageBitmap(await (await fetch(`data:image/png;base64,${data}`)).blob());
      const canvas = new OffscreenCanvas(image.width, image.height);
      const context = canvas.getContext("2d")!;
      context.drawImage(image, 0, 0);
      return context.getImageData(0, 0, image.width, image.height);
    };
    const [x, y] = [await load(a), await load(b)];
    const scale = x.width / innerWidth;
    // Inside the card, inset by 8 px so its rounded corners (14 px radius), shadow and edge antialiasing never count.
    const l = Math.round((rect.l + 8) * scale), r = Math.round((rect.r - 8) * scale), t = Math.round((rect.t + 8) * scale), bt = Math.round((rect.b - 8) * scale);
    let inside = 0, outside = 0;
    const where: string[] = [];
    for (let row = 0; row < x.height; row++) for (let col = 0; col < x.width; col++) {
      const i = (row * x.width + col) * 4;
      const delta = Math.max(Math.abs(x.data[i]! - y.data[i]!), Math.abs(x.data[i + 1]! - y.data[i + 1]!), Math.abs(x.data[i + 2]! - y.data[i + 2]!));
      // A leak of terminal text changes thousands of pixels by far more than this; antialiasing of a button edge changes a few by 4 or 5 of 255.
      if (delta <= 7) continue;
      if (col >= l && col < r && row >= t && row < bt) { inside++; if (where.length < 6) where.push(`${col},${row} d=${delta}`); } else outside++;
    }
    return { inside, outside, where };
  }, { a: withText.toString("base64"), b: withoutText.toString("base64"), rect: m.box });
  expect(diff.outside, "the test has teeth: dense text is on screen around the card").toBeGreaterThan(2000);
  expect(diff.inside, `no pixel inside the card changes when the text behind it is hidden (first at ${diff.where.join(" | ")}; card ${JSON.stringify(m.box)})`).toBe(0);
});

test("Enter right after the confirmation opens keeps the host", async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 900 });
  await startRemovalFromPalette(page, "ink");
  const tip = page.locator(".ui-confirm-tip");
  await expect(tip).toBeVisible();
  await expect(tip.locator(".ui-confirm-no")).toBeFocused();
  await page.keyboard.press("Enter");
  await expect(tip).toHaveCount(0);
  await expect(page.locator(".ui-toast", { hasText: "would be removed" })).toHaveCount(0);
});
