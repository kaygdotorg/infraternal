/**
 * The host-removal confirmation belongs to what it acts on (TASTE: "A confirmation belongs to what it acts on"; owner,
 * 2026-11-06: "wtf?" and "it's just that the removal design is really bad!", #391), and it stays glass that shows colour
 * and never legible text (TASTE: "Glass shows colour, never legible text"; owner: "Keep glass, fix contrast").
 *
 * On the clusters prototype (scene 1) with `?removal=1`, every terminal shows a dense `ls -la` listing (the live terminal
 * is written to, the preview windows are filled), another host's window is focused, and "Remove host: <other>" is started
 * from the palette, at every card transparency level the user can pick. The confirmation must: be centred, compact and not
 * hang on the focused window's pill, have two plain buttons ("Remove", "Keep") side by side inside the card (44 px high on
 * a phone, which these cases run as a touch device), put the full host name in the title, and keep every character behind
 * it illegible (`glyph-legibility.ts`: the strokes of the unblurred text must not survive in the glass). Escape returns
 * focus to where it was, and Enter right after opening keeps the host.
 */
import { expect, test } from "playwright/test";
import { type CardPixels, LEVELS, measureOpenCard, openDenseConsole, openRemovalOverDenseTerminal, SIZES, startRemovalFromPalette, startRemovalFromSidebar, THEMES } from "./removal-fixture";

/** Above this correlation with the unblurred text (whole card, rim included), characters are still legible through the glass. */
const LEGIBLE_CORRELATION = 0.15;
/** The same limit for the card's outer 14 px rim alone, where the blur of a small card used to fade out. */
const LEGIBLE_RIM_CORRELATION = 0.3;
/** Below this stroke energy behind the card the case proved nothing: the card must sit over dense text. */
const MIN_TEXT_BEHIND_PALETTE = 30;
/** The same floor for the sidebar-started card, set from measurement (see the numbers in the issue). */
const MIN_TEXT_BEHIND_SIDEBAR = 8;
/** Above this correlation of colour and shape with a coloured block behind it, the card shows its surroundings: it is glass. */
const GLASS_COLOUR_CORRELATION = 0.4;
/** At or below this the card shows none of what is behind it: it is opaque. */
const OPAQUE_COLOUR_CORRELATION = 0.2;

/**
 * The glass checks for one open card: no character legible through the whole card or its rim, dense text really behind it
 * (so a card over a blank part of the terminal cannot pass), and at the translucent levels colour and shape from behind
 * showing through (so an opaque card cannot pass as glass); the Solid level is opaque by design and must show none.
 */
function expectGlass(label: string, pixels: CardPixels, level: string, minTextBehind: number): void {
  const { text, colour } = pixels;
  const numbers = `corr ${text.corr.toFixed(3)}, rim ${text.ringCorr.toFixed(3)}, inner ${text.innerCorr.toFixed(3)}, text behind ${text.behindRms.toFixed(2)}, colour ${colour.corr.toFixed(3)}`;
  console.log(`LEGIBILITY ${label}: ${numbers}`);
  expect(text.behindRms, `the test has teeth: dense text sits behind the card (${numbers})`).toBeGreaterThan(minTextBehind);
  expect(text.corr, `no character behind the card is legible (${numbers})`).toBeLessThan(LEGIBLE_CORRELATION);
  expect(text.ringCorr, `no character is legible in the card's rim (${numbers})`).toBeLessThan(LEGIBLE_RIM_CORRELATION);
  if (level === "solid") expect(colour.corr, `Solid is opaque (${numbers})`).toBeLessThan(OPAQUE_COLOUR_CORRELATION);
  else expect(colour.corr, `the card is glass: colour and shape from behind show through (${numbers})`).toBeGreaterThan(GLASS_COLOUR_CORRELATION);
}

for (const size of SIZES) for (const theme of THEMES) for (const level of LEVELS) test(`removal from the palette ${size.id} ${theme} ${level}: centred, plain buttons, no legible text behind`, async ({ browser }) => {
  const context = await browser.newContext({ viewport: { width: size.width, height: size.height }, deviceScaleFactor: 2, hasTouch: size.touch, isMobile: size.touch });
  const page = await context.newPage();
  try {
    const removed = await openRemovalOverDenseTerminal(page, theme, level);
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
      const byId = (id: string | null): string | undefined => (id ? document.getElementById(id)?.textContent ?? undefined : undefined);
      return {
        side: tip.dataset.side, box: { l: box.left, r: box.right, t: box.top, b: box.bottom, w: box.width, cx: box.left + box.width / 2, cy: box.top + box.height / 2 },
        yes: { l: yb.left, r: yb.right, t: yb.top, b: yb.bottom, h: yb.height, text: yes.textContent }, no: { l: nb.left, r: nb.right, t: nb.top, b: nb.bottom, h: nb.height, text: no.textContent },
        pill: { l: pill.left, r: pill.right, t: pill.top, b: pill.bottom }, spans, vw: innerWidth, vh: innerHeight,
        title: tip.querySelector(".ui-confirm-tip-message")!.textContent, yesLabel: yes.getAttribute("aria-label"),
        labelledBy: byId(tip.getAttribute("aria-labelledby")), describedBy: byId(tip.getAttribute("aria-describedby")),
        coarse: matchMedia("(pointer: coarse)").matches, rem: parseFloat(getComputedStyle(document.documentElement).fontSize),
      };
    });
    expect(m.side, "started from the palette: centred, no tail").toBe("center");
    expect(Math.abs(m.box.cx - m.vw / 2), "centred horizontally").toBeLessThanOrEqual(1);
    expect(Math.abs(m.box.cy - m.vh / 2), "centred vertically").toBeLessThanOrEqual(1);
    expect(m.box.w, "as compact as an anchored card (the 21.25rem cap)").toBeLessThanOrEqual(21.25 * m.rem + 0.5);
    const touchesPill = Math.abs((m.box.l + m.box.r) / 2 - (m.pill.l + m.pill.r) / 2) < 2 && Math.abs(m.box.t - m.pill.b) < 24;
    expect(touchesPill, "not hung on the focused window's pill").toBe(false);
    expect(m.title, "the full host name is in the title").toBe(`Remove ${removed}?`);
    expect(m.labelledBy, "the dialog is named by its title").toBe(m.title);
    expect(m.describedBy, "the dialog is described by its effect line").toContain("Revokes its access");
    expect(m.yes.text, "the button is the plain verb").toBe("Remove");
    expect(m.yesLabel).toBe("Remove");
    expect(m.no.text).toBe("Keep");
    expect(m.no.r, "cancel sits beside confirm").toBeLessThanOrEqual(m.yes.l + 1);
    expect(Math.abs((m.no.t + m.no.b) / 2 - (m.yes.t + m.yes.b) / 2), "same centre line").toBeLessThanOrEqual(0.5);
    for (const b of [m.yes, m.no]) {
      expect(b.l, "button inside the card, left").toBeGreaterThanOrEqual(m.box.l);
      expect(b.r, "button inside the card, right").toBeLessThanOrEqual(m.box.r + 0.5);
      expect(b.b, "button inside the card, bottom").toBeLessThanOrEqual(m.box.b);
      if (size.touch) expect(b.h, "a touch target is at least 44 px").toBeGreaterThanOrEqual(43.5);
    }
    expect(m.coarse, `${size.id} runs as a ${size.touch ? "touch" : "mouse"} device`).toBe(size.touch);
    for (const s of m.spans) expect(s.scroll, `${s.text} is not clipped`).toBeLessThanOrEqual(s.client + 1);
    expect(m.box.l, "inside the viewport").toBeGreaterThanOrEqual(0);
    expect(m.box.r).toBeLessThanOrEqual(m.vw);

    const pixels = await measureOpenCard(page, `${size.id}-${theme}-${level}`);
    expectGlass(`${size.id} ${theme} ${level}`, pixels, level, MIN_TEXT_BEHIND_PALETTE);
  } finally { await context.close(); }
});

/** The card started from the sidebar's host row is anchored to that row and is glass too (same checks, a lower text floor: the sidebar's own rows are half of what is behind it). */
for (const size of SIZES) for (const theme of THEMES) for (const level of ["tinted", "frosted"] as const) test(`removal from the sidebar ${size.id} ${theme} ${level}: anchored, no legible text behind`, async ({ browser }) => {
  const context = await browser.newContext({ viewport: { width: size.width, height: size.height }, deviceScaleFactor: 2, hasTouch: size.touch, isMobile: size.touch });
  const page = await context.newPage();
  try {
    await openDenseConsole(page, theme, level);
    await startRemovalFromSidebar(page);
    // sleep: the open animation (scale 0.96 to 1) must finish before boxes and pixels are measured
    await page.waitForTimeout(400);
    const side = await page.locator(".ui-confirm-tip").getAttribute("data-side");
    expect(["top", "bottom"], "anchored to the host's own row, with a tail").toContain(side);
    expect(await page.locator(".ui-confirm-tip-message").textContent()).toBe("Remove edge-arm?");
    const pixels = await measureOpenCard(page, `sidebar-${size.id}-${theme}-${level}`);
    expectGlass(`sidebar ${size.id} ${theme} ${level}`, pixels, level, MIN_TEXT_BEHIND_SIDEBAR);
  } finally { await context.close(); }
});

test("Escape returns focus to where it was, and Enter right after opening keeps the host", async ({ browser }) => {
  const context = await browser.newContext({ viewport: { width: 1440, height: 900 }, deviceScaleFactor: 2 });
  const page = await context.newPage();
  try {
    // Click into the live terminal, as a person would, so the palette opens from a focused terminal and focus has somewhere to return to.
    await openDenseConsole(page, "ink", "tinted");
    await page.locator("#terminal-host").click({ timeout: 5_000 });
    const before = await page.evaluate(() => { const el = document.activeElement as HTMLElement; el.dataset.j300Focus = "1"; return el.tagName; });
    expect(before, "the terminal held focus before the palette opened").not.toBe("BODY");
    await startRemovalFromPalette(page);
    const tip = page.locator(".ui-confirm-tip");
    await expect(tip).toBeVisible();
    await expect(tip.locator(".ui-confirm-no")).toBeFocused();
    await page.keyboard.press("Escape");
    await expect(tip).toHaveCount(0);
    const after = await page.evaluate(() => { const el = document.activeElement as HTMLElement; return { marked: el.dataset.j300Focus, what: `${el.tagName}#${el.id}.${el.className}` }; });
    expect(after.marked, `Escape returns focus to the terminal (focus is on ${after.what})`).toBe("1");

    // Enter pressed as soon as the card opens, before focus has landed on Keep, and again once it has: the host stays.
    await test.step("open the palette again", async () => {
      await page.keyboard.press("Control+Shift+K");
      await page.locator("#palette-input").fill("Remove host", { timeout: 10_000 });
      await expect(page.locator(".palette .result", { hasText: "Remove host:" }).first()).toBeVisible();
    });
    await test.step("Enter twice, the second before focus lands on Keep", async () => {
      await page.keyboard.press("Enter");
      await page.keyboard.press("Enter");
    });
    await expect(page.locator(".ui-toast", { hasText: "would be removed" })).toHaveCount(0);
    await test.step("Enter on Keep, once the card shows", async () => {
      if (await tip.count()) {
        await expect(tip.locator(".ui-confirm-no")).toBeFocused({ timeout: 5_000 });
        await page.keyboard.press("Enter");
        await expect(tip).toHaveCount(0);
      }
    });
    await expect(page.locator(".ui-toast", { hasText: "would be removed" })).toHaveCount(0);
  } finally { await context.close(); }
});
