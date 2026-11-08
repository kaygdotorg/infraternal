/**
 * Keyboard opens instantly (#427; owner, 2026-11-08): a surface opened or closed from a keyboard shortcut (the command palette
 * on ⌘K, the shortcuts panel on ⌘/ and `?`) appears and disappears with no animation at all, while the same surface opened
 * with the pointer keeps its motion. The trigger source of the event that flips the state decides, for both directions, so a
 * pointer close of a keyboard-opened surface may animate and a keyboard close of a pointer-opened one must not.
 *
 * Each check samples the very first animation frame after the event: the surface must already be in its final state
 * (fully opaque and unclipped on open, gone on close) and no CSS transition may be running on it or on the top-bar controls
 * it covers. Runs at a desktop and a phone viewport, both with a hardware keyboard, against the test double's canvas.
 */
import { expect, test, type Page } from "playwright/test";

/** The state of the surfaces in the first frame after the sampled event. */
interface Frame {
  paletteHidden: boolean;
  paletteOpacity: string;
  paletteTransform: string;
  scrimOpacity: string | null;
  /** Running CSS transitions on the palette, its scrim, the shortcuts panel and the top-bar pills. */
  running: string[];
  panelPresent: boolean;
  panelClip: string | null;
  panelContentOpacity: string | null;
  capsuleOpacity: string;
}

/** The two sizes every check runs at: a desktop window and a phone, both driven with a hardware keyboard. */
const VIEWPORTS = [{ name: "desktop 1440x900", width: 1440, height: 900 }, { name: "phone 393x852", width: 393, height: 852 }];
/** The chord that opens the command palette on the (non-Mac) test browser. */
const PALETTE_KEY = "Control+Shift+K";
/** The two ways to open the shortcuts panel: the bare question mark and the chord that also works inside a terminal. */
const SHORTCUTS_KEYS = ["?", "Control+Shift+/"];

/** Loads the test double's canvas, waits for its windows, and blurs the terminal so single-key shortcuts such as `?` reach the page. */
async function openCanvas(page: Page): Promise<void> {
  await page.context().request.post("/__mock/reset").catch(() => page.context().request.post("/__mock/reset"));
  await page.goto("/?mock=1&proto=windows&bg=none&fixture=none");
  await expect.poll(() => page.evaluate(() => window.__tracerTestDouble?.isConnected() === true), { timeout: 30_000 }).toBe(true);
  await expect.poll(() => page.evaluate(() => (window as unknown as { __tracerCanvas?: { windows(): string[] } }).__tracerCanvas?.windows().length ?? 0)).toBeGreaterThan(2);
  await page.evaluate(() => (document.activeElement as HTMLElement | null)?.blur());
}

/**
 * Arms a one-shot sampler: on the next non-modifier keydown or pointerdown (capture, before any handler) it waits for the first animation
 * frame and records the surfaces' state in `window.__frame`. Returns nothing; read it back with {@link frame}.
 */
async function arm(page: Page): Promise<void> {
  await page.evaluate(() => {
    const w = window as unknown as { __frame?: unknown };
    w.__frame = undefined;
    const sample = (): void => {
      const palette = document.querySelector<HTMLElement>("#palette")!;
      const scrim = document.querySelector<HTMLElement>(".palette-scrim");
      const panel = document.querySelector<HTMLElement>(".ui-shortcuts");
      const running = document.getAnimations().filter((a) => a instanceof CSSTransition && a.playState === "running")
        .map((a) => `${(a as CSSTransition).transitionProperty} on ${(a.effect as KeyframeEffect).target instanceof Element ? ((a.effect as KeyframeEffect).target as Element).className : "?"}`)
        .filter((text) => /palette|ui-shortcuts|capsule|tab-add|sidebar-toggle|glass-bed/.test(text));
      w.__frame = {
        // The computed display, not the `hidden` attribute: a fading palette keeps `display` until its fade ends.
        paletteHidden: getComputedStyle(palette).display === "none",
        paletteOpacity: getComputedStyle(palette).opacity,
        paletteTransform: getComputedStyle(palette).transform,
        scrimOpacity: scrim ? getComputedStyle(scrim).opacity : null,
        running,
        panelPresent: panel !== null,
        panelClip: panel ? getComputedStyle(panel).clipPath : null,
        panelContentOpacity: panel ? getComputedStyle(panel.querySelector(".ui-shortcuts-body")!).opacity : null,
        capsuleOpacity: getComputedStyle(document.querySelector("#capsule")!).opacity,
      } satisfies Frame;
    };
    // One trigger arms it: whichever of the two listeners fires first removes both, so a stale one never resamples a later step.
    const off = new AbortController();
    const arm = (): void => { off.abort(); requestAnimationFrame(sample); };
    // A chord such as Control+Shift+K sends a keydown for each modifier first. Arming on those would start the sampler before
    // the shortcut's own key, so a slow open could look finished by timing alone: arm on the chord's final, non-modifier key.
    const modifiers = new Set(["Control", "Shift", "Alt", "Meta", "AltGraph"]);
    window.addEventListener("keydown", (event) => { if (!modifiers.has(event.key)) arm(); }, { capture: true, signal: off.signal });
    window.addEventListener("pointerdown", arm, { capture: true, signal: off.signal });
  });
}

/** The frame recorded by the armed sampler, once it has run. */
async function frame(page: Page): Promise<Frame> {
  await expect.poll(() => page.evaluate(() => (window as unknown as { __frame?: unknown }).__frame !== undefined)).toBe(true);
  return page.evaluate(() => (window as unknown as { __frame: Frame }).__frame);
}

/** Opens the palette from the keyboard and checks the first frame is final, with nothing running. */
async function expectPaletteOpenInstant(page: Page): Promise<void> {
  await arm(page);
  await page.keyboard.press(PALETTE_KEY);
  const f = await frame(page);
  expect(f.paletteHidden).toBe(false);
  expect(f.paletteOpacity, "palette opacity in the first frame after the key").toBe("1");
  expect(f.paletteTransform, "palette scale in the first frame after the key").not.toMatch(/matrix\(0\.9/);
  expect(f.scrimOpacity).toBe("1");
  expect(f.running, "transitions running after the key").toEqual([]);
}

for (const viewport of VIEWPORTS) {
  test.describe(viewport.name, () => {
    test.beforeEach(async ({ page }) => {
      await page.setViewportSize({ width: viewport.width, height: viewport.height });
      await openCanvas(page);
    });

    test("the palette opens and closes from the keyboard with no animation", async ({ page }) => {
      await expectPaletteOpenInstant(page);
      await arm(page);
      await page.keyboard.press("Escape");
      const closed = await frame(page);
      expect(closed.paletteHidden, "palette is gone in the first frame after Escape").toBe(true);
      expect(closed.running).toEqual([]);
      expect(closed.capsuleOpacity, "the covered capsule is back at once").toBe("1");
      // Toggling with the same chord is instant too.
      await expectPaletteOpenInstant(page);
      await arm(page);
      await page.keyboard.press(PALETTE_KEY);
      expect((await frame(page)).paletteHidden).toBe(true);
    });

    for (const key of SHORTCUTS_KEYS) test(`the shortcuts panel opens and closes from ${key} with no animation`, async ({ page }) => {
      await arm(page);
      await page.keyboard.press(key);
      const open = await frame(page);
      expect(open.panelPresent).toBe(true);
      expect(open.panelClip, "panel is unclipped in the first frame after the key").toBe("none");
      expect(open.panelContentOpacity).toBe("1");
      expect(open.capsuleOpacity, "the pill under the panel is already hidden").toBe("0");
      expect(open.running).toEqual([]);
      await arm(page);
      await page.keyboard.press("Escape");
      const closed = await frame(page);
      expect(closed.panelPresent, "panel is gone in the first frame after Escape").toBe(false);
      expect(closed.capsuleOpacity).toBe("1");
    });

    test("a pointer open still animates, and a keyboard close of it is instant", async ({ page }) => {
      await arm(page);
      await page.locator("#capsule").click();
      const open = await frame(page);
      expect(open.paletteHidden).toBe(false);
      expect(Number(open.paletteOpacity), "pointer open fades in").toBeLessThan(1);
      await expect(page.locator("#palette")).toHaveCSS("opacity", "1");
      await arm(page);
      await page.keyboard.press("Escape");
      expect((await frame(page)).paletteHidden, "keyboard close of a pointer-opened palette").toBe(true);
    });

    test("a pointer close of a keyboard-opened palette animates", async ({ page }) => {
      await expectPaletteOpenInstant(page);
      await arm(page);
      await page.locator(".palette-scrim").click({ position: { x: 4, y: viewport.height - 4 } });
      const f = await frame(page);
      expect(f.paletteHidden ? "hidden at once" : "fading").toBe("fading");
      await expect(page.locator("#palette")).toBeHidden();
    });

    test("the first keystroke after the palette chord lands", async ({ page }) => {
      await page.keyboard.press(PALETTE_KEY);
      await page.keyboard.type("thm", { delay: 0 });
      await expect(page.locator("#palette-input")).toHaveValue("thm");
    });
  });
}

/**
 * A modifier key on its own is not a shortcut: pressing Shift 60 ms into a pointer-opened palette must not cut its fade short
 * (J373 review of #427). The palette's opacity transition has to run its whole length, and never be cancelled.
 */
test("Shift pressed during a pointer open does not cut the fade short", async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 900 });
  await openCanvas(page);
  await page.evaluate(() => {
    const palette = document.querySelector("#palette")!;
    const log: { run?: number; end?: number; cancelled: boolean } = { cancelled: false };
    (window as unknown as { __fade: typeof log }).__fade = log;
    palette.addEventListener("transitionrun", (e) => { if ((e as TransitionEvent).propertyName === "opacity" && log.run === undefined) log.run = performance.now(); });
    palette.addEventListener("transitionend", (e) => { if ((e as TransitionEvent).propertyName === "opacity") log.end = performance.now(); });
    palette.addEventListener("transitioncancel", (e) => { if ((e as TransitionEvent).propertyName === "opacity") log.cancelled = true; });
  });
  await page.locator("#capsule").click();
  // sleep: let the pointer-opened fade get 60 ms in, as the reviewer did, before the modifier arrives
  await page.waitForTimeout(60);
  await page.keyboard.down("Shift");
  await expect.poll(() => page.evaluate(() => (window as unknown as { __fade: { end?: number } }).__fade.end !== undefined)).toBe(true);
  await page.keyboard.up("Shift");
  const fade = await page.evaluate(() => (window as unknown as { __fade: { run: number; end: number; cancelled: boolean } }).__fade);
  expect(fade.cancelled, "the fade was cancelled").toBe(false);
  expect(fade.end - fade.run, "the fade ran its whole length (about 240 ms)").toBeGreaterThan(200);
});
