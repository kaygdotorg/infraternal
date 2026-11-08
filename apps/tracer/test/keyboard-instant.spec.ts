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

/**
 * A camera flight started by a key (Control+Shift+digit, or a view picked in the palette by keyboard) jumps to its view in the
 * same frame, with no spring (#427; owner: "actions originating from keyboard shortcuts = no animation"). The same flight
 * started by a pointer click on the view list keeps flying, so its first frame is still short of where it ends.
 */
test("a camera flight from a key jumps at once, a pointer one still flies", async ({ page }) => {
  await page.setViewportSize({ width: 1280, height: 800 });
  await page.goto("/?mock=1&proto=clusters&scene=3&theme=ink&bg=soft");
  await expect(page.locator(".cl-mockup")).toBeVisible({ timeout: 20_000 });
  const camera = (): Promise<{ cx: number; cy: number; z: number }> => page.evaluate(() => (window as unknown as { __tracerClusters: { camera(): { cx: number; cy: number; z: number } } }).__tracerClusters.camera());
  /** The camera one animation frame after the trigger ran, then once it has certainly settled. */
  const firstFrameThenFinal = async (trigger: () => Promise<void>): Promise<{ first: { cx: number; cy: number; z: number }; final: { cx: number; cy: number; z: number } }> => {
    await trigger();
    const first = await page.evaluate(() => new Promise<{ cx: number; cy: number; z: number }>((resolve) => requestAnimationFrame(() => resolve((window as unknown as { __tracerClusters: { camera(): { cx: number; cy: number; z: number } } }).__tracerClusters.camera()))));
    // sleep: a flight is at most about 400 ms; wait it out so the end position is known
    await page.waitForTimeout(1200);
    return { first, final: await camera() };
  };
  // sleep: let the mockup's opening motion finish before the first measurement
  await page.waitForTimeout(1200);
  const moved = (a: { cx: number; cy: number; z: number }, b: { cx: number; cy: number; z: number }): boolean => Math.abs(a.cx - b.cx) * b.z > 1 || Math.abs(a.cy - b.cy) * b.z > 1 || Math.abs(a.z - b.z) > 0.001;
  const start = await camera();
  const key = await firstFrameThenFinal(() => page.keyboard.press("Control+Shift+Digit3"));
  expect(moved(start, key.final), "the key flight went somewhere").toBe(true);
  expect(moved(key.first, key.final), "key flight: the camera is already at its end one frame after the key").toBe(false);
  // Pointer: the capsule opens the view list and a row is clicked.
  await page.locator("#capsule").click();
  // sleep: the pointer-opened palette grows in for 240 ms
  await page.waitForTimeout(700);
  const pointer = await firstFrameThenFinal(async () => { await page.locator(".cl-viewlist li, .cl-viewrow").nth(0).click(); });
  expect(moved(key.final, pointer.final), "the pointer flight went somewhere").toBe(true);
  expect(moved(pointer.first, pointer.final), "pointer flight: the camera is still on its way one frame after the click").toBe(true);
});

// ---- round 3 (J378 review of #427): the rule is central, so no key-triggered motion is left behind ----------------------------

/** A camera position as the clusters mockup reports it. */
type Cam = { cx: number; cy: number; z: number };

/** True for a `clip-path` that hides nothing: none, or an inset of 0 on every side (a morph at rest may leave the second form). */
const clipIsWhole = (clip: string): boolean => clip === "none" || [...clip.replace(/round.*$/, "").matchAll(/-?[\d.]+/g)].every((n) => Math.abs(Number(n[0])) < 0.5);

/** Loads the clusters mockup (the view list, the camera and the palette's view picks) and waits for it to settle. */
async function openClusters(page: Page): Promise<void> {
  await page.setViewportSize({ width: 1280, height: 800 });
  await page.goto("/?mock=1&proto=clusters&scene=3&theme=ink&bg=soft");
  await expect(page.locator(".cl-mockup")).toBeVisible({ timeout: 20_000 });
  // sleep: let the mockup's opening motion finish before the first measurement
  await page.waitForTimeout(1500);
  await page.evaluate(() => (document.activeElement as HTMLElement | null)?.blur());
}

/** The camera as the clusters mockup reports it right now. */
const cameraOf = (page: Page): Promise<Cam> => page.evaluate(() => (window as unknown as { __tracerClusters: { camera(): Cam } }).__tracerClusters.camera());
/** True when two camera positions differ by more than a pixel on screen (or a little zoom). */
const moved = (a: Cam, b: Cam): boolean => Math.abs(a.cx - b.cx) * b.z > 1 || Math.abs(a.cy - b.cy) * b.z > 1 || Math.abs(a.z - b.z) > 0.001;

/**
 * Runs `trigger` (a key press) while sampling the camera on every animation frame, and returns the camera before it, once the
 * flight has certainly ended, and how many sampled frames showed a position strictly between the two. A jump has none. (The
 * palette loads the code for its actions on first use, so a jump can land a few frames after the key; what matters is that
 * the camera never shows a position on the way.)
 */
async function flight(page: Page, trigger: () => Promise<void>): Promise<{ before: Cam; final: Cam; inBetween: number }> {
  const before = await cameraOf(page);
  await page.evaluate(() => {
    const w = window as unknown as { __cams: Cam[]; __tracerClusters: { camera(): Cam } };
    w.__cams = [];
    const t0 = performance.now();
    const tick = (): void => { w.__cams.push({ ...w.__tracerClusters.camera() }); if (performance.now() - t0 < 2200) requestAnimationFrame(tick); };
    requestAnimationFrame(tick);
  });
  await trigger();
  // sleep: the slowest flight measured is about 600 ms; the sampler runs 2.2 s, so wait it out
  await page.waitForTimeout(2400);
  const cams = await page.evaluate(() => (window as unknown as { __cams: Cam[] }).__cams);
  const final = cams[cams.length - 1]!;
  return { before, final, inBetween: cams.filter((c) => moved(c, before) && moved(c, final)).length };
}

test.describe("every camera flight a key starts jumps (the rule is in Camera.flyTo)", () => {
  test.beforeEach(async ({ page }) => {
    await openClusters(page);
    await page.keyboard.press("Control+Shift+Digit3");
    // sleep: park the camera inside a view first, so Escape has somewhere to fly out from
    await page.waitForTimeout(600);
  });

  /** Picks a palette row by keyboard: the chord, the query, Enter. */
  const palettePick = (page: Page, query: string) => async (): Promise<void> => {
    await page.keyboard.press("Control+Shift+K");
    await page.keyboard.type(query, { delay: 0 });
    await expect(page.locator("#palette-results .result").first()).toBeVisible();
    await page.keyboard.press("Enter");
  };

  /** The key that parks the camera where the case under test has somewhere to go; `undefined` leaves it inside view 3. */
  type Prelude = string | undefined;
  const cases: Array<[string, Prelude, (page: Page) => () => Promise<void>]> = [
    ["Escape to the overview", undefined, (page) => () => page.keyboard.press("Escape")],
    // The canvas lock moves the camera when it starts from the overview; a view's own framing is the same either way.
    ["Control+Shift+G (canvas lock)", "Escape", (page) => () => page.keyboard.press("Control+Shift+G")],
    ["the palette's All views + Enter", undefined, (page) => palettePick(page, "all views")],
    ["a window picked in the palette + Enter", "Control+Shift+Digit1", (page) => palettePick(page, "nix-cache")],
  ];
  for (const [name, prelude, make] of cases) test(name, async ({ page }) => {
    if (prelude) {
      await page.keyboard.press(prelude);
      // sleep: let the prelude's flight (if the build still springs) end before the case starts
      await page.waitForTimeout(900);
    }
    const f = await flight(page, make(page));
    expect(moved(f.before, f.final), `${name} went somewhere`).toBe(true);
    expect(f.inBetween, `${name}: frames that showed the camera on its way`).toBe(0);
  });
});

test.describe("the pill-morph popovers open and close instantly from the keyboard", () => {
  test.beforeEach(async ({ page }) => { await openClusters(page); });

  test("Enter on the focused capsule opens the view list whole, Escape removes it", async ({ page }) => {
    await page.locator("#capsule").focus();
    await arm(page);
    await page.keyboard.press("Enter");
    const open = await page.evaluate(() => new Promise<{ present: boolean; clip: string; pill: string }>((resolve) => requestAnimationFrame(() => {
      const panel = document.querySelector<HTMLElement>(".cl-viewlist");
      resolve({ present: panel !== null, clip: panel ? getComputedStyle(panel).clipPath : "", pill: getComputedStyle(document.querySelector("#capsule")!).opacity });
    })));
    expect(open.present).toBe(true);
    expect(clipIsWhole(open.clip), `view list is whole in the first frame after Enter (clip-path: ${open.clip})`).toBe(true);
    expect(open.pill, "the pill under it is already hidden").toBe("0");
    await page.keyboard.press("Escape");
    const closed = await page.evaluate(() => new Promise<{ present: boolean; pill: string }>((resolve) => requestAnimationFrame(() => resolve({ present: document.querySelector(".cl-viewlist") !== null, pill: getComputedStyle(document.querySelector("#capsule")!).opacity }))));
    expect(closed.present, "view list is gone in the first frame after Escape").toBe(false);
    expect(closed.pill).toBe("1");
  });

  test("the view list's Search everything row opens the palette like any pointer open, and the chord stays instant", async ({ page }) => {
    await page.locator("#capsule").click();
    await expect(page.locator(".cl-viewlist")).toBeVisible();
    await page.locator(".cl-viewrow-search").click();
    // The first animation frame after the click has run: arm() would sample at the press, before the click's handler.
    const pointerOpen = await page.evaluate(() => new Promise<{ hidden: boolean; opacity: number }>((resolve) => requestAnimationFrame(() => {
      const palette = document.querySelector<HTMLElement>("#palette")!;
      resolve({ hidden: getComputedStyle(palette).display === "none", opacity: Number(getComputedStyle(palette).opacity) });
    })));
    expect(pointerOpen.hidden, "the palette opened").toBe(false);
    expect(pointerOpen.opacity, "a click on Search everything fades the palette in").toBeLessThan(1);
    await expect(page.locator("#palette")).toHaveCSS("opacity", "1");
    await page.keyboard.press("Escape");
    await expectPaletteOpenInstant(page);
  });

  test("a pointer open of the view list still morphs out of the pill", async ({ page }) => {
    await page.locator("#capsule").click();
    const first = await page.evaluate(() => new Promise<string>((resolve) => requestAnimationFrame(() => resolve(getComputedStyle(document.querySelector(".cl-viewlist")!).clipPath))));
    expect(clipIsWhole(first), `pointer open is still clipped part way in the first frame (clip-path: ${first})`).toBe(false);
  });
});

test.describe("round 3 polish", () => {
  test("a key removes the open and close motion only around the key, not until the next pointer press", async ({ page }) => {
    await page.setViewportSize({ width: 1440, height: 900 });
    await openCanvas(page);
    const capsuleTransition = (): Promise<string> => page.evaluate(() => getComputedStyle(document.querySelector("#capsule")!).transitionDuration);
    await page.locator("#capsule").click();
    await page.keyboard.press("Escape");
    // sleep: a few frames after the key, so only a rule that lasts beyond the key can still be on
    await page.waitForTimeout(150);
    expect(await capsuleTransition(), "the capsule's cover fade is back a moment after a key").not.toBe("0s");
  });

  test("Escape out of the palette returns focus to where it was", async ({ page }) => {
    await page.setViewportSize({ width: 1440, height: 900 });
    await openCanvas(page);
    await page.locator("#sidebar-toggle").focus();
    await page.keyboard.press(PALETTE_KEY);
    await expect(page.locator("#palette-input")).toBeFocused();
    await page.keyboard.press("Escape");
    await expect(page.locator("#sidebar-toggle")).toBeFocused();
  });

  test("the pointer-open palette respects reduced motion", async ({ page }) => {
    await page.emulateMedia({ reducedMotion: "reduce" });
    await page.setViewportSize({ width: 1440, height: 900 });
    await openCanvas(page);
    await arm(page);
    await page.locator("#capsule").click();
    const f = await frame(page);
    expect(f.paletteOpacity, "no fade under reduced motion").toBe("1");
    expect(f.running).toEqual([]);
  });
});
