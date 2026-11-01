/**
 * Guards TASTE.md section 1: a focus ring is never clipped or covered, on any side, in any field.
 *
 * The ring is drawn outside its element (`outline` plus `outline-offset`, packages/ui/styles.css), so a
 * parent that clips its overflow cuts it off wherever the field touches that parent's edge: the last
 * field before the actions row lost its bottom edge in the setup card's pane viewport. This spec walks
 * every focus stop of the setup steps, the returning sign-in and (when the recovery presentation is
 * built in) the recovery key entry, with the real Tab key, at the desktop and phone viewports, and checks
 * on the production build that for each stop
 *   - the whole ring box lies inside the clip rectangle of every ancestor that clips, and inside the page;
 *   - at the middle of each side of the ring, nothing that paints (a background, a border, a control) sits
 *     above the ring other than the field's own ancestors.
 */
import { expect, test, type Page, type TestInfo } from "playwright/test";
import { uiFactor } from "./ui-factor";

const viewports = [
  { id: "desktop", width: 1440, height: 900 },
  { id: "phone", width: 393, height: 852 },
] as const;

interface Stop { label: string; why: string }

/** Measures the focused element's ring in the page. Returns the problems found, empty when the ring is whole. */
async function probeRing(page: Page): Promise<{ label: string; problems: string[]; box: { x: number; y: number; width: number; height: number } | null }> {
  return page.evaluate(() => {
    const active = document.activeElement as HTMLElement | null;
    if (!active || active === document.body) return { label: "(nothing focused)", problems: ["nothing has focus"], box: null };
    const label = active.id ? `#${active.id}` : `${active.tagName.toLowerCase()}.${active.className}`;
    // A checkbox is visually hidden: its ring is drawn on the visible tick beside it.
    const target = active.matches('input[type="checkbox"]')
      ? (active.parentElement?.querySelector<HTMLElement>(".tick") ?? active)
      : active;
    const style = getComputedStyle(target);
    const width = parseFloat(style.outlineWidth);
    const offset = parseFloat(style.outlineOffset);
    if (style.outlineStyle === "none" || !(width > 0)) return { label, problems: ["no ring is drawn while Tab-focused"], box: null };

    const rect = target.getBoundingClientRect();
    const reach = offset + width;
    const outer = { left: rect.left - reach, top: rect.top - reach, right: rect.right + reach, bottom: rect.bottom + reach };
    const problems: string[] = [];
    const eps = 0.01;

    // Every message carries the numbers, so a failure can be read without re-running it.
    const n = (value: number): string => value.toFixed(1);
    const outside = (clip: { left: number; top: number; right: number; bottom: number }, x: boolean, y: boolean, who: string): void => {
      if (x && outer.left < clip.left - eps) problems.push(`left edge clipped by ${who} (ring ${n(outer.left)} < clip ${n(clip.left)})`);
      if (x && outer.right > clip.right + eps) problems.push(`right edge clipped by ${who} (ring ${n(outer.right)} > clip ${n(clip.right)})`);
      if (y && outer.top < clip.top - eps) problems.push(`top edge clipped by ${who} (ring ${n(outer.top)} < clip ${n(clip.top)})`);
      if (y && outer.bottom > clip.bottom + eps) problems.push(`bottom edge clipped by ${who} (ring ${n(outer.bottom)} > clip ${n(clip.bottom)})`);
    };
    outside({ left: 0, top: 0, right: document.documentElement.clientWidth, bottom: document.documentElement.clientHeight }, true, true, "the page");
    for (let parent = target.parentElement; parent; parent = parent.parentElement) {
      const parentStyle = getComputedStyle(parent);
      const clipsX = parentStyle.overflowX !== "visible";
      const clipsY = parentStyle.overflowY !== "visible";
      if (!clipsX && !clipsY) continue;
      const box = parent.getBoundingClientRect();
      const left = box.left + parent.clientLeft;
      const top = box.top + parent.clientTop;
      outside({ left, top, right: left + parent.clientWidth, bottom: top + parent.clientHeight }, clipsX, clipsY, `${parent.tagName.toLowerCase()}.${String(parent.className).split(" ")[0] || parent.id}`);
    }

    const paints = (element: Element): boolean => {
      const s = getComputedStyle(element);
      return !/^(rgba\(0, 0, 0, 0\)|transparent)$/.test(s.backgroundColor) || s.backgroundImage !== "none"
        || (parseFloat(s.borderTopWidth) > 0 && s.borderTopStyle !== "none") || element.matches("button,input,textarea,select,img,svg,canvas,video");
    };
    const middle = reach - width / 2; // the centre line of the ring band
    const mx = (rect.left + rect.right) / 2;
    const my = (rect.top + rect.bottom) / 2;
    const sides: [string, number, number][] = [
      ["top", mx, rect.top - middle], ["bottom", mx, rect.bottom + middle],
      ["left", rect.left - middle, my], ["right", rect.right + middle, my],
    ];
    for (const [side, x, y] of sides) {
      const hit = document.elementFromPoint(x, y);
      if (!hit) { problems.push(`${side} edge is off screen`); continue; }
      if (hit.contains(target) || target.contains(hit)) continue; // the field itself or one of its ancestors
      if (paints(hit)) problems.push(`${side} edge is covered by ${hit.tagName.toLowerCase()}.${String(hit.className).split(" ")[0] || hit.id}`);
    }
    return { label, problems, box: { x: outer.left, y: outer.top, width: outer.right - outer.left, height: outer.bottom - outer.top } };
  });
}

/** Waits for every running animation and transition (pane slides, height glides) to settle. */
async function settle(page: Page): Promise<void> {
  await page.evaluate(async () => {
    await document.fonts.ready;
    await Promise.all(document.getAnimations().map((animation) => animation.finished.catch(() => undefined)));
    await new Promise((resolve) => requestAnimationFrame(() => requestAnimationFrame(resolve)));
  });
}

const FOCUSABLE = 'input:not([type="hidden"]):not([disabled]), button:not([disabled]), a[href], summary, [tabindex="0"]';

/**
 * Walks every focus stop in the active card with the real Tab key and returns what was found wrong.
 * The first stop is focused from script after one real Tab has switched on the keyboard modality,
 * because Tab itself would move past it.
 */
async function walkCard(page: Page, testInfo: TestInfo, name: string, scope = ".auth-card:not([inert])"): Promise<Stop[]> {
  await settle(page);
  await page.keyboard.press("Tab");
  expect(await page.evaluate(() => document.documentElement.dataset.focusRing)).toBe("on");
  const first = await page.evaluate(({ scope, sel }) => {
    const element = [...document.querySelectorAll<HTMLElement>(`${scope} :is(${sel})`)].find((candidate) => candidate.getClientRects().length > 0);
    element?.focus();
    return Boolean(element);
  }, { scope, sel: FOCUSABLE });
  expect(first, `${name}: the card has a focus stop`).toBe(true);

  const stops: Stop[] = [];
  const seen = new Set<string>();
  for (let i = 0; i < 40; i++) {
    const inScope = await page.evaluate((s) => Boolean(document.activeElement?.closest(s)), scope);
    if (!inScope) break;
    const probe = await probeRing(page);
    const key = `${probe.label}@${probe.box?.x}`;
    if (seen.has(key)) break;
    seen.add(key);
    for (const problem of probe.problems) stops.push({ label: `${name} ${probe.label}`, why: problem });
    if (process.env.FOCUS_RING_SHOTS && probe.box) {
      const pad = 12;
      const path = testInfo.outputPath(`${name}-${probe.label.replace(/[^a-z0-9]+/gi, "-")}.png`);
      await page.screenshot({
        path, animations: "disabled",
        clip: { x: Math.max(0, probe.box.x - pad), y: Math.max(0, probe.box.y - pad), width: probe.box.width + 2 * pad, height: probe.box.height + 2 * pad },
      });
      await testInfo.attach(`${name}-${probe.label}`, { path, contentType: "image/png" });
    }
    await page.keyboard.press("Tab");
  }
  expect(seen.size, `${name}: walked at least one focus stop`).toBeGreaterThan(0);
  return stops;
}

/**
 * Walks the active card at both viewports and adds every ring problem to `problems`. Nothing asserts here:
 * the test asserts once at its end, so one run shows every broken stop of the whole flow, not the first step's.
 */
async function collectRingProblems(page: Page, testInfo: TestInfo, name: string, problems: string[]): Promise<void> {
  for (const viewport of viewports) {
    await page.setViewportSize({ width: viewport.width, height: viewport.height });
    await page.evaluate(() => (document.activeElement as HTMLElement | null)?.blur());
    for (const stop of await walkCard(page, testInfo, `${name}-${viewport.id}`)) problems.push(`${stop.label}: ${stop.why}`);
  }
}

test("every setup and sign-in focus ring is whole: not clipped, not covered", async ({ page }, testInfo) => {
  test.setTimeout(120_000);
  const problems: string[] = [];
  const context = page.context();
  const setup = await (await context.request.post("/__mock/reset", { maxRetries: 1 })).json() as { setup_token: string };
  const cdp = await context.newCDPSession(page);
  await cdp.send("WebAuthn.enable");
  await cdp.send("WebAuthn.addVirtualAuthenticator", {
    options: { protocol: "ctap2", ctap2Version: "ctap2_1", transport: "internal", hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true, hasPrf: true },
  });
  await page.emulateMedia({ colorScheme: "dark", reducedMotion: "no-preference" });
  await page.goto("/?mock=1");
  await expect(page.locator("#setup-token")).toBeVisible();

  await collectRingProblems(page, testInfo, "setup-1-token", problems);
  await page.locator("#setup-token").fill(setup.setup_token);
  await page.getByRole("button", { name: "Continue" }).click();

  await expect(page.locator("#setup-display-name")).toBeVisible();
  await page.locator("#setup-username").fill("ada");
  await page.locator("#setup-display-name").fill("Ada Lovelace");
  // Making room for the ring must not move anything: the pane keeps the step bar's 30 px above it and the
  // footer's 26 px below it (auth.css). Below, the pane's fractional line height adds 0.3125 px on the
  // unmodified code too (the script rounds the viewport height to whole pixels), so that gap is a range.
  await settle(page);
  const gaps = await page.evaluate(() => {
    const top = (selector: string) => document.querySelector(selector)!.getBoundingClientRect();
    return { aboveTitle: top(".auth-pane").top - top(".auth-steps").bottom, belowFields: top(".auth-footer").top - top(".auth-pane").bottom };
  });
  // The gaps are lengths of the interface (rem), so they are 30 and 26 px times the UI's factor (1.1 on a desktop).
  const factor = await uiFactor(page);
  expect(gaps.aboveTitle).toBeCloseTo(30 * factor, 1);
  expect(gaps.belowFields).toBeGreaterThanOrEqual(26 * factor - 0.01);
  expect(gaps.belowFields).toBeLessThan(27 * factor);
  await collectRingProblems(page, testInfo, "setup-2-identity", problems);
  await page.getByRole("button", { name: "Continue" }).click();

  await expect(page.getByRole("heading", { name: "Create your passkey" })).toBeVisible();
  await collectRingProblems(page, testInfo, "setup-3-passkey", problems);
  await page.getByRole("button", { name: "Create passkey" }).click();

  await expect(page.locator("#recovery-words li")).toHaveCount(24);
  await collectRingProblems(page, testInfo, "setup-4-recovery", problems);
  await page.locator(".auth-check").click();
  await page.getByRole("button", { name: "Open infraternal" }).click();
  await expect(page.locator("#welcome-title")).toHaveText("Welcome to infraternal");

  // Returning sign-in: only the passkey button, which must not be cut off by the card either.
  await context.clearCookies();
  await page.evaluate(() => localStorage.clear());
  await page.reload();
  await expect(page.locator("#login-passkey")).toBeVisible();
  await collectRingProblems(page, testInfo, "signin", problems);
  expect(problems).toEqual([]);
});

test.describe("recovery key entry", () => {
  test.skip(!["preview", "1"].includes(process.env.INFRATERNAL_RECOVERY_UI ?? "off"), "Recovery presentation requires an explicit build flag");

  test("every recovery entry focus ring is whole: not clipped, not covered", async ({ page }, testInfo) => {
    await page.route("**/auth/status", (route) => route.fulfill({ json: { setup_required: false } }));
    await page.route("**/auth/session", (route) => route.fulfill({ status: 401, json: {} }));
    await page.emulateMedia({ colorScheme: "dark", reducedMotion: "no-preference" });
    await page.goto("/?mock=1&proto=recovery");
    await page.getByRole("button", { name: "use recovery key", exact: true }).click();
    await expect(page.getByRole("heading", { name: "Use your recovery key" })).toBeVisible();
    const problems: string[] = [];
    await collectRingProblems(page, testInfo, "recovery-entry", problems);
    expect(problems).toEqual([]);
  });
});
