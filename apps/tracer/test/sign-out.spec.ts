/**
 * Signing out of this device (#171, TASTE "You can always sign yourself out").
 *
 * Against the mock canvas: the profile pill's menu (pointer and keyboard), the palette row and Settings, Account each
 * ask once with the compact confirmation (title, tick and cross icon buttons with tooltips), then land on the sign-in
 * screen with no window, sidebar, overlay or live connection left, and a reload stays signed out. Cancel and a failed
 * request leave the person signed in. A phone has 44 px targets. The product path (real cookie, product canvas) is
 * signed out through the palette and stays signed out after a reload. Review screenshots land in job scratch.
 *
 * The double keeps a preview signed out until the page is opened with `fresh=1` or it is reset, so every test resets it
 * afterwards, and the page URLs here never carry `fresh=1` (a reload must stay signed out).
 */
import { tracerEvidencePath } from "./evidence-path";
import { mkdirSync } from "node:fs";
import { resolve } from "node:path";
import { expect, test, type Page } from "playwright/test";

const OUT = tracerEvidencePath("signout");
mkdirSync(OUT, { recursive: true });

test.afterEach(async ({ page }) => { await page.context().request.post("/__mock/reset"); });

async function open(page: Page, theme = "ink"): Promise<void> {
  await page.goto(`/?mock=1&proto=clusters&scene=3&theme=${theme}`);
  await expect(page.locator(".cl-mockup")).toBeVisible({ timeout: 20_000 });
}

async function openSidebar(page: Page): Promise<void> {
  await page.locator("#sidebar-toggle").click();
  await expect(page.locator("#sidebar")).toBeVisible();
  await page.waitForTimeout(500);
}

const pill = (page: Page) => page.locator(".ui-sidebar-user");
const menu = (page: Page) => page.locator(".ui-anchored-popover[aria-label='Account']");
const confirm = (page: Page) => page.locator(".ui-confirm-tip[data-open='true']");

/** The person is back at the sign-in card and nothing of the session is left behind. */
async function expectSignedOut(page: Page): Promise<void> {
  await expect(page.getByRole("heading", { name: "Welcome back" })).toBeVisible({ timeout: 10_000 });
  await expect(page.locator(".ui-window, #sidebar, #palette, .ui-toast, .ui-confirm-tip, .ui-anchored-popover, .ui-settings")).toHaveCount(0);
  expect(await page.evaluate(() => (window as unknown as { __tracerTestDouble?: unknown }).__tracerTestDouble)).toBeUndefined();
}

/** Every WebSocket the page opened is closed once the person has signed out. */
function trackSockets(page: Page): () => number {
  const sockets: Array<{ isClosed(): boolean }> = [];
  page.on("websocket", (socket) => sockets.push(socket));
  return () => sockets.filter((socket) => !socket.isClosed()).length;
}

async function reloadStaysSignedOut(page: Page): Promise<void> {
  await page.reload();
  await expect(page.getByRole("heading", { name: "Welcome back" })).toBeVisible({ timeout: 10_000 });
  await page.waitForTimeout(800);
  await expect(page.locator(".ui-window, #sidebar")).toHaveCount(0);
}

test("profile pill: a menu with Settings and Sign out; the confirmation asks once and signs out", async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 900 });
  const live = trackSockets(page);
  await open(page);
  await openSidebar(page);
  await expect.poll(live).toBeGreaterThan(0);

  await pill(page).click();
  await expect(menu(page)).toBeVisible();
  await expect(menu(page).getByRole("menuitem")).toHaveText(["Settings", "Sign out"]);
  // It opens above the pill, inside the screen, and hugs its rows (not the sidebar's width).
  const pillBox = (await pill(page).boundingBox())!;
  const box = (await menu(page).boundingBox())!;
  expect(box.y + box.height).toBeLessThanOrEqual(pillBox.y);
  expect(pillBox.y - (box.y + box.height)).toBeLessThan(14);
  expect(box.width).toBeLessThan(260);
  await page.waitForTimeout(250);
  await page.screenshot({ path: resolve(OUT, "pill-menu-desktop-ink.png") });

  // Escape closes it, a second press on the pill closes it too.
  await page.keyboard.press("Escape");
  await expect(menu(page)).toHaveCount(0);
  await pill(page).click();
  await expect(menu(page)).toBeVisible();
  await pill(page).click();
  await expect(menu(page)).toHaveCount(0);

  await pill(page).click();
  await menu(page).getByRole("menuitem", { name: "Sign out" }).click();
  await expect(confirm(page)).toBeVisible();
  await expect(confirm(page)).toContainText("Sign out of this device?");
  // Two icon buttons, no text buttons; each is named and carries a tooltip.
  const yes = confirm(page).getByRole("button", { name: "Sign out" });
  const no = confirm(page).getByRole("button", { name: "Cancel" });
  await expect(yes).toHaveAttribute("data-tip", "Sign out");
  await expect(no).toHaveAttribute("data-tip", "Cancel");
  await expect(confirm(page).locator("button svg")).toHaveCount(2);
  await expect(yes).not.toContainText("Sign out");
  await page.waitForTimeout(250);
  await page.screenshot({ path: resolve(OUT, "confirm-desktop-ink.png") });

  // Cancel keeps the session.
  await no.click();
  await expect(confirm(page)).toHaveCount(0);
  await expect(page.locator(".cl-mockup")).toBeVisible();

  await pill(page).click();
  await menu(page).getByRole("menuitem", { name: "Sign out" }).click();
  await confirm(page).getByRole("button", { name: "Sign out" }).click();
  await expectSignedOut(page);
  await expect.poll(live).toBe(0);
  await page.waitForTimeout(600);
  await page.screenshot({ path: resolve(OUT, "signed-out-desktop-ink.png") });
  await reloadStaysSignedOut(page);
});

test("profile pill by keyboard: Enter opens the menu on its first row, arrows walk it, Escape returns to the pill", async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 900 });
  await open(page);
  await openSidebar(page);
  await pill(page).focus();
  await page.keyboard.press("Enter");
  await expect(menu(page)).toBeVisible();
  await expect(menu(page).getByRole("menuitem", { name: "Settings" })).toBeFocused();
  await page.keyboard.press("ArrowDown");
  await expect(menu(page).getByRole("menuitem", { name: "Sign out" })).toBeFocused();
  await page.keyboard.press("ArrowDown");
  await expect(menu(page).getByRole("menuitem", { name: "Settings" })).toBeFocused();
  await page.keyboard.press("Escape");
  await expect(menu(page)).toHaveCount(0);
  await expect(pill(page)).toBeFocused();

  await page.keyboard.press("Enter");
  await expect(menu(page).getByRole("menuitem", { name: "Settings" })).toBeFocused();
  await page.keyboard.press("ArrowUp");
  await expect(menu(page).getByRole("menuitem", { name: "Sign out" })).toBeFocused();
  await page.keyboard.press("Enter");
  // The confirmation takes focus (on Cancel); Tab reaches Sign out, and Enter signs out.
  await expect(confirm(page)).toBeVisible();
  await page.keyboard.press("Tab");
  await expect(confirm(page).getByRole("button", { name: "Sign out" })).toBeFocused();
  await page.keyboard.press("Enter");
  await expectSignedOut(page);
});

test("the palette has Sign out; it asks, then signs out", async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 900 });
  const live = trackSockets(page);
  await open(page);
  await page.keyboard.press("Control+Shift+K");
  await expect(page.locator("#palette")).toBeVisible();
  await page.locator("#palette-input").fill("sign out");
  const row = page.locator("#palette-results .result", { hasText: "Sign out" });
  await expect(row).toHaveCount(1);
  await expect(row).toContainText("this device");
  await page.keyboard.press("Enter");
  await expect(page.locator("#palette")).toBeHidden();
  await expect(confirm(page)).toBeVisible();
  await expect(confirm(page)).toContainText("Sign out of this device?");
  await confirm(page).getByRole("button", { name: "Sign out" }).click();
  await expectSignedOut(page);
  await expect.poll(live).toBe(0);
  await reloadStaysSignedOut(page);
});

test("Settings, Account has the row; it asks, then signs out", async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 900 });
  await open(page);
  await page.evaluate(() => window.dispatchEvent(new CustomEvent("tracer:canvas-action", { detail: { action: "canvas:settings:account", source: "pointer" } })));
  const row = page.locator(".ui-sp-row", { hasText: "Sign out of this device" });
  await expect(row).toBeVisible({ timeout: 10_000 });
  await expect(row.locator("button[data-action='sign-out']")).toHaveAttribute("data-tip", "Sign out");
  await page.waitForTimeout(900);
  await page.screenshot({ path: resolve(OUT, "settings-account-desktop-ink.png") });
  await row.locator("button[data-action='sign-out']").click();
  await expect(confirm(page)).toContainText("Sign out of this device?");
  await confirm(page).getByRole("button", { name: "Sign out" }).click();
  await expectSignedOut(page);
  await reloadStaysSignedOut(page);
});

test("signing out while the terminal is still connecting leaves no terminal behind", async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 900 });
  // The terminal cannot finish opening until its WebAssembly module arrives. Hold that one request until the person has
  // signed out, then let it through: the terminal client completes AFTER sign-out, the order a slow link produces.
  let release!: () => void;
  const gate = new Promise<void>((resolveGate) => { release = resolveGate; });
  await page.route(/\.wasm$/, async (route) => { await gate; await route.continue(); });
  let closedAfterRelease = 0, released = false;
  page.on("websocket", (socket) => { socket.on("close", () => { if (released) closedAfterRelease++; }); });
  const live = trackSockets(page);
  const hook = () => page.evaluate(() => (window as unknown as { __tracerTestDouble?: unknown }).__tracerTestDouble !== undefined);
  await open(page);
  expect(await hook(), "the terminal is still connecting").toBe(false);
  await page.keyboard.press("Control+Shift+K");
  await page.locator("#palette-input").fill("sign out");
  await page.keyboard.press("Enter");
  await confirm(page).getByRole("button", { name: "Sign out" }).click();
  await expect(page.getByRole("heading", { name: "Welcome back" })).toBeVisible({ timeout: 10_000 });
  released = true;
  release();
  // The late client either closes its own connection straight away or never connects at all (what it does depends on how far the
  // sign-out got when the module arrived). Both are fine; what is not is a client that stays. Wait, up to a deadline, for the
  // first close after the release, which a kept client also produces when it reconnects but never without having set its hook.
  await expect.poll(() => closedAfterRelease, { timeout: 4_000 }).toBeGreaterThan(0).catch(() => undefined);
  expect(await live(), "no connection is left open after sign-out").toBe(0);
  expect(await hook(), "no live terminal is left behind the sign-in screen").toBe(false);
});

test("a sign-out the server could not complete says so and leaves the person signed in", async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 900 });
  await open(page);
  await page.route("**/auth/logout", (route) => route.abort());
  await page.keyboard.press("Control+Shift+K");
  await page.locator("#palette-input").fill("sign out");
  await page.keyboard.press("Enter");
  await confirm(page).getByRole("button", { name: "Sign out" }).click();
  const toast = page.locator(".ui-toast:not([hidden])");
  await expect(toast).toContainText("Could not sign out");
  // TASTE: the icon matches the news. A failure wears the caution mark, never the success tick.
  await expect(toast.locator(".ui-toast-glyph")).toBeVisible();
  await expect(toast.locator(".ui-toast-marker")).toBeHidden();
  await expect(page.locator(".cl-mockup")).toBeVisible();
  await expect(page.getByRole("heading", { name: "Welcome back" })).toHaveCount(0);
});

for (const [name, viewport, scale] of [["phone", { width: 393, height: 852 }, 3], ["small", { width: 375, height: 667 }, 2]] as const) {
  for (const theme of ["ink", "paper"]) {
    test(`touch: 44 px targets, the menu and the confirmation fit (${name}, ${theme})`, async ({ browser }) => {
      const context = await browser.newContext({ viewport, deviceScaleFactor: scale, hasTouch: true, isMobile: true });
      const page = await context.newPage();
      await open(page, theme);
      await openSidebar(page);
      await pill(page).tap();
      await expect(menu(page)).toBeVisible();
      await page.waitForTimeout(400); // the open animation scales the card; measure it at rest
      for (const item of await menu(page).getByRole("menuitem").all()) expect((await item.boundingBox())!.height).toBeGreaterThanOrEqual(44);
      const stage = (await page.locator("#sidebar").boundingBox())!;
      const box = (await menu(page).boundingBox())!;
      expect(box.x).toBeGreaterThanOrEqual(0);
      expect(box.x + box.width).toBeLessThanOrEqual(viewport.width);
      expect(box.y).toBeGreaterThanOrEqual(stage.y);
      await page.waitForTimeout(300);
      await page.screenshot({ path: resolve(OUT, `pill-menu-${name}-${theme}.png`) });
      await menu(page).getByRole("menuitem", { name: "Sign out" }).tap();
      await expect(confirm(page)).toBeVisible();
      await page.waitForTimeout(400);
      for (const button of await confirm(page).getByRole("button").all()) {
        const b = (await button.boundingBox())!;
        expect(b.width).toBeGreaterThanOrEqual(44);
        expect(b.height).toBeGreaterThanOrEqual(44);
      }
      const tip = (await confirm(page).boundingBox())!;
      expect(tip.x).toBeGreaterThanOrEqual(0);
      expect(tip.x + tip.width).toBeLessThanOrEqual(viewport.width);
      await page.waitForTimeout(300);
      await page.screenshot({ path: resolve(OUT, `confirm-${name}-${theme}.png`) });
      await confirm(page).getByRole("button", { name: "Sign out" }).tap();
      await expectSignedOut(page);
      await page.waitForTimeout(600);
      await page.screenshot({ path: resolve(OUT, `signed-out-${name}-${theme}.png`) });
      await context.close();
    });
  }
}

for (const theme of ["ink", "paper"]) {
  test(`captures: desktop menu, confirmation and sign-in (${theme})`, async ({ page }) => {
    await page.setViewportSize({ width: 1440, height: 900 });
    await open(page, theme);
    await openSidebar(page);
    await pill(page).click();
    await expect(menu(page)).toBeVisible();
    await page.waitForTimeout(300);
    await page.screenshot({ path: resolve(OUT, `pill-menu-desktop-${theme}.png`) });
    await menu(page).getByRole("menuitem", { name: "Sign out" }).click();
    await expect(confirm(page)).toBeVisible();
    await page.waitForTimeout(300);
    await page.screenshot({ path: resolve(OUT, `confirm-desktop-${theme}.png`) });
    await confirm(page).getByRole("button", { name: "Sign out" }).click();
    await expectSignedOut(page);
    await page.waitForTimeout(600);
    await page.screenshot({ path: resolve(OUT, `signed-out-desktop-${theme}.png`) });
  });
}

test("the product canvas on the real cookie: sign out from the palette, a reload stays signed out", async ({ page }) => {
  test.setTimeout(120_000);
  await page.setViewportSize({ width: 1280, height: 720 });
  const context = page.context();
  await context.request.post("/__mock/reset");
  const cdp = await context.newCDPSession(page);
  await cdp.send("WebAuthn.enable");
  await cdp.send("WebAuthn.addVirtualAuthenticator", {
    options: { protocol: "ctap2", ctap2Version: "ctap2_1", transport: "internal", hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true, hasPrf: true },
  });
  await page.goto("/?mock=1");
  const token = (await (await context.request.get("/__mock/setup-token")).json() as { setup_token: string }).setup_token;
  await page.locator("#setup-token").fill(token);
  await page.getByRole("button", { name: "Continue" }).click();
  await page.locator("#setup-username").fill("signout_test");
  await page.locator("#setup-display-name").fill("Sign out test");
  await page.getByRole("button", { name: "Continue" }).click();
  await page.getByRole("button", { name: "Create passkey" }).click();
  await page.locator(".auth-check").click();
  await page.getByRole("button", { name: "Open infraternal" }).click();
  await expect(page.getByText("TEST DOUBLE")).toBeVisible();

  // The product canvas, on the same session cookie.
  await page.goto("/");
  await expect(page.locator(".ui-window").first()).toBeVisible({ timeout: 30_000 });
  const live = trackSockets(page);
  await page.keyboard.press("Control+Shift+K");
  await page.locator("#palette-input").fill("sign out");
  await page.keyboard.press("Enter");
  await expect(confirm(page)).toContainText("Sign out of this device?");
  await confirm(page).getByRole("button", { name: "Sign out" }).click();
  await expectSignedOut(page);
  await expect.poll(live).toBe(0);
  await reloadStaysSignedOut(page);
  await page.goto("/");
  await expect(page.getByRole("heading", { name: "Welcome back" })).toBeVisible();
  await expect(page.locator(".ui-window")).toHaveCount(0);
});

/** Every key of both storage areas, plus whether Cache Storage, IndexedDB and the cookies hold anything. */
async function storageSnapshot(page: Page): Promise<{ local: Record<string, string>; session: Record<string, string>; caches: string[]; databases: string[]; cookies: string }> {
  return page.evaluate(async () => {
    const dump = (area: Storage): Record<string, string> => Object.fromEntries(Object.keys(area).map((k) => [k, area.getItem(k) ?? ""]));
    return {
      local: dump(localStorage), session: dump(sessionStorage), caches: await caches.keys(),
      databases: (await indexedDB.databases()).map((d) => d.name ?? ""), cookies: document.cookie,
    };
  });
}

const ACCOUNT_KEY = /^(infraternal\.canvas\.|tracer\.sessions?\.|tracer\.user-id$)/;

test("D245: signing out removes the account's data from every storage area; signing back in starts clean", async ({ page }) => {
  test.setTimeout(120_000);
  await page.setViewportSize({ width: 1280, height: 720 });
  const context = page.context();
  await context.request.post("/__mock/reset");
  const cdp = await context.newCDPSession(page);
  await cdp.send("WebAuthn.enable");
  await cdp.send("WebAuthn.addVirtualAuthenticator", {
    options: { protocol: "ctap2", ctap2Version: "ctap2_1", transport: "internal", hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true, hasPrf: true },
  });
  await page.goto("/?mock=1");
  const token = (await (await context.request.get("/__mock/setup-token")).json() as { setup_token: string }).setup_token;
  await page.locator("#setup-token").fill(token);
  await page.getByRole("button", { name: "Continue" }).click();
  await page.locator("#setup-username").fill("clear_test");
  await page.locator("#setup-display-name").fill("Clear test");
  await page.getByRole("button", { name: "Continue" }).click();
  await page.getByRole("button", { name: "Create passkey" }).click();
  await page.locator(".auth-check").click();
  await page.getByRole("button", { name: "Open infraternal" }).click();
  await expect(page.getByText("TEST DOUBLE")).toBeVisible();
  await page.goto("/");
  await expect(page.locator(".ui-window").first()).toBeVisible({ timeout: 30_000 });

  // A device preference, and another account's data that shares this browser.
  await page.evaluate(() => {
    localStorage.setItem("tracer.theme", "mocha");
    localStorage.setItem("infraternal.canvas.someone-else", "{}");
    localStorage.setItem("tracer.sessions.someone-else", "[]");
  });
  // Make a layout change and let the 300 ms coalescing save land, then see what the account owns.
  // The product canvas finishes opening its windows a moment after the first one appears.
  await page.waitForTimeout(3000);
  const windows = await page.locator(".ui-window").count();
  await page.locator(".ui-window").first().locator("[data-action='split-right']").click();
  await expect(page.locator(".ui-window")).toHaveCount(windows + 1);
  await expect.poll(() => page.evaluate(() => Object.keys(localStorage).some((k) => k.startsWith("infraternal.canvas.") && !k.endsWith("someone-else")))).toBe(true);
  const before = await storageSnapshot(page);
  const own = (snap: typeof before) => [...Object.keys(snap.local), ...Object.keys(snap.session)].filter((k) => ACCOUNT_KEY.test(k) && !k.endsWith("someone-else"));
  expect(own(before).some((k) => k.startsWith("infraternal.canvas."))).toBe(true);
  const canvasBytes = Object.entries(before.local).filter(([k]) => k.startsWith("infraternal.canvas.")).reduce((n, [, v]) => n + v.length, 0);
  console.log(`layout document: ${canvasBytes} bytes; keys: ${own(before).join(", ")}`);
  // The mock host keeps no session list or tab pointer; seed what a real host's session leaves for this account.
  const id = own(before).find((k) => k.startsWith("infraternal.canvas."))!.slice("infraternal.canvas.".length);
  await page.evaluate((account) => {
    localStorage.setItem(`tracer.sessions.${account}`, JSON.stringify([{ host: "h", id: "s1", name: "build", pinned: false, frecency: 1 }]));
    sessionStorage.setItem(`tracer.session.${account}`, "s1");
  }, id);

  await page.keyboard.press("Control+Shift+K");
  await page.locator("#palette-input").fill("sign out");
  await page.keyboard.press("Enter");
  await confirm(page).getByRole("button", { name: "Sign out" }).click();
  await expectSignedOut(page);
  // Late writes: let every timer, the pagehide flush and the sockets' last messages run, then look again.
  await page.evaluate(() => { window.dispatchEvent(new Event("pagehide")); document.dispatchEvent(new Event("visibilitychange")); });
  await page.waitForTimeout(1500);
  const after = await storageSnapshot(page);
  expect(own(after)).toEqual([]);
  expect(after.local["tracer.theme"]).toBe("mocha");
  expect(after.local["infraternal.canvas.someone-else"]).toBe("{}");
  expect(after.local["tracer.sessions.someone-else"]).toBe("[]");
  expect(after.caches).toEqual([]);
  expect(after.databases).toEqual([]);
  expect(after.cookies).toBe("");
  // Nothing mentions the signed-out account id anywhere in what is left.
  expect(JSON.stringify([after.local, after.session])).not.toContain(id);

  // A reload stays clean, and signing back in starts with a fresh layout (the server restores it later).
  await reloadStaysSignedOut(page);
  expect(own(await storageSnapshot(page))).toEqual([]);
});
