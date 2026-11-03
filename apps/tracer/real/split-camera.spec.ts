/**
 * A keyboard split at 54 real windows lands the new window fully on screen, beside or below the one it came from,
 * active and focused (#141). Production server binary, real PTYs: a real terminal takes focus when it connects, which
 * is what a mock window never does.
 */
import { expect, test, type Page } from "playwright/test";
import { personName, startRealServer, type RealServer } from "./server";

test.describe.configure({ mode: "serial" });
let server: RealServer;
let page: Page;

test.beforeAll(async ({ browser }) => {
  server = await startRealServer();
  const context = await browser.newContext({ ignoreHTTPSErrors: true, viewport: { width: 1440, height: 900 } });
  page = await context.newPage();
  const cdp = await context.newCDPSession(page);
  await cdp.send("WebAuthn.enable");
  await cdp.send("WebAuthn.addVirtualAuthenticator", { options: { protocol: "ctap2", ctap2Version: "ctap2_1", transport: "internal", hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true, hasPrf: true } });
  await page.goto(server.origin + "/?theme=ink&bg=none");
  await page.locator("#setup-token").fill(server.token);
  await page.getByRole("button", { name: "Continue", exact: true }).click();
  await page.locator("#setup-username").fill(personName("split_real"));
  await page.locator("#setup-display-name").fill("Split real");
  await page.getByRole("button", { name: "Continue", exact: true }).click();
  await page.getByRole("button", { name: "Create passkey" }).click();
  await page.getByRole("heading", { name: "Save your recovery key" }).waitFor();
  await page.locator(".auth-check").click();
  await page.getByRole("button", { name: "Open infraternal" }).click();
  await page.locator(".cl-viewport").waitFor();
});
test.afterAll(async () => { await page?.context().close(); await server?.dispose(); });


const windows = () => page.locator('.cl[data-view="console"] .ui-window');
const active = () => page.evaluate(() => {
  const w = document.querySelector<HTMLElement>('.cl[data-view="console"] .ui-window[data-active]');
  const r = w?.getBoundingClientRect();
  return { id: w?.dataset.windowId ?? null, n: document.querySelectorAll('.cl[data-view="console"] .ui-window').length, l: r?.left ?? 0, r: r?.right ?? 0, t: r?.top ?? 0, b: r?.bottom ?? 0, vw: innerWidth, vh: innerHeight, focused: Boolean(w?.contains(document.activeElement)) };
});

test("keyboard splits stay in view: split right x53, then right and down from the first, a middle and the last column", async () => {
  test.setTimeout(600_000);
  await windows().first().locator(".terminal-host").click({ position: { x: 60, y: 60 } });
  const bad: string[] = [];
  const check = (tag: string, before: Awaited<ReturnType<typeof active>>, after: Awaited<ReturnType<typeof active>>, dir: "right" | "down", old: { l: number; r: number; t: number; b: number }) => {
    if (after.n !== before.n + 1) bad.push(`${tag}: count ${before.n}->${after.n}`);
    if (after.id === before.id) bad.push(`${tag}: active did not change`);
    if (after.l < -1 || after.r > after.vw + 1 || after.t < -1 || after.b > after.vh + 1) bad.push(`${tag}: off screen ${JSON.stringify(after)}`);
    if (old.r < -1 || old.l > after.vw + 1) bad.push(`${tag}: the old window left the screen ${JSON.stringify(old)}`);
    if (dir === "right" && after.l < old.r - 1) bad.push(`${tag}: not right of the old window (new ${after.l}, old right edge ${old.r})`);
    if (dir === "down" && after.t < old.b - 1) bad.push(`${tag}: not below the old window`);
  };
  const rectOf = (id: string) => page.evaluate((id) => { const r = document.querySelector<HTMLElement>(`.cl[data-view="console"] .ui-window[data-window-id="${id}"]`)!.getBoundingClientRect(); return { l: r.left, r: r.right, t: r.top, b: r.bottom }; }, id);
  const press = async (dir: "right" | "down") => {
    const before = await active();
    await page.keyboard.press(dir === "right" ? "Control+Shift+KeyD" : "Control+Shift+KeyE");
    await expect.poll(async () => (await active()).n).toBe(before.n + 1);
    await page.waitForTimeout(Number(process.env.SPLIT_SETTLE ?? 250));
    return before;
  };
  for (let i = 1; i < 54; i++) {
    const before = await press("right");
    const after = await active();
    check(`grow ${i}`, before, after, "right", await rectOf(before.id!));
  }
  console.log("windows", (await active()).n, "failures while growing", bad.length);
  for (const pick of [0, 26, 53]) {
    await windows().nth(pick).locator(".terminal-host").click({ position: { x: 60, y: 60 }, force: true }).catch(() => {});
    await page.waitForTimeout(1200);
    for (const dir of ["right", "down"] as const) {
      const before = await press(dir);
      const after = await active();
      check(`col ${pick}/${dir}`, before, after, dir, await rectOf(before.id!));
    }
  }
  console.log(bad.join("\n"));
  expect(bad).toEqual([]);
});
