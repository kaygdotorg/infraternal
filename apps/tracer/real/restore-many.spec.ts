/**
 * Restoring many windows at once must never show a person "offline or cannot reach this server" (#556).
 *
 * The server answers only a few plugin calls at a time on one socket (MAX_PENDING_PLUGIN_CALLS) and refuses the rest
 * as `unavailable`, which a window shows as that offline message. A page restoring 8, 16 or 32 windows after a reload
 * or a dropped network, and a person (or a script) clicking "new window" ten times in a second, all put many calls on
 * the socket together. Production server binary, production build, real PTYs; no test double.
 */
import { expect, test, type Page } from "playwright/test";
import { personName, startRealServer, type RealServer } from "./server";

test.describe.configure({ mode: "default" });

const windows = (page: Page) => page.locator('.cl[data-view="console"] .ui-window');
const OFFLINE = "offline or cannot reach";

/** Enrols the first passkey of a fresh server and lands on the canvas. */
async function enrol(page: Page, server: RealServer): Promise<void> {
  const cdp = await page.context().newCDPSession(page);
  await cdp.send("WebAuthn.enable");
  await cdp.send("WebAuthn.addVirtualAuthenticator", { options: { protocol: "ctap2", ctap2Version: "ctap2_1", transport: "internal", hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true, hasPrf: true } });
  await page.goto(server.origin + "/");
  await page.locator("#setup-token").fill(server.token);
  await page.getByRole("button", { name: "Continue", exact: true }).click();
  await page.locator("#setup-username").fill(personName("restore_many"));
  await page.locator("#setup-display-name").fill("Restore many");
  await page.getByRole("button", { name: "Continue", exact: true }).click();
  await page.getByRole("button", { name: "Create passkey" }).click();
  await page.getByRole("heading", { name: "Save your recovery key" }).waitFor();
  await page.locator(".auth-check").click();
  await page.getByRole("button", { name: "Open infraternal" }).click();
  await page.locator(".cl-viewport").waitFor();
}

/**
 * The actions the server refused, on every socket so far. A canvas that asks for the mesh while this fixture runs
 * none is told "mesh unavailable" by the mesh feature itself; that is no refusal from the call cap and no window
 * shows it, so it is left out.
 */
function refusedActions(server: RealServer): string[] {
  const names: string[] = [];
  for (const b of server.bridges) {
    const asked = new Map(b.control.filter((f) => f.dir === "up" && f.type === "Call").map((f) => [f.callId, f.detail]));
    for (const f of b.control) if (f.dir === "down" && f.type === "Result" && f.detail !== "ok" && !f.reason?.includes("mesh unavailable")) names.push(`${asked.get(f.callId) ?? "?"}: ${f.reason ?? ""}`);
  }
  return names;
}
const refusedOn = (server: RealServer): number => refusedActions(server).length;
/** Distinct sessions attached on the sockets still open (a long-lived page rotates to a second socket past 28 windows). */
const attachedOn = (server: RealServer): number => new Set(server.bridges.filter((b) => !b.closed).flatMap((b) => [...b.attached.values()].flat())).size;
/** Calls the newest socket has sent that the server has not answered yet. */
function pendingOn(server: RealServer): number {
  const control = server.bridges.filter((b) => !b.closed).at(-1)?.control ?? [];
  const answered = new Set(control.filter((f) => f.dir === "down" && f.type === "Result").map((f) => f.callId));
  return control.filter((f) => f.dir === "up" && f.type === "Call" && !answered.has(f.callId)).length;
}

for (const total of [8, 16, 32]) {
  test.describe(`${total} windows`, () => {
    let server: RealServer;
    let page: Page;
    test.beforeAll(async ({ browser }) => {
      server = await startRealServer();
      const context = await browser.newContext({ ignoreHTTPSErrors: true, viewport: { width: 1440, height: 900 } });
      page = await context.newPage();
      await enrol(page, server);
    });
    test.afterAll(async () => { await page?.context().close(); await server?.dispose(); });

    /** Waits until every window has attached and none says offline, as a person would see it; prints the numbers. */
    async function whole(label: string, since: number, refusedBefore: number): Promise<void> {
      await expect(windows(page)).toHaveCount(total, { timeout: 60_000 });
      await expect.poll(() => attachedOn(server), { timeout: 120_000, message: "every window attached" }).toBeGreaterThanOrEqual(total);
      const ms = Math.round(performance.now() - since);
      const offlineWindows = await windows(page).filter({ hasText: OFFLINE }).count();
      const refusedResults = refusedOn(server) - refusedBefore;
      console.log(`${label} n=${total} ${JSON.stringify({ ms, offlineWindows, refusedResults, refused: refusedActions(server).slice(refusedBefore) })}`);
      expect.soft(offlineWindows).toBe(0);
      expect.soft(refusedResults).toBe(0);
    }

    test("builds the canvas, reloads it, drops the network; no window is ever offline", async () => {
      test.setTimeout(480_000);
      while ((await windows(page).count()) < total) {
        const count = await windows(page).count();
        // A person opens windows one at a time; wait for the calls of the last one so the setup itself is not the test.
        await expect.poll(() => pendingOn(server), { timeout: 30_000 }).toBeLessThan(3);
        await page.locator(".tab-add").click();
        await expect(windows(page)).toHaveCount(count + 1);
      }
      // The server keeps the layout; the last window's save is still on its way when its shell attaches, and a reload
      // before it lands would restore one window fewer, which is a different question from this spec's.
      await page.waitForTimeout(3_000);

      const before = refusedOn(server);
      const t0 = performance.now();
      await page.reload();
      await page.locator(".cl-viewport").waitFor();
      await whole("RESTORE-RELOAD", t0, before);

      const beforeDrop = refusedOn(server);
      const sockets = server.bridges.length;
      const t1 = performance.now();
      await server.interruptBrowserRoutes(2_000);
      await expect.poll(() => server.bridges.length, { timeout: 60_000 }).toBeGreaterThan(sockets);
      await whole("RESTORE-DROP", t1, beforeDrop);
    });
  });
}

test.describe("ten new windows within a second", () => {
  let server: RealServer;
  let page: Page;
  test.beforeAll(async ({ browser }) => {
    server = await startRealServer();
    const context = await browser.newContext({ ignoreHTTPSErrors: true, viewport: { width: 1440, height: 900 } });
    page = await context.newPage();
    await enrol(page, server);
  });
  test.afterAll(async () => { await page?.context().close(); await server?.dispose(); });

  test("every window gets its shell, none offline", async () => {
    test.setTimeout(180_000);
    await expect(windows(page)).toHaveCount(1);
    const t0 = performance.now();
    // Clicked from the page: a new window is still flying into view, and a pointer click would aim at where it was.
    await page.locator(".tab-add").evaluate(async (button) => {
      for (let i = 0; i < 10; i++) { (button as HTMLElement).click(); await new Promise((r) => setTimeout(r, 90)); }
    });
    await expect(windows(page)).toHaveCount(11);
    // Not a hard wait: a window the server refused never attaches, and the report below says so.
    await expect.poll(() => attachedOn(server), { timeout: 30_000 }).toBeGreaterThanOrEqual(11).catch(() => undefined);
    const ms = Math.round(performance.now() - t0);
    const offlineWindows = await windows(page).filter({ hasText: OFFLINE }).count();
    console.log(`RAPID-NEW n=10 ${JSON.stringify({ ms, attached: attachedOn(server), offlineWindows, refused: refusedActions(server) })}`);
    expect.soft(attachedOn(server)).toBeGreaterThanOrEqual(11);
    expect.soft(offlineWindows).toBe(0);
    expect.soft(refusedOn(server)).toBe(0);
  });
});
