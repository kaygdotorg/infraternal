/**
 * A window whose session the host no longer has (#158), on the product canvas against the test double.
 *
 * The production incident: the host lost a session, and its window kept a green dot over a blank body while the
 * attach was repeated about twice a second. Here the double's "host" loses the session and drops the link; the page
 * must ask once, take the server's final answer (Close 4404), show the ended state, never attach again, and open a
 * new shell in the same window with one action.
 */
import { mkdir } from "node:fs/promises";
import { resolve } from "node:path";
import { expect, test, type APIRequestContext, type Page } from "playwright/test";

type MockState = { attach_count: number; session_id: string; echoed_text: string };
/** The latency proxy may hang up a pooled keep-alive connection that a socket drop closed; one retry absorbs it. */
const retry = <T>(call: () => Promise<T>): Promise<T> => call().catch(() => call());
const mockState = async (request: APIRequestContext): Promise<MockState> => (await (await retry(() => request.get("/__mock/state"))).json()) as MockState;

async function openProduct(page: Page): Promise<void> {
  const request = page.context().request;
  await retry(() => request.post("/__mock/reset"));
  await retry(() => request.post("/__mock/open-terminal"));
  await page.setViewportSize({ width: 1440, height: 900 });
  await page.goto("/?theme=ink&bg=none");
  await expect.poll(() => page.locator("#terminal-screen").getAttribute("data-connected"), { timeout: 30_000 }).toBe("true");
}

test("a dead session ends quietly: one attach, an ended state, and a new shell in the same window", async ({ page }, testInfo) => {
  test.setTimeout(90_000);
  const request = page.context().request;
  await openProduct(page);
  const win = page.locator(".ui-window").first();
  await expect(win).toHaveAttribute("data-status", "live");
  await expect(page.locator(".capsule-session")).toHaveText("· 1 session");
  await expect.poll(async () => (await mockState(request)).attach_count).toBeGreaterThanOrEqual(1);
  const before = (await mockState(request)).attach_count;

  // The host loses the session and the link drops: the page reconnects and asks once.
  const dead = ((await (await retry(() => request.post("/__mock/end-session"))).json()) as { session_id: string }).session_id;
  await expect(win.locator(".cl-sx-strip")).toBeVisible({ timeout: 10_000 });
  await expect(win.locator(".cl-sx-strip-text")).toHaveText("Session ended");
  await expect(win.locator(".cl-sx-strip .ui-mark")).toHaveAttribute("data-mark", "ended");
  // The dot is no longer live, and the empty terminal behind the pill is hidden (no cursor inviting typing).
  await expect(win).toHaveAttribute("data-status", "offline");
  await expect(win.locator(".terminal-host")).toBeHidden();
  // The top pill counts sessions: an ended one is not one.
  await expect(page.locator(".capsule-session")).toHaveText("· 0 sessions");
  const ended = (await mockState(request)).attach_count;
  expect(ended, "exactly one attach after the session ended").toBe(before + 1);

  // No retry: not over time, and not after another link drop.
  await page.waitForTimeout(2_000);
  await retry(() => request.post("/__mock/drop-sockets"));
  await page.waitForTimeout(3_000);
  expect((await mockState(request)).attach_count, "the page attached to a dead session again").toBe(ended);
  await expect(win.locator(".cl-sx-strip-text")).toHaveText("Session ended");

  // The capture the owner reviews (1440×900, production build, ink).
  await page.mouse.move(2, 2);
  await page.waitForTimeout(400);
  const dir = resolve(import.meta.dirname, "..", "captures", "dead-session");
  await mkdir(dir, { recursive: true });
  const shot = resolve(dir, "ended-1440x900-ink.png");
  await page.screenshot({ path: shot, animations: "disabled" });
  await testInfo.attach("ended-1440x900-ink", { path: shot, contentType: "image/png" });

  // One action: a new shell on the same host, in this same window.
  const windows = await page.locator(".ui-window").count();
  await win.getByRole("button", { name: "New shell" }).click();
  await expect(win.locator(".cl-sx-strip")).toHaveCount(0);
  await expect(win).toHaveAttribute("data-status", "live");
  await expect(page.locator(".capsule-session")).toHaveText("· 1 session");
  await expect.poll(async () => (await mockState(request)).session_id).not.toBe(dead);
  await expect.poll(async () => (await mockState(request)).attach_count).toBe(ended + 1);
  expect(await page.locator(".ui-window").count()).toBe(windows);
  await expect(win.locator(".terminal-host")).toBeVisible();
  // The new shell takes typing.
  await win.locator(".terminal-host").click();
  await page.keyboard.type("echo alive");
  await expect.poll(async () => (await mockState(request)).echoed_text).toContain("echo alive");
});

for (const status of [7, 0]) test(`a retired session carries exit ${status} through the same final ended path`, async ({ page }, testInfo) => {
  test.setTimeout(90_000);
  const request = page.context().request;
  await openProduct(page);
  const win = page.locator(".ui-window").first();
  const before = (await mockState(request)).attach_count;
  const response = await retry(() => request.post("/__mock/retire-session", { data: { status } }));
  const dead = (await response.json() as { session_id: string }).session_id;
  await expect(win.locator(".cl-sx-strip-text")).toHaveText(`Session ended · Exit ${status}`);
  await expect(win).toHaveAttribute("data-status", "offline");
  await expect(win.locator(".terminal-host")).toBeHidden();
  await expect(page.locator(".capsule-session")).toHaveText("· 0 sessions");
  await page.waitForTimeout(2_000);
  expect((await mockState(request)).attach_count).toBe(before + 1);
  const dir = resolve(import.meta.dirname, "..", "captures", "dead-session");
  await mkdir(dir, { recursive: true });
  const shot = resolve(dir, `retired-exit-${status}-1440x900-ink.png`);
  await page.screenshot({ path: shot, animations: "disabled" });
  await testInfo.attach(`retired-exit-${status}`, { path: shot, contentType: "image/png" });
  await win.getByRole("button", { name: "New shell" }).click();
  await expect(win.locator(".cl-sx-strip")).toHaveCount(0);
  await expect(win).toHaveAttribute("data-status", "live");
  await expect.poll(async () => (await mockState(request)).session_id).not.toBe(dead);
});

test("a drop between saved status and final Close resumes to the same ended answer", async ({ page }) => {
  test.setTimeout(90_000);
  const request = page.context().request;
  await openProduct(page);
  const win = page.locator(".ui-window").first();
  const before = (await mockState(request)).attach_count;
  await retry(() => request.post("/__mock/retire-session-drop-close", { data: { status: 7 } }));
  await expect(win.locator(".cl-sx-strip-text")).toHaveText("Session ended · Exit 7", { timeout: 20_000 });
  await expect(win).toHaveAttribute("data-status", "offline");
  expect((await mockState(request)).attach_count).toBe(before + 2);
  await page.waitForTimeout(2_000);
  expect((await mockState(request)).attach_count).toBe(before + 2);
});
