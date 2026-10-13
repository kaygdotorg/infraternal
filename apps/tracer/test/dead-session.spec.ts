/**
 * A window whose session the host no longer has (#158), on the product canvas against the test double.
 *
 * The production incident: the host lost a session, and its window kept a green dot over a blank body while the
 * attach was repeated about twice a second. Here the double pushes an inventory without the lost session and drops
 * the link; the page removes the row, settles the existing window, never retries it after the ended state, and
 * opens a new shell with one action.
 */
import { tracerEvidencePath } from "./evidence-path";
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
  // The client connection flag precedes host receipt of AttachTerm on the delayed link.
  await expect.poll(async () => (await mockState(request)).attach_count, { timeout: 10_000 }).toBeGreaterThanOrEqual(1);
}

test("a dead session disappears and does not retry after the ended state", async ({ page }, testInfo) => {
  test.setTimeout(90_000);
  const request = page.context().request;
  await openProduct(page);
  const win = page.locator(".ui-window").first();
  await expect(win).toHaveAttribute("data-status", "live");
  await expect(page.locator(".capsule-session")).toHaveText("· 1 session");
  await expect.poll(async () => (await mockState(request)).attach_count).toBeGreaterThanOrEqual(1);
  const before = (await mockState(request)).attach_count;

  // The pushed inventory removes the row immediately, independent of the terminal connection.
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
  expect(ended, "the authoritative inventory prevents a stale attach").toBe(before);

  // The snapshot makes the terminal final too; neither time nor another link drop can revive it.
  await page.waitForTimeout(2_000);
  await retry(() => request.post("/__mock/drop-sockets"));
  await page.waitForTimeout(3_000);
  expect((await mockState(request)).attach_count, "the page attached to a dead session again").toBe(ended);
  await expect(win.locator(".cl-sx-strip-text")).toHaveText("Session ended");

  // The capture the owner reviews (1440×900, production build, ink).
  await page.mouse.move(2, 2);
  await page.waitForTimeout(400);
  const dir = tracerEvidencePath("dead-session");
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

test("the sidebar waits for the live-shim snapshot and never lists ended cached sessions", async ({ page }, testInfo) => {
  test.setTimeout(90_000);
  const request = page.context().request;
  await openProduct(page);
  const { session_ids: endedIds } = await (await retry(() => request.post("/__mock/seed-ended-sessions", { data: { count: 40 } }))).json() as { session_ids: string[] };
  const identity = await page.evaluate(async () => {
    const response = await fetch("/auth/session", { method: "POST", headers: { "Content-Type": "application/json" }, body: "{}" });
    return await response.json() as { user_id: string; hostname: string };
  });
  await page.evaluate(({ userId, host, ids }) => {
    const rows = ids.map((id, index) => ({ host, id, name: "shell", pinned: false, frecency: ids.length - index }));
    localStorage.setItem(`tracer.sessions.${userId}`, JSON.stringify(rows));
  }, { userId: identity.user_id, host: identity.hostname, ids: endedIds });
  await page.reload();
  await expect(page.locator(".ui-window").first()).toHaveAttribute("data-status", "live", { timeout: 30_000 });
  await expect(page.locator(".capsule-session")).toHaveText("· 1 session");
  await page.locator("#sidebar-toggle").click();
  const rows = page.locator(`#tree .bm-sec[data-id="view:console"] .bm-leaf[data-id^="s:"]`);
  await expect(rows).toHaveCount(1);
  const listed = await rows.evaluateAll((nodes) => nodes.map((node) => (node as HTMLElement).dataset.id ?? ""));
  expect(listed[0]).toContain((await mockState(request)).session_id);
  for (const id of endedIds) await expect(page.locator(`#tree .bm-leaf[data-id$='/${id}']`)).toHaveCount(0);
  for (const id of listed) {
    await page.locator(`#tree .bm-leaf[data-id='${id}']`).click();
    await expect(page.locator(".ui-window").first()).toHaveAttribute("data-status", "live");
  }

  // The reviewed capture is the production bundle at the desktop target viewport.
  const dir = tracerEvidencePath("ended-sessions");
  await mkdir(dir, { recursive: true });
  const shot = resolve(dir, "sidebar-after-1440x900.png");
  await page.screenshot({ path: shot, animations: "disabled" });
  await testInfo.attach("sidebar-after-1440x900", { path: shot, contentType: "image/png" });
});

test("a pushed ended-session snapshot removes its sidebar row and pill count within one second", async ({ page }) => {
  test.setTimeout(90_000);
  const request = page.context().request;
  await openProduct(page);
  await expect(page.locator("#terminal-screen")).toHaveAttribute("data-connected", "true", { timeout: 30_000 });
  await page.locator("#sidebar-toggle").click();
  const rows = page.locator(`#tree .bm-sec[data-id="view:console"] .bm-leaf[data-id^="s:"]`);
  await expect(rows).toHaveCount(1);
  expect((await retry(() => request.post("/__mock/remove-session-from-inventory"))).ok()).toBe(true);
  await expect(rows).toHaveCount(0, { timeout: 1_000 });
  await expect(page.locator(".capsule-session")).toHaveText("· 0 sessions");
});

test("agent restart hides unverified cached rows and restores the fresh live snapshot", async ({ page }) => {
  test.setTimeout(90_000);
  const request = page.context().request;
  await openProduct(page);
  await expect(page.locator("#terminal-screen")).toHaveAttribute("data-connected", "true", { timeout: 30_000 });
  await page.locator("#sidebar-toggle").click();
  const rows = page.locator(`#tree .bm-sec[data-id="view:console"] .bm-leaf[data-id^="s:"]`);
  await expect(rows).toHaveCount(1);

  expect((await retry(() => request.post("/__mock/agent-offline"))).ok()).toBe(true);
  await expect(rows).toHaveCount(0, { timeout: 1_000 });
  await expect(page.locator(".capsule-session")).toHaveText("· 0 sessions");

  expect((await retry(() => request.post("/__mock/agent-online"))).ok()).toBe(true);
  await expect(rows).toHaveCount(1, { timeout: 1_000 });
  await rows.first().click();
  await expect(page.locator(".ui-window").first()).toHaveAttribute("data-status", "live");
});

for (const status of [7, 0]) test(`a retired session carries exit ${status} through the same final ended path`, async ({ page }, testInfo) => {
  test.setTimeout(90_000);
  const request = page.context().request;
  await openProduct(page);
  const win = page.locator(".ui-window").first();
  await expect.poll(async () => (await mockState(request)).attach_count).toBeGreaterThanOrEqual(1);
  const before = (await mockState(request)).attach_count;
  const response = await retry(() => request.post("/__mock/retire-session", { data: { status } }));
  const dead = (await response.json() as { session_id: string }).session_id;
  await expect(win.locator(".cl-sx-strip-text")).toHaveText(`Session ended · Exit ${status}`);
  await expect(win).toHaveAttribute("data-status", "offline");
  await expect(win.locator(".terminal-host")).toBeHidden();
  await expect(page.locator(".capsule-session")).toHaveText("· 0 sessions");
  await page.waitForTimeout(2_000);
  expect((await mockState(request)).attach_count).toBe(before);
  const dir = tracerEvidencePath("dead-session");
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
  await expect.poll(async () => (await mockState(request)).attach_count).toBeGreaterThanOrEqual(1);
  const before = (await mockState(request)).attach_count;
  await retry(() => request.post("/__mock/retire-session-drop-close", { data: { status: 7 } }));
  await expect(win.locator(".cl-sx-strip-text")).toHaveText("Session ended · Exit 7", { timeout: 20_000 });
  await expect(win).toHaveAttribute("data-status", "offline");
  expect((await mockState(request)).attach_count).toBe(before + 2);
  await page.waitForTimeout(2_000);
  expect((await mockState(request)).attach_count).toBe(before + 2);
});
