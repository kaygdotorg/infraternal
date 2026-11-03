/**
 * Restored windows whose sessions the host no longer has (#185), on the product canvas against the test double.
 *
 * The production report: two restored windows showed "Session ended  New shell  x"; New shell did nothing, and the
 * strip seemed to run away from the pointer. Here the layout is saved with two windows on sessions the host
 * reports as gone, the page is reloaded, and the strip is driven the way a person does: approach slowly, click.
 */
import { tracerEvidencePath } from "./evidence-path";
import { mkdir } from "node:fs/promises";
import { resolve } from "node:path";
import { expect, test, type APIRequestContext, type Page } from "playwright/test";
import { FORMAT, VERSION } from "../src/canvas/model/schema";

const retry = <T>(call: () => Promise<T>): Promise<T> => call().catch(() => call());
type MockState = { attach_count: number; session_id: string; echoed_text: string };
const mockState = async (request: APIRequestContext): Promise<MockState> => (await (await retry(() => request.get("/__mock/state"))).json()) as MockState;

/** Boots the product, then saves a two-window layout on sessions the host has already lost, and reloads into it. */
async function restoreEnded(page: Page, width = 1440, height = 900): Promise<void> {
  const request = page.context().request;
  await retry(() => request.post("/__mock/reset"));
  await retry(() => request.post("/__mock/open-terminal"));
  await page.setViewportSize({ width, height });
  await page.goto("/?theme=ink&bg=none");
  await expect.poll(() => page.locator("#terminal-screen").getAttribute("data-connected"), { timeout: 30_000 }).toBe("true");
  const { session_ids: ids } = (await (await retry(() => request.post("/__mock/seed-ended-sessions", { data: { count: 2 } }))).json()) as { session_ids: string[] };
  // The layout is server-owned (D312): the page keeps no document in its storage to edit, and it saves one only on an edit.
  // So the spec writes the saved layout itself, two windows on the lost sessions, and lets the server push it as another
  // device would, then reloads into it.
  const { hostname } = await page.evaluate(async () => {
    const response = await fetch("/auth/session", { method: "POST", headers: { "Content-Type": "application/json" }, body: "{}" });
    return await response.json() as { hostname: string };
  });
  const win = (n: number) => ({ id: `t-restored-${n}`, target: { type: "session", id: ids[n], host: hostname, name: "shell" } });
  const document = { format: FORMAT, version: VERSION, revision: 0, views: [{ id: "console", kind: "console", name: "Console", cell: { x: 0, y: 0 }, layout: { type: "tiled", columns: [{ id: "c1", weight: 1, windows: [win(0)] }, { id: "c2", weight: 1, windows: [win(1)] }] } }] };
  expect((await retry(() => request.post("/__mock/layout", { data: { document } }))).ok(), "the double accepts the restored layout").toBe(true);
  await page.reload();
  await expect(page.locator(".cl-sx-strip")).toHaveCount(2, { timeout: 30_000 });
}

test("a restored ended window starts a new shell on click, and its strip stays under the pointer", async ({ page }, testInfo) => {
  test.setTimeout(120_000);
  const request = page.context().request;
  await restoreEnded(page);
  const wins = page.locator(".ui-window[data-kind='terminal']");
  await expect(wins).toHaveCount(2);
  const win = wins.first();
  const strip = win.locator(".cl-sx-strip");
  await expect(strip.locator(".cl-sx-strip-text")).toHaveText("Session ended");
  await page.waitForTimeout(500);

  const dir = tracerEvidencePath("ended-strip");
  await mkdir(dir, { recursive: true });
  const tag = process.env.ENDED_STRIP_TAG ?? "after";
  await page.screenshot({ path: resolve(dir, `${tag}-restored-1440x900-ink.png`), animations: "disabled" });

  // Approach slowly from the left edge of the window to the button: the strip never moves.
  const rest = (await strip.boundingBox())!;
  const target = (await strip.getByRole("button", { name: "New shell" }).boundingBox())!;
  const box = (await win.boundingBox())!;
  const boxes: Array<{ x: number; y: number; width: number; height: number }> = [];
  await page.mouse.move(box.x + 20, box.y + box.height - 20);
  for (let i = 0; i <= 40; i++) {
    const t = i / 40;
    await page.mouse.move(box.x + 20 + (target.x + target.width / 2 - box.x - 20) * t, box.y + box.height - 20 + (target.y + target.height / 2 - box.y - box.height + 20) * t);
    boxes.push((await strip.boundingBox())!);
    await page.waitForTimeout(16);
  }
  for (const b of boxes) expect(b).toEqual(rest);
  await page.screenshot({ path: resolve(dir, `${tag}-hover-1440x900-ink.png`), animations: "disabled" });

  // The click opens a new shell in this same window: the strip goes, the window is live and takes typing.
  // A press must not move it either: the shared pill's pressed scale used to replace the strip's centring transform,
  // so the strip jumped out from under the button between pointerdown and pointerup and the click was lost.
  await page.mouse.down();
  await page.waitForTimeout(200);
  expect(await strip.boundingBox(), "the strip moved while pressed").toEqual(rest);
  await page.mouse.up();
  await expect(strip).toHaveCount(0, { timeout: 5_000 });
  await expect(win).toHaveAttribute("data-status", "live", { timeout: 10_000 });
  await expect(wins).toHaveCount(2);
  await expect(win.locator(".terminal-host")).toBeVisible();
  await expect.poll(async () => (await mockState(request)).session_id).not.toBe("");
  await page.keyboard.type("echo alive");
  await expect.poll(async () => (await mockState(request)).echoed_text, { timeout: 10_000 }).toContain("echo alive");
  await page.screenshot({ path: resolve(dir, `${tag}-opened-1440x900-ink.png`), animations: "disabled" });
  // The other restored window is untouched.
  await expect(page.locator(".cl-sx-strip")).toHaveCount(1);
});

test("a refused new shell says why in the strip, and Try again recovers", async ({ page }, testInfo) => {
  test.setTimeout(120_000);
  const request = page.context().request;
  await restoreEnded(page);
  const win = page.locator(".ui-window[data-kind='terminal']").first();
  const strip = win.locator(".cl-sx-strip");
  await retry(() => request.post("/__mock/refuse-next-open"));
  await strip.getByRole("button", { name: "New shell" }).click();
  // An "unavailable" refusal means the host's infraternal agent is not connected to the server; the strip says so and names the
  // fix (#291, D291; terminal-refusal.ts, pinned by open-refusal.test.ts). It used to say "could not start a shell".
  await expect(strip.locator(".cl-sx-strip-text")).toHaveText(/The infraternal agent on .+ cannot reach the server\. Check that outbound TCP 443 is allowed from /, { timeout: 10_000 });
  await expect(strip).toHaveAttribute("data-result", "refused");
  // The reason sits in the strip, not in a toast on the side.
  await expect(page.locator(".ui-toast")).toBeHidden();
  await page.mouse.move(2, 2);
  const dir = tracerEvidencePath("ended-strip");
  await mkdir(dir, { recursive: true });
  await page.screenshot({ path: resolve(dir, `${process.env.ENDED_STRIP_TAG ?? "after"}-refused-1440x900-ink.png`), animations: "disabled" });
  await testInfo.attach("refused", { path: resolve(dir, `${process.env.ENDED_STRIP_TAG ?? "after"}-refused-1440x900-ink.png`), contentType: "image/png" });
  await strip.getByRole("button", { name: "Try again" }).click();
  await expect(strip).toHaveCount(0, { timeout: 5_000 });
  await expect(win).toHaveAttribute("data-status", "live", { timeout: 10_000 });
});

test("Enter on the focused ended window starts a new shell, and the cross closes the window", async ({ page }) => {
  test.setTimeout(120_000);
  const request = page.context().request;
  await restoreEnded(page);
  const wins = page.locator(".ui-window[data-kind='terminal']");
  const win = wins.first();
  // Focus the window without touching the strip: click its empty body, then press Enter.
  const box = (await win.boundingBox())!;
  await page.mouse.click(box.x + box.width / 2, box.y + 160);
  await page.keyboard.press("Enter");
  await expect(win.locator(".cl-sx-strip")).toHaveCount(0, { timeout: 5_000 });
  await expect(win).toHaveAttribute("data-status", "live", { timeout: 10_000 });
  await expect.poll(async () => (await mockState(request)).session_id).not.toBe("");
  // The other window closes with its cross.
  const second = wins.nth(1);
  await second.locator(".cl-sx-dismiss").click();
  await expect(wins).toHaveCount(1);
});

test.describe("phone", () => {
  test.use({ viewport: { width: 393, height: 852 }, hasTouch: true, isMobile: true });
  test("the ended strip on a phone takes a tap", async ({ page }) => {
    test.setTimeout(120_000);
    await restoreEnded(page, 393, 852);
    const win = page.locator(".ui-window[data-kind='terminal']").first();
    const strip = win.locator(".cl-sx-strip");
    await expect(strip).toBeVisible();
    const dir = tracerEvidencePath("ended-strip");
    await mkdir(dir, { recursive: true });
    await page.screenshot({ path: resolve(dir, `${process.env.ENDED_STRIP_TAG ?? "after"}-restored-393x852-ink.png`), animations: "disabled" });
    const rest = (await strip.boundingBox())!;
    await strip.getByRole("button", { name: "New shell" }).tap();
    await expect(strip).toHaveCount(0, { timeout: 5_000 });
    await expect(win).toHaveAttribute("data-status", "live", { timeout: 10_000 });
    expect(rest.height).toBeGreaterThanOrEqual(38);
  });
});
