/**
 * "Not saved — keep this tab open" waits about a second before it shows (D358, #395), on the product canvas against the
 * test double. A normal move is confirmed within one round trip and must never show it; a save the server does not
 * answer (the double holds it) shows it after about a second, and it goes as soon as the save is answered.
 */
import { expect, test, type APIRequestContext, type Page } from "playwright/test";

/** The notice text, exactly as the canvas shows it. */
const NOTICE = "Not saved — keep this tab open";
/** The latency proxy may hang up a pooled keep-alive connection that a socket drop closed; one retry absorbs it. */
const retry = <T>(call: () => Promise<T>): Promise<T> => call().catch(() => call());
/** The layout revision the double has saved: it grows by one for every edit it answered. */
const savedRevision = async (request: APIRequestContext): Promise<number> =>
  ((await (await retry(() => request.get("/__mock/layout"))).json()) as { document: { revision: number } }).document.revision;

/** Opens the product canvas on one live shell and waits until its first layout saves are done. */
async function openProduct(page: Page): Promise<void> {
  const request = page.context().request;
  await retry(() => request.post("/__mock/reset"));
  await retry(() => request.post("/__mock/open-terminal"));
  await page.setViewportSize({ width: 1440, height: 900 });
  await page.goto("/?theme=ink&bg=none");
  await expect.poll(() => page.locator("#terminal-screen").getAttribute("data-connected"), { timeout: 30_000 }).toBe("true");
  await expect(page.locator(".ui-window[data-kind='terminal']")).toHaveCount(1);
  // Records every time the notice is put on screen, so a flash between two samples cannot be missed.
  await page.evaluate((text) => {
    const seen = { count: 0 };
    Reflect.set(window, "__pendingSeen", seen);
    new MutationObserver(() => {
      const shown = [...document.querySelectorAll(".ui-toast-message")].some((node) => node.textContent === text);
      if (shown && !Reflect.get(window, "__pendingNow")) seen.count++;
      Reflect.set(window, "__pendingNow", shown);
    }).observe(document.body, { subtree: true, childList: true, characterData: true });
  }, NOTICE);
  // sleep: lets the first saves of the boot (console view, the shell window) settle before the spec starts counting.
  await page.waitForTimeout(1_500);
  await page.evaluate(() => { (Reflect.get(window, "__pendingSeen") as { count: number }).count = 0; });
}

/** Drags the shell window's east edge 150 px narrower: one layout edit. */
async function resize(page: Page): Promise<void> {
  const box = (await page.locator(".ui-window[data-kind='terminal']").boundingBox())!;
  await page.mouse.move(box.x + box.width - 2, box.y + box.height / 2);
  await page.mouse.down();
  await page.mouse.move(box.x + box.width - 152, box.y + box.height / 2, { steps: 8 });
  await page.mouse.up();
}

/** How many times the notice was put on screen since `openProduct` reset the count. */
const timesShown = (page: Page): Promise<number> => page.evaluate(() => (Reflect.get(window, "__pendingSeen") as { count: number }).count);

test("a normal resize is saved without ever showing the notice", async ({ page }) => {
  test.setTimeout(90_000);
  const request = page.context().request;
  await openProduct(page);
  const before = await savedRevision(request);
  await resize(page);
  await expect.poll(() => savedRevision(request), { timeout: 10_000 }).toBeGreaterThan(before);
  // sleep: the notice would come about a second after the edit; wait past that to see that it never does.
  await page.waitForTimeout(2_000);
  expect(await timesShown(page), "the notice flashed for an edit the server confirmed in one round trip").toBe(0);
  await expect(page.getByText(NOTICE, { exact: true })).toHaveCount(0);
});

test("a save the server does not answer shows the notice after about a second, until it is saved", async ({ page }) => {
  test.setTimeout(90_000);
  const request = page.context().request;
  await openProduct(page);
  await retry(() => request.post("/__mock/layout/hold", { data: { hold: true } }));
  try {
    await resize(page);
    const editedAt = Date.now();
    const notice = page.getByText(NOTICE, { exact: true });
    await expect(notice).toBeVisible({ timeout: 5_000 });
    const after = Date.now() - editedAt;
    expect(after, "the notice showed before the edit had waited about a second").toBeGreaterThanOrEqual(900);
    // It stays while the save waits.
    // sleep: the notice must hold steady through a long wait, not time out on its own.
    await page.waitForTimeout(2_000);
    await expect(notice).toBeVisible();
    expect(await timesShown(page)).toBe(1);
  } finally {
    await retry(() => request.post("/__mock/layout/hold", { data: { hold: false } }));
  }
  await expect(page.getByText(NOTICE, { exact: true })).toHaveCount(0, { timeout: 10_000 });
});
