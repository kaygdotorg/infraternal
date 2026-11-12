// SPDX-License-Identifier: AGPL-3.0-only
/**
 * What J528's checks missed on a real server (#500, J539). J509's real-device run found three things the test double passed:
 * the connected host missing from the sidebar tree after a restart, a locked host without "Unlock to connect", and no Open
 * shell button after `exit`. This spec runs the same surfaces against the double as a real server behaves (see the
 * "what a real server does" notes in `mock-server.ts`): a row has every key and the host's reported name, a connected host stays
 * online through a restart while the CA locks, every socket drops, and the list tells subscribers when it changes.
 *
 * 1. After the last window closes, a person with one added host (so two hosts: the server's own and the added one) is offered
 *    an Open shell button; with several hosts it opens the palette limited to "Open shell on <host>" rows.
 * 2. A host that is offline behind the lock is offered "Unlock host connections" *and* Open shell (the server's own host works).
 * 3. A server restart never takes a connected host out of the tree, and the lock never marks an online host.
 *
 * Functional: nothing asserts speed. Checked at 1440 and 402 px wide.
 */
import { expect, test, type Page } from "playwright/test";
import { tracerEvidencePath } from "./evidence-path";

/** The admitted id of the added host. */
const HOST_ID = "33333333-4444-4555-8666-777777777777";
/** The added host's name as a real server sends it: the hostname the host reported. */
const HOST = "worker-j539";
/** The added host's row, online (what a connected host looks like). */
const ADDED = { id: HOST_ID, name: HOST, user: "operator", os: "Debian GNU/Linux", address: "operator@worker.lan", online: true };
/** The two review widths. */
const SIZES = [
  { id: "1440", viewport: { width: 1440, height: 900 }, touch: false },
  { id: "402", viewport: { width: 402, height: 720 }, touch: true },
] as const;
/** One review size from {@link SIZES}. */
type Size = (typeof SIZES)[number];

/** A context at `size`, as a phone (touch, mobile) or a desktop. */
async function newPage(browser: import("playwright/test").Browser, size: Size): Promise<{ page: Page; close: () => Promise<void> }> {
  const context = await browser.newContext({ viewport: size.viewport, deviceScaleFactor: size.touch ? 3 : 1, ...(size.touch ? { hasTouch: true, isMobile: true } : {}) });
  return { page: await context.newPage(), close: () => context.close() };
}

/** Opens the product on the double with `hosts` admitted and the CA locked or not, and waits for the first window. */
async function openProduct(page: Page, options: { hosts: unknown[]; locked: boolean }): Promise<void> {
  await page.request.post("/__mock/reset");
  await page.request.post("/__mock/remote-hosts", { data: { hosts: options.hosts } });
  await page.request.post("/__mock/ca", { data: { locked: options.locked } });
  await page.goto("/?mock=1&proto=product&fresh=1&bg=none&theme=ink");
  await expect(page.locator(".ui-window").first().locator(".ui-window-host")).toHaveText(/\S/, { timeout: 40_000 });
}

/** Closes the one open window the palette's way, so the view is empty. */
async function closeAllWindows(page: Page): Promise<void> {
  const palette = async (): Promise<void> => { await page.keyboard.press("Control+Shift+K"); await page.locator("#palette-input").fill("Close window"); };
  await palette();
  await page.locator("#palette-results [role=option]").filter({ hasText: "Close window" }).first().click();
  await expect(page.locator(".cl-empty")).toBeVisible({ timeout: 15_000 });
}

/** Opens the sidebar and waits for its rows. */
async function openSidebar(page: Page): Promise<void> {
  if (await page.locator("#sidebar").evaluate((el) => (el as HTMLElement).hidden)) await page.locator("#sidebar-toggle").click();
  await expect(page.locator('#tree[data-rows="ready"]')).toHaveCount(1, { timeout: 30_000 });
}

/** The sidebar's row for the added host. */
const hostRow = (page: Page) => page.locator(`#tree li.bm-subhead[data-id="h:${HOST}"]`);

for (const size of SIZES) {
  test(`empty state ${size.id}: one added host, so two hosts: Open shell is offered and opens the palette of shells`, async ({ browser }) => {
    const { page, close } = await newPage(browser, size);
    try {
      await openProduct(page, { hosts: [ADDED], locked: false });
      await closeAllWindows(page);
      const empty = page.locator(".cl-empty");
      await expect(empty).toContainText("No windows open");
      // The list of hosts arrives a moment after the first window: wait for the placeholder that knows both hosts before pressing.
      await expect(empty, "the placeholder knows the added host").toHaveAttribute("data-mode", /^windows:many/, { timeout: 15_000 });
      const open = empty.getByRole("button", { name: "Open shell" });
      await expect(open, "after exit there is a way to open a shell right here").toBeVisible();
      await page.screenshot({ path: tracerEvidencePath("j539", `empty-open-shell-${size.id}.png`) });
      await open.click();
      await expect(page.locator("#palette"), "Open shell opens the palette").toBeVisible();
      await page.screenshot({ path: tracerEvidencePath("j539", `empty-palette-${size.id}.png`) });
      const rows = page.locator("#palette-results [role=option]");
      await expect(rows.filter({ hasText: `Open shell on ${HOST}` }), "the added host is one of the shells to open").toHaveCount(1);
      await expect(rows, "only the shells of the two hosts are listed (the server's own and the added one)").toHaveCount(2);
      await rows.filter({ hasText: `Open shell on ${HOST}` }).click();
      await expect(empty, "the chosen shell took the empty state's place").toHaveCount(0, { timeout: 15_000 });
    } finally { await close(); }
  });

  test(`empty state ${size.id}: a host offline behind the lock says so, offers Unlock, and the server's own host still opens`, async ({ browser }) => {
    const { page, close } = await newPage(browser, size);
    try {
      await openProduct(page, { hosts: [{ ...ADDED, online: false }], locked: true });
      await closeAllWindows(page);
      const empty = page.locator(".cl-empty");
      await expect(empty).toContainText(`${HOST} is locked`);
      await expect(empty.getByRole("button", { name: "Unlock host connections" })).toBeVisible();
      await expect(empty.getByRole("button", { name: "Open shell" }), "the server's own host is not locked").toBeVisible();
      await page.screenshot({ path: tracerEvidencePath("j539", `empty-locked-${size.id}.png`) });
    } finally { await close(); }
  });

  test(`restart ${size.id}: a connected host stays in the tree through a server restart, and an offline one says locked until its agent is back`, async ({ browser }) => {
    const { page, close } = await newPage(browser, size);
    try {
      await openProduct(page, { hosts: [ADDED], locked: false });
      await openSidebar(page);
      await expect(hostRow(page)).toBeVisible({ timeout: 30_000 });
      // The restart: every socket drops, the CA locks, the host (its agent keeps its certificate) stays online.
      await page.request.post("/__mock/restart", { data: {} });
      for (let i = 0; i < 12; i++) {
        // sleep: sampling the tree across the reconnect, so a moment without the host cannot hide between two checks
        await page.waitForTimeout(500);
        await expect(hostRow(page), `sample ${i}: the connected host is still a row`).toBeVisible();
        await expect(hostRow(page), `sample ${i}: an online host carries no lock note`).not.toContainText("locked");
      }
      await expect(page.locator('#tree .bm-leaf[data-id^="u:"]'), "an online host has nothing to unlock").toHaveCount(0);
      // Before its agent is back the host reads offline, and behind the lock it says so and offers the unlock inline.
      await page.request.post("/__mock/restart", { data: { offline: true } });
      await expect(hostRow(page)).toContainText("locked", { timeout: 30_000 });
      await expect(page.locator(`#tree .bm-leaf[data-id="u:${HOST_ID}"]`)).toContainText("Unlock to connect");
      await page.screenshot({ path: tracerEvidencePath("j539", `restart-offline-${size.id}.png`) });
      // The agent reconnects: the list says online, the note and the unlock row go.
      await page.request.post("/__mock/remote-hosts", { data: { hosts: [ADDED] } });
      await expect(hostRow(page)).not.toContainText("locked", { timeout: 30_000 });
      await expect(page.locator('#tree .bm-leaf[data-id^="u:"]')).toHaveCount(0);
    } finally { await close(); }
  });
}
