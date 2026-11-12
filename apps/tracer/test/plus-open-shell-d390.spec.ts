// SPDX-License-Identifier: AGPL-3.0-only
/**
 * D390 (#500, #194): the "+" beside the top pill. With exactly one admitted host it opens that host's shell straight away; with several it opens
 * the command palette showing only the "Open shell on <host>" rows, one per admitted host, offline ones included. Checked in a production
 * build at a desktop width and at the two iPhone widths.
 */
import { expect, test, type Page } from "playwright/test";
import { decodeMuxedFrame, encodeMuxedFrame } from "../../../packages/protocol/src/codec";

/** The desktop and phone sizes of the review (TASTE: check 1440, 402 and 375). */
const SIZES = [
  { name: "1440", viewport: { width: 1440, height: 900 }, touch: false },
  { name: "402", viewport: { width: 402, height: 874 }, touch: true },
  { name: "375", viewport: { width: 375, height: 812 }, touch: true },
] as const;

/** Adds admitted hosts to the page's host list, as the server's `remote.host.list` would answer them. */
async function admitHosts(page: Page, hosts: Array<{ id: string; name: string; online: boolean }>): Promise<() => number> {
  let reads = 0;
  await page.routeWebSocket(/\/v1\/ws(?:\?|$)/, (socket) => {
    const server = socket.connectToServer();
    socket.onMessage((message) => {
      if (typeof message !== "string") {
        const { frame } = decodeMuxedFrame(message);
        if (frame.type === "Call" && frame.actionId === "remote.host.list") {
          reads++;
          socket.send(Buffer.from(encodeMuxedFrame(0, {
            type: "Result", callId: frame.callId, ok: true,
            json: new TextEncoder().encode(JSON.stringify({ hosts, next: null })),
          })));
          return;
        }
      }
      server.send(message);
    });
    server.onMessage((message) => socket.send(message));
  });
  return () => reads;
}

/** The "Open shell on …" options the palette lists right now. */
const shellRows = (page: Page) => page.getByRole("option").filter({ hasText: /^\s*›?_?\s*Open shell on / });
/** The palette's visible options. */
const options = (page: Page) => page.locator("#palette-results [role=option]");

for (const size of SIZES) {
  test.describe(`+ at ${size.name}`, () => {
    test.use({ viewport: size.viewport, hasTouch: size.touch, isMobile: size.touch });

    test("with several hosts, + opens the palette with one Open shell on row per host and nothing else", async ({ page }) => {
      await page.request.post("/__mock/reset");
      const reads = await admitHosts(page, [
        { id: "11111111-2222-3333-4444-555555555551", name: "review-online-host", online: true },
        { id: "11111111-2222-3333-4444-555555555552", name: "review-offline-host", online: false },
      ]);
      await page.goto("/?mock=1&proto=product&fresh=1&bg=none");
      await expect.poll(reads, { timeout: 20_000 }).toBeGreaterThan(0);
      await page.keyboard.press("Control+Shift+K");
      await expect(page.locator("#palette")).toBeVisible();
      await expect(page.getByRole("option").filter({ hasText: "Open shell on review-offline-host" })).toHaveCount(1);
      const everyHost = await shellRows(page).count();
      expect(everyHost, "the whole palette lists the mock host and both admitted hosts").toBeGreaterThanOrEqual(3);
      await page.keyboard.press("Escape");
      await expect(page.locator("#palette")).toBeHidden();

      await page.getByRole("button", { name: "New window", exact: true }).click();
      await expect(page.locator("#palette")).toBeVisible();
      await expect(options(page)).toHaveCount(everyHost);
      const labels = await options(page).allInnerTexts();
      for (const label of labels) expect(label, `a scoped row: ${label}`).toMatch(/Open shell on /);
      await expect(page.getByRole("option").filter({ hasText: "Open shell on review-offline-host" })).toBeVisible();
      await expect(page.getByRole("option").filter({ hasText: "Open shell on review-online-host" })).toBeVisible();
      // The palette is still a palette: typing narrows the scoped rows, and choosing one opens that host's shell.
      await page.locator("#palette-input").fill("online");
      await expect(options(page)).toHaveCount(1);
      const before = await page.locator("[data-view='console'] .ui-window").count();
      await options(page).first().click();
      await expect(page.locator("#palette")).toBeHidden();
      await expect(page.locator("[data-view='console'] .ui-window")).toHaveCount(before + 1);
    });

    test("with exactly one host, + opens that host's shell directly", async ({ page }) => {
      await page.request.post("/__mock/reset");
      await page.goto("/?mock=1&proto=product&fresh=1&bg=none");
      await expect(page.locator("[data-view='console'] .ui-window").first()).toBeVisible({ timeout: 45_000 });
      await page.keyboard.press("Control+Shift+K");
      await expect(shellRows(page), "the guard: this page has exactly one admitted host").toHaveCount(1);
      await page.keyboard.press("Escape");
      const before = await page.locator("[data-view='console'] .ui-window").count();
      await page.getByRole("button", { name: "New window", exact: true }).click();
      await expect(page.locator("[data-view='console'] .ui-window")).toHaveCount(before + 1);
      await expect(page.locator("#palette")).toBeHidden();
    });
  });
}
