// SPDX-License-Identifier: AGPL-3.0-only
/**
 * A full account's new page takes over the connection of its longest-hidden tab (#523, owner decision B).
 *
 * The account is filled with real tabs and held protocol connections (stand-ins for forgotten tabs that never report
 * being hidden). One real tab is hidden; a newly opened page must then load its canvas at once by taking that tab's
 * connection, and the hidden tab must stay quiet: no reconnect while hidden, which would take another tab's place in
 * turn. Shown again, it takes the place of the tab hidden longest and carries on without a word. A tab that comes back
 * when no other tab is hidden says it is paused (if its return is slow) and, when the server refuses it for the
 * limit, names the limit with Try again; it connects as soon as a tab is closed. Real server, no test double.
 *
 * Visibility is set the way background-tab.spec.ts sets it: `document.hidden` and a `visibilitychange` event, which is
 * all the page reads.
 */
import { expect, test, type BrowserContext, type Page, type WebSocket as PageSocket } from "playwright/test";
import { tracerEvidencePath } from "../test/evidence-path";
import { enrol, windows } from "./layout-devices";
import { watchLayout } from "./layout-observer";
import { ACCOUNT_SOCKETS, holdConnection } from "./held-connection";
import { startRealServer, type RealServer } from "./server";

/** Evidence folder for this spec's screenshots. */
const EVIDENCE = "connection-takeover-523";

/** Marks the page hidden or shown, as a browser does for a background tab. */
const setHidden = (page: Page, hidden: boolean): Promise<void> => page.evaluate((hide) => {
  Object.defineProperty(document, "hidden", { configurable: true, get: () => hide });
  Object.defineProperty(document, "visibilityState", { configurable: true, get: () => (hide ? "hidden" : "visible") });
  document.dispatchEvent(new Event("visibilitychange"));
}, hidden);

/** A tab of the account with a record of its sockets, and a switch that takes this one tab off the network. */
interface Tab { page: Page; sockets: PageSocket[]; offline(on: boolean): Promise<void> }

/** Opens the app in a new tab of `context` and waits for its canvas. */
async function openTab(context: BrowserContext, server: RealServer, width: number): Promise<Tab> {
  const page = await context.newPage();
  await page.setViewportSize({ width, height: width < 600 ? 852 : 900 });
  const sockets: PageSocket[] = [];
  page.on("websocket", (socket) => sockets.push(socket));
  // Per-page network emulation: only this tab goes offline, to hold a returning tab in its paused state.
  const cdp = await context.newCDPSession(page);
  const offline = (on: boolean) => cdp.send("Network.emulateNetworkConditions", { offline: on, latency: 0, downloadThroughput: -1, uploadThroughput: -1 }).then(() => undefined);
  await cdp.send("Network.enable");
  await page.goto(`${server.origin}/?bg=none`);
  await expect(windows(page)).toHaveCount(1, { timeout: 30_000 });
  await expect(page.locator(".startup-notice")).toHaveCount(0);
  return { page, sockets, offline };
}

/** The tab's socket count once it has settled, with every one of them closed. */
async function expectAllClosed(tab: Tab): Promise<void> {
  await expect.poll(() => tab.sockets.every((socket) => socket.isClosed()), { timeout: 15_000 }).toBe(true);
}

/** The persistent takeover toast, by its words. */
const toast = (page: Page, words: string) => page.locator(".ui-toast").filter({ hasText: words });

/** Screenshots `page` at desktop and phone widths, then puts the width back. */
async function receipts(page: Page, name: string, scheme: string): Promise<void> {
  for (const width of [1440, 393]) {
    await page.setViewportSize({ width, height: width < 600 ? 852 : 900 });
    await page.screenshot({ path: tracerEvidencePath(EVIDENCE, `${name}-${width}-${scheme}.png`) });
  }
  await page.setViewportSize({ width: 1440, height: 900 });
}

test("a full account's new page takes over its longest-hidden tab, which pauses and comes back when shown", async ({ browser }) => {
  // Enrolment, then the whole round twice (light and dark): about 3 minutes on a loaded build host.
  test.setTimeout(360_000);
  const server = await startRealServer({ port: Number(process.env.TRACER_TEST_PORT ?? 4673) });
  const context = await browser.newContext({ viewport: { width: 1440, height: 900 }, ignoreHTTPSErrors: true });
  try {
    const first = watchLayout(await context.newPage());
    await enrol(first, server);
    for (const scheme of ["light", "dark"] as const) {
      // Session cookie only, no cached look, so these pages follow the scheme (the enrolled tab's look pins its own).
      const tabs = await context.browser()!.newContext({ storageState: { cookies: await context.cookies(), origins: [] }, colorScheme: scheme, ignoreHTTPSErrors: true });
      const held: { close(): void }[] = [];
      try {
        const old = await openTab(tabs, server, 1440);
        // The enrolled tab and `old` hold two connections; forgotten tabs hold the rest.
        while (held.length < ACCOUNT_SOCKETS - 2) held.push(await holdConnection(server, context));
        await setHidden(old.page, true);

        // The account is full: the new page loads at once by taking the hidden tab's connection.
        const fresh = await openTab(tabs, server, 1440);
        await expectAllClosed(old);
        // sleep: a hidden, taken-over tab must stay quiet; give a reconnect loop time to show itself if there were one.
        await old.page.waitForTimeout(3000);
        expect(old.sockets).toHaveLength(1);

        // `fresh` goes to the background and `old` comes back: `old` takes `fresh`'s connection and carries on quietly.
        await setHidden(fresh.page, true);
        await setHidden(old.page, false);
        await expect(old.page.locator("#terminal-screen")).toHaveAttribute("data-connected", "true", { timeout: 15_000 });
        await expectAllClosed(fresh);
        expect(old.sockets).toHaveLength(2);
        await expect(toast(old.page, "paused")).toHaveCount(0);
        await expect(windows(old.page)).toHaveCount(1);

        // `fresh` comes back while nothing else is hidden. Held off the network for a moment, it says it is paused.
        await fresh.offline(true);
        await setHidden(fresh.page, false);
        const paused = toast(fresh.page, "This tab is paused");
        await expect(paused).toBeVisible({ timeout: 15_000 });
        await expect(paused.getByRole("button", { name: "Resume" })).toBeVisible();
        await receipts(fresh.page, "paused", scheme);

        // Back online, its next try (the network's return, or its backoff) reaches the server, which has no hidden tab
        // to give: the limit is named in the same toast, with Try again.
        await fresh.offline(false);
        const limit = toast(fresh.page, "Too many open tabs");
        await expect(limit).toBeVisible({ timeout: 15_000 });
        await receipts(fresh.page, "limit", scheme);

        // Closing a forgotten tab frees a connection; Try again connects and the toast goes.
        held.pop()?.close();
        await limit.getByRole("button", { name: "Try again" }).click();
        await expect(fresh.page.locator("#terminal-screen")).toHaveAttribute("data-connected", "true", { timeout: 15_000 });
        await expect(toast(fresh.page, "Too many open tabs")).toHaveCount(0);
        await expect(windows(fresh.page)).toHaveCount(1);
        await receipts(fresh.page, "resumed", scheme);
      } finally {
        for (const connection of held) connection.close();
        await tabs.close();
      }
    }
  } finally {
    await context.close();
    await server.dispose();
  }
});
