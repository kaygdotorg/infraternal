// SPDX-License-Identifier: AGPL-3.0-only
/**
 * A refused layout save must not be retried in a loop (#500, J528).
 *
 * J521 saw "That layout change was not saved. The saved layout is back." climb past 1,000 during Add host. The mechanism: a
 * window this tab opened is not in the server's layout until a save is accepted. When the server refuses the save, the layout
 * is repainted from the server's copy; the repaint kept the unsaved window (it is the person's) and asked for a save again, which
 * was refused again, forever, at network speed, one toast each time.
 *
 * The interceptor refuses every `canvas.layout.apply` and counts them. After one new window is opened the count must stay
 * small (a refusal is told once, and the next save waits for the next change the person makes), at 1440, 402 and 375 px.
 * Functional: no speed is asserted, only that the number of refused saves stops growing.
 */
import { expect, test, type Page } from "playwright/test";
import { decodeMuxedFrame, encodeMuxedFrame } from "../../../packages/protocol/src/codec";

/** The three review widths. */
const SIZES = [
  { id: "1440", viewport: { width: 1440, height: 900 }, touch: false },
  { id: "402", viewport: { width: 402, height: 720 }, touch: true },
  { id: "375", viewport: { width: 375, height: 640 }, touch: true },
] as const;

/** Refuses every layout save the page sends and counts them; every other call goes to the test double. */
async function refuseSaves(page: Page): Promise<{ saves: () => number }> {
  let saves = 0;
  await page.routeWebSocket(/\/v1\/ws(?:\?|$)/, (socket) => {
    const server = socket.connectToServer();
    socket.onMessage((message) => {
      if (typeof message !== "string") {
        const { frame } = decodeMuxedFrame(message);
        if (frame.type === "Call" && frame.actionId === "canvas.layout.apply") {
          saves++;
          socket.send(Buffer.from(encodeMuxedFrame(0, { type: "Result", callId: frame.callId, ok: false, json: new TextEncoder().encode('{"error":"invalid canvas operation"}') })));
          return;
        }
      }
      server.send(message);
    });
    server.onMessage((message) => socket.send(message));
  });
  return { saves: () => saves };
}

for (const size of SIZES) {
  test(`a refused layout save is not retried in a loop: ${size.id}`, async ({ browser }) => {
    const context = await browser.newContext({ viewport: size.viewport, deviceScaleFactor: size.touch ? 3 : 1, ...(size.touch ? { hasTouch: true, isMobile: true } : {}) });
    const page = await context.newPage();
    try {
      const { saves } = await refuseSaves(page);
      await page.request.post("/__mock/reset");
      await page.goto("/?mock=1&proto=product&layout=server&fresh=1&bg=none&theme=ink");
      await expect(page.locator(".ui-window").first().locator(".ui-window-host")).toHaveText(/\S/, { timeout: 40_000 });
      const before = saves();
      // A new window is a layout change the server refuses.
      await page.getByRole("button", { name: "New window", exact: true }).click();
      await expect.poll(() => saves(), { timeout: 15_000, message: "the new window is saved at least once" }).toBeGreaterThan(before);
      // A loop keeps counting; a bounded retry stops. Compare two reads two seconds apart, then the total.
      // sleep: let any retry loop run so its growth shows
      await page.waitForTimeout(2000);
      const first = saves();
      // sleep: a second read after more time proves the count has stopped growing
      await page.waitForTimeout(2000);
      const second = saves();
      expect(second, `saves refused: ${first} then ${second}; a loop keeps growing`).toBe(first);
      expect(second - before, "one refusal per change the person made, not hundreds").toBeLessThanOrEqual(5);
    } finally { await context.close(); }
  });
}
