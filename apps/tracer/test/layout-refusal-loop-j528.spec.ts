// SPDX-License-Identifier: AGPL-3.0-only
/**
 * A refused look save must not be retried in a loop (#500, J528).
 *
 * J521 saw "That layout change was not saved. The saved layout is back." climb past 1,000. The mechanism: the account's saved look
 * can lack the canvas-level fields a newer page writes (window sizes, extended info, UI font). The page completes such a look by
 * saving it once; if the server refuses that save (an older or stricter server), the saved look comes back, still incomplete, and
 * the page completed it again, and again, one toast each time, at network speed.
 *
 * The interceptor refuses every `look.set` layout save and counts them; the double's account document is then replaced by one
 * whose look lacks those fields. The count must stop growing after the first refusal (the next real change of the look tries again),
 * at 1440, 402 and 375 px. Functional: no speed is asserted, only that the number of refused saves stops growing.
 */
import { expect, test, type Page } from "playwright/test";
import { decodeMuxedFrame, encodeMuxedFrame } from "../../../packages/protocol/src/codec";

/** The three review widths. */
const SIZES = [
  { id: "1440", viewport: { width: 1440, height: 900 }, touch: false },
  { id: "402", viewport: { width: 402, height: 720 }, touch: true },
  { id: "375", viewport: { width: 375, height: 640 }, touch: true },
] as const;

/** Refuses every `look.set` layout save the page sends and counts them; every other call goes to the test double. */
async function refuseLookSaves(page: Page): Promise<{ refused: () => number; arm: () => void }> {
  let refused = 0, armed = false;
  await page.routeWebSocket(/\/v1\/ws(?:\?|$)/, (socket) => {
    const server = socket.connectToServer();
    socket.onMessage((message) => {
      if (typeof message !== "string") {
        const { frame } = decodeMuxedFrame(message);
        if (frame.type === "Call" && frame.actionId === "canvas.layout.apply") {
          const input = JSON.parse(new TextDecoder().decode(frame.inputJson)) as { intent?: { type?: string } };
          if (armed && input.intent?.type === "look.set") {
            refused++;
            socket.send(Buffer.from(encodeMuxedFrame(0, { type: "Result", callId: frame.callId, ok: false, json: new TextEncoder().encode('{"error":"invalid canvas operation"}') })));
            return;
          }
        }
      }
      server.send(message);
    });
    server.onMessage((message) => socket.send(message));
  });
  return { refused: () => refused, arm: () => { armed = true; } };
}

for (const size of SIZES) {
  test(`a refused look save is not retried in a loop: ${size.id}`, async ({ browser }) => {
    const context = await browser.newContext({ viewport: size.viewport, deviceScaleFactor: size.touch ? 3 : 1, ...(size.touch ? { hasTouch: true, isMobile: true } : {}) });
    const page = await context.newPage();
    try {
      const { refused, arm } = await refuseLookSaves(page);
      await page.request.post("/__mock/reset");
      await page.goto("/?mock=1&proto=product&layout=server&fresh=1&bg=none&theme=ink");
      await expect(page.locator(".ui-window").first().locator(".ui-window-host")).toHaveText(/\S/, { timeout: 40_000 });
      // Let the page's own first saves settle, then hand it an account look written by an older page: no canvas-level fields.
      // sleep: the first saves and the look's own announce delay
      await page.waitForTimeout(2500);
      // From here the server refuses look saves, as an older or stricter one would.
      arm();
      const before = refused();
      const replaced = await page.evaluate(async () => {
        const read = await (await fetch("/__mock/layout")).json() as { document: { look?: Record<string, unknown> } };
        const document = read.document;
        // The double's own copy of the account document: the look the page saved when it first loaded.
        if (!document.look) throw new Error(`no look in the account document: ${Object.keys(document).join(",")}`);
        delete document.look.windowSizes; delete document.look.extendedInfo; delete document.look.uiFont;
        return (await fetch("/__mock/layout", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ document }) })).ok;
      });
      expect(replaced, "the double took the older look").toBe(true);
      await expect.poll(() => refused(), { timeout: 15_000, message: "the page tries to complete the look at least once" }).toBeGreaterThan(before);
      // sleep: let any retry loop run so its growth shows
      await page.waitForTimeout(2000);
      const first = refused();
      // sleep: a second read after more time proves the count has stopped growing
      await page.waitForTimeout(2000);
      const second = refused();
      expect(second, `look saves refused: ${first} then ${second}; a loop keeps growing`).toBe(first);
      expect(second - before, "one refusal, not hundreds").toBeLessThanOrEqual(3);
    } finally { await context.close(); }
  });
}
