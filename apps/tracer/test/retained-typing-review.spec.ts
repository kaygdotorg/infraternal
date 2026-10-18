/** Independent #244 production-browser keyboard and decline checks after a refused resume. */
import { expect, test, type Page, type WebSocketRoute } from "playwright/test";
import { encodeMuxedFrame, WebSocketFrameDecoder } from "../../../packages/protocol/src/codec";

/** Force one refused capability while retaining deterministic typing between disconnect and fresh Welcome. */
async function pendingTyping(page: Page): Promise<string[]> {
  const delivered: string[] = [];
  const request = page.context().request;
  await request.post("/__mock/reset");
  await request.post("/__mock/open-terminal");
  let routes = 0;
  let initial: WebSocketRoute | undefined;
  let initialUpstream: WebSocketRoute | undefined;
  let refusal: WebSocketRoute | undefined;
  let resumeSeen = false;
  await page.routeWebSocket(/\/v1\/ws(?:\?|$)/, (socket) => {
    routes += 1;
    if (routes === 2) {
      refusal = socket;
      socket.onMessage((message) => {
        if (typeof message !== "string") new WebSocketFrameDecoder().feed(new Uint8Array(message), (_stream, frame) => {
          if (frame.type === "Resume") resumeSeen = true;
        });
      });
      return;
    }
    const upstream = socket.connectToServer();
    socket.onMessage((message) => {
      if (typeof message !== "string") new WebSocketFrameDecoder().feed(new Uint8Array(message), (_stream, frame) => {
        if (frame.type === "Input") delivered.push(new TextDecoder().decode(frame.bytes));
      });
      upstream.send(message);
    });
    if (routes === 1) { initial = socket; initialUpstream = upstream; }
  });
  await page.goto("/?theme=ink&bg=none");
  const card = page.locator('.cl[data-view="console"] .ui-window').first();
  await expect(card).toHaveAttribute("data-status", "live", { timeout: 30_000 });
  await card.locator(".terminal-host textarea").focus();
  initialUpstream!.close();
  initial!.close();
  await expect.poll(() => resumeSeen).toBe(true);
  await page.keyboard.type("synthetic-offline");
  refusal!.send(Buffer.from(encodeMuxedFrame(0, { type: "Close", code: 1008, reason: "the server refused to resume the connection" })));
  await expect(card.getByRole("button", { name: "Resend typing" })).toBeVisible();
  await expect(card).toHaveAttribute("data-status", "live");
  expect(delivered).toHaveLength(0);
  return delivered;
}

test("review: saved typing offers a non-resend exit in the live terminal window", async ({ page }, testInfo) => {
  await pendingTyping(page);
  const notice = page.locator('.cl[data-view="console"] .ui-window .ui-toast');
  await expect(notice.getByRole("status")).toHaveAttribute("aria-live", "polite");
  await page.screenshot({ path: testInfo.outputPath("retained-typing-no-decline.png") });
  await expect(notice.getByRole("button", { name: /dismiss|discard|cancel|decline/i })).toBeVisible();
});

test("review: keyboard can reach Resend typing from the terminal without sending more typing", async ({ page }) => {
  const delivered = await pendingTyping(page);
  const card = page.locator('.cl[data-view="console"] .ui-window').first();
  const input = card.locator(".terminal-host textarea");
  await input.focus();
  await page.keyboard.press("Tab");
  await page.keyboard.press("Shift+Tab");
  const trapped = await input.evaluate(element => document.activeElement === element);
  // Prove those navigation attempts were retained as terminal input. The
  // button itself supports Enter after a test-only programmatic focus.
  await card.getByRole("button", { name: "Resend typing" }).focus();
  await page.keyboard.press("Enter");
  await expect.poll(() => delivered.join("")).toBe("synthetic-offline\t\u001b[Z");
  expect(trapped, "Tab and Shift+Tab must allow reaching the pending consent control").toBe(false);
});


test("review: a focused Resend typing button accepts Enter", async ({ page }) => {
  const delivered = await pendingTyping(page);
  const resend = page.getByRole("button", { name: "Resend typing" });
  await resend.focus();
  await page.keyboard.press("Enter");
  await expect.poll(() => delivered.join("")).toBe("synthetic-offline");
  expect(delivered).toHaveLength(1);
});
