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
  await expect(notice.getByRole("group", { name: /Saved typing actions/ })).toHaveAttribute("aria-label", /Ctrl\+Shift\+Space/);
  await expect(notice.getByRole("button", { name: "Resend typing" })).toBeVisible();
  await expect(notice.getByRole("button", { name: "Discard" })).toBeVisible();
  await page.screenshot({ path: testInfo.outputPath("retained-typing-actions.png") });
});

test("review: terminal keys stay with the shell and the shortcut reaches saved typing actions", async ({ page }) => {
  const delivered = await pendingTyping(page);
  const card = page.locator('.cl[data-view="console"] .ui-window').first();
  const input = card.locator(".terminal-host textarea");
  const resend = card.getByRole("button", { name: "Resend typing" });
  const discard = card.getByRole("button", { name: "Discard" });
  await input.focus();
  await page.keyboard.press("Tab");
  await expect(input).toBeFocused();
  await expect.poll(() => delivered.join("")).toBe("\t");
  await page.keyboard.press("Shift+Tab");
  await expect(input).toBeFocused();
  await expect.poll(() => delivered.join("")).toBe("\t\u001b[Z");
  await expect(resend).toBeVisible();
  await page.keyboard.press("Control+Shift+Space");
  await expect(resend).toBeFocused();
  await page.keyboard.press("Tab");
  await expect(discard).toBeFocused();
  await page.keyboard.press("Enter");
  await expect(card.locator(".ui-toast")).toBeHidden();
  expect(delivered.join("")).toBe("\t\u001b[Z");
});


test("review: a focused Resend typing button accepts Enter", async ({ page }) => {
  const delivered = await pendingTyping(page);
  const resend = page.getByRole("button", { name: "Resend typing" });
  await resend.focus();
  await page.keyboard.press("Enter");
  await expect.poll(() => delivered.join("")).toBe("synthetic-offline");
  expect(delivered).toHaveLength(1);
});

test("review: typing in the fresh shell does not grow or dismiss the saved typing offer", async ({ page }) => {
  const delivered = await pendingTyping(page);
  const card = page.locator('.cl[data-view="console"] .ui-window').first();
  const input = card.locator(".terminal-host textarea");
  const notice = card.locator(".ui-toast");
  await input.focus();
  await page.keyboard.type("fresh-shell");
  await expect.poll(() => delivered.join("")).toBe("fresh-shell");
  await expect(notice.getByRole("button", { name: "Resend typing" })).toBeVisible();
  await expect(notice.getByRole("button", { name: "Discard" })).toBeVisible();

  await notice.getByRole("button", { name: "Discard" }).click();
  await expect(notice).toBeHidden();
  expect(delivered.join("")).toBe("fresh-shell");
});
