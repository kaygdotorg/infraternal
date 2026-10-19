/** Independent #244 production-browser keyboard and decline checks after a refused resume. */
import { expect, test, type Page, type WebSocketRoute } from "playwright/test";
import { encodeMuxedFrame, WebSocketFrameDecoder } from "../../../packages/protocol/src/codec";

/** Force one refused capability while retaining deterministic typing between disconnect and fresh Welcome. */
async function pendingTyping(page: Page, theme = "ink"): Promise<string[]> {
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
  await page.goto(`/?mock=1&proto=product&theme=${theme}&bg=none`);
  const card = page.locator('.cl[data-view="console"] .ui-window').first();
  await expect(card).toHaveAttribute("data-status", "live", { timeout: 30_000 });
  await card.locator(".terminal-host textarea").focus();
  initialUpstream!.close();
  initial!.close();
  await expect.poll(() => resumeSeen).toBe(true);
  await page.keyboard.type("synthetic-offline");
  refusal!.send(Buffer.from(encodeMuxedFrame(0, { type: "Close", code: 1008, reason: "the server refused to resume the connection" })));
  await expect(card.getByRole("button", { name: "Send again" })).toBeVisible();
  await expect(card).toHaveAttribute("data-status", "live");
  expect(delivered).toHaveLength(0);
  return delivered;
}

test("review: saved typing offers a non-resend exit in the live terminal window", async ({ page }, testInfo) => {
  await pendingTyping(page);
  const notice = page.locator('.cl[data-view="console"] .ui-window .ui-toast');
  await expect(notice.getByRole("status")).toHaveAttribute("aria-live", "polite");
  await expect(notice.getByRole("group", { name: /Saved typing actions/ })).toHaveAttribute("aria-label", /Ctrl\+Shift\+Space/);
  await expect(notice.getByRole("button", { name: "Send again" })).toBeVisible();
  await expect(notice.getByRole("button", { name: "Discard" })).toBeVisible();
  await page.screenshot({ path: testInfo.outputPath("retained-typing-actions.png") });
});

test("review: terminal keys stay with the shell and the shortcut reaches saved typing actions", async ({ page }) => {
  const delivered = await pendingTyping(page);
  const card = page.locator('.cl[data-view="console"] .ui-window').first();
  const input = card.locator(".terminal-host textarea");
  const resend = card.getByRole("button", { name: "Send again" });
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


test("review: a focused Send again button accepts Enter", async ({ page }) => {
  const delivered = await pendingTyping(page);
  const resend = page.getByRole("button", { name: "Send again" });
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
  await expect(notice.getByRole("button", { name: "Send again" })).toBeVisible();
  await expect(notice.getByRole("button", { name: "Discard" })).toBeVisible();

  await notice.getByRole("button", { name: "Discard" }).click();
  await expect(notice).toBeHidden();
  expect(delivered.join("")).toBe("fresh-shell");
});

for (const choice of ["Discard", "Send again"]) {
  test(`review: keyboard ${choice} preserves committed text input in the live shell`, async ({ page }, testInfo) => {
    const delivered = await pendingTyping(page);
    const card = page.locator('.cl[data-view="console"] .ui-window').first();
    const input = card.locator(".terminal-host textarea");
    await input.focus();
    await page.keyboard.press("Control+Shift+Space");
    await expect(card.getByRole("button", { name: "Send again" })).toBeFocused();
    if (choice === "Discard") await page.keyboard.press("Tab");
    await expect(card.getByRole("button", { name: choice })).toBeFocused();
    await page.keyboard.press("Enter");
    await expect(card.locator(".ui-toast")).toBeHidden();
    await page.screenshot({ path: testInfo.outputPath(`after-${choice.replaceAll(" ", "-")}.png`) });
    await page.keyboard.type("after-choice");
    await expect.poll(() => delivered.join("")).toBe(
      `${choice === "Send again" ? "synthetic-offline" : ""}after-choice`,
    );
    await expect.poll(() => card.locator(".terminal-host").evaluate((host) => host.contains(document.activeElement))).toBe(true);
    // Focus stays in the terminal and physical keys work; text-only input must work too.
    await page.keyboard.insertText("漢字");
    await expect.poll(() => delivered.join("")).toBe(
      `${choice === "Send again" ? "synthetic-offline" : ""}after-choice漢字`,
    );
  });
}

test("review: committed text reaches a focused fresh terminal", async ({ page }) => {
  const delivered = await pendingTyping(page);
  await page.getByRole("button", { name: "Discard" }).click();
  await page.locator('.cl[data-view="console"] .ui-window .terminal-host textarea').first().focus();
  await page.keyboard.insertText("漢字");
  await expect.poll(() => delivered.join("")).toBe("漢字");
});

test("review: repeated native activation sends the saved marker once", async ({ page }) => {
  const delivered = await pendingTyping(page);
  await page.getByRole("button", { name: "Send again" }).evaluate((button) => {
    (button as HTMLButtonElement).click();
    (button as HTMLButtonElement).click();
  });
  await expect.poll(() => delivered.join("")).toBe("synthetic-offline");
  expect(delivered).toHaveLength(1);
});

test("review: pending typing is absent from storage writes and console and is retired at sign-out", async ({ page }) => {
  let markerLogs = 0;
  page.on("console", (message) => { if (message.text().includes("synthetic-offline")) markerLogs += 1; });
  await page.addInitScript(() => {
    const state = window as unknown as { reviewMarkerWrites: number };
    state.reviewMarkerWrites = 0;
    const original = Storage.prototype.setItem;
    Storage.prototype.setItem = function (key: string, value: string): void {
      if (`${key}${value}`.includes("synthetic-offline")) state.reviewMarkerWrites += 1;
      original.call(this, key, value);
    };
  });
  const delivered = await pendingTyping(page);
  expect(await page.evaluate(() => (window as unknown as { reviewMarkerWrites: number }).reviewMarkerWrites)).toBe(0);
  expect(markerLogs).toBe(0);
  await page.keyboard.press("Control+Shift+K");
  await page.locator("#palette-input").fill("sign out");
  await page.keyboard.press("Enter");
  await page.locator('.ui-confirm-tip[data-open="true"]').getByRole("button", { name: "Sign out" }).click();
  await expect(page.getByRole("heading", { name: "Welcome back" })).toBeVisible();
  await expect(page.locator(".ui-window, .ui-toast")).toHaveCount(0);
  await page.keyboard.press("Control+Shift+Space");
  await page.keyboard.press("Enter");
  expect(delivered).toHaveLength(0);
  expect(markerLogs).toBe(0);
  await page.reload();
  await expect(page.getByRole("heading", { name: "Welcome back" })).toBeVisible();
  await page.context().request.post("/__mock/reset");
});

test("review: plain Ctrl Space stays with the shell and the focus chord is inert after Discard", async ({ page }) => {
  const delivered = await pendingTyping(page);
  const input = page.locator('.cl[data-view="console"] .ui-window .terminal-host textarea').first();
  await input.focus();
  await page.keyboard.press("Control+Space");
  await expect.poll(() => delivered.join("")).toBe("\u0000");
  await expect(page.getByRole("button", { name: "Discard" })).toBeVisible();
  await page.getByRole("button", { name: "Discard" }).click();
  await input.focus();
  await page.keyboard.press("Control+Shift+Space");
  await expect.poll(() => delivered.join("")).toBe("\u0000\u0000");
  await expect(input).toBeFocused();
});

test("review: closing a pending window leaves no saved-input action behind", async ({ page }) => {
  const delivered = await pendingTyping(page);
  await page.locator('.cl[data-view="console"] .ui-window .terminal-host textarea').first().focus();
  await page.keyboard.press("Control+Shift+X");
  await expect(page.locator('.cl[data-view="console"] .ui-window')).toHaveCount(0);
  await expect(page.getByRole("button", { name: "Send again" })).toHaveCount(0);
  await page.keyboard.press("Control+Shift+Space");
  await page.keyboard.press("Enter");
  expect(delivered).toHaveLength(0);
});

for (const width of [1440, 393, 375]) for (const theme of ["ink", "paper"]) {
  test(`review: stacked saved typing actions fit and receive clicks at ${width}px ${theme}`, async ({ browser }, info) => {
    const phone = width < 600;
    const context = await browser.newContext({
      viewport: { width, height: phone ? (width === 375 ? 667 : 852) : 900 },
      hasTouch: phone, isMobile: phone, deviceScaleFactor: phone ? 3 : 1,
    });
    try {
      const page = await context.newPage();
      const delivered = await pendingTyping(page, theme);
      const card = page.locator('.cl[data-view="console"] .ui-window').first();
      const notice = card.locator(".ui-toast");
      await expect(notice).toHaveAttribute("data-stacked", "true");
      const message = (await notice.getByRole("status").boundingBox())!;
      const actions = (await notice.getByRole("group", { name: /Saved typing actions/ }).boundingBox())!;
      expect(message.y + message.height).toBeLessThanOrEqual(actions.y + 1);
      const host = (await card.boundingBox())!;
      for (const name of ["Send again", "Discard"]) {
        const button = notice.getByRole("button", { name, exact: true });
        const box = (await button.boundingBox())!;
        expect(box.x).toBeGreaterThanOrEqual(Math.max(0, host.x));
        expect(box.x + box.width).toBeLessThanOrEqual(Math.min(width, host.x + host.width));
        if (phone) expect(box.height).toBeGreaterThanOrEqual(44);
        await button.click({ trial: true });
      }
      await page.screenshot({ path: info.outputPath(`offer-${width}-${theme}.png`) });
      await notice.getByRole("button", { name: theme === "ink" ? "Send again" : "Discard" }).click();
      await expect(notice).toBeHidden();
      await expect.poll(() => delivered.join("")).toBe(theme === "ink" ? "synthetic-offline" : "");
    } finally { await context.close(); }
  });
}

/** Browser composition must keep its text target while a pending typing notice is visible. */
for (const pending of [false, true]) test(`review: active composition survives the focus chord with a ${pending ? "pending" : "resolved"} typing choice`, async ({ page }) => {
  await pendingTyping(page);
  if (!pending) {
    await page.getByRole("button", { name: "Discard" }).click();
    await expect(page.locator('.cl[data-view="console"] .ui-window .ui-toast').first()).toBeHidden();
  }
  const input = page.locator('.cl[data-view="console"] .ui-window .terminal-host textarea').first();
  await input.focus();
  await input.evaluate((element) => {
    const target = element as HTMLElement;
    target.dataset.reviewCompositionStarted = "0";
    target.dataset.reviewCompositionEnded = "0";
    element.addEventListener("compositionstart", () => { target.dataset.reviewCompositionStarted = "1"; });
    element.addEventListener("compositionend", () => { target.dataset.reviewCompositionEnded = "1"; });
    const record = (event: KeyboardEvent): void => {
      if (event.code !== "Space") return;
      target.dataset.reviewSpaceComposing = String(event.isComposing);
      target.dataset.reviewSpaceTrusted = String(event.isTrusted);
      window.removeEventListener("keydown", record, true);
    };
    window.addEventListener("keydown", record, true);
  });
  const session = await page.context().newCDPSession(page);
  try {
    await session.send("Input.imeSetComposition", { text: "漢", selectionStart: 1, selectionEnd: 1 });
    await expect(input).toHaveAttribute("data-review-composition-started", "1");
    await expect(input).toHaveAttribute("data-review-composition-ended", "0");
    await page.keyboard.press("Control+Shift+Space");
    await expect(input).toHaveAttribute("data-review-space-composing", "true");
    await expect(input).toHaveAttribute("data-review-space-trusted", "true");
    await expect(input).toHaveAttribute("data-review-composition-ended", "0");
    await expect(input).toBeFocused();
  } finally { await session.detach(); }
});
