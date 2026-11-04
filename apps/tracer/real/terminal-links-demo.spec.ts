/** Records terminal link behavior from the production tracer with a real server and local PTY. */
import { expect, test, type BrowserContext, type Page } from "playwright/test";
import { mkdir, mkdtemp, rm } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { personName, startRealServer, type RealServer } from "./server";

const demoPath = process.env.TERMINAL_LINKS_DEMO_PATH;
const address = process.env.TERMINAL_LINKS_DEMO_ADDRESS ?? "127.0.0.1";
const hostname = process.env.TERMINAL_LINKS_DEMO_HOST ?? (address === "127.0.0.1" ? "localhost" : address);
const port = Number(process.env.TRACER_TEST_PORT ?? "4621");

test.describe("terminal links on a real PTY", () => {
  test.skip(!demoPath, "set TERMINAL_LINKS_DEMO_PATH to record the owner demo");
  test.describe.configure({ mode: "serial" });

  let server: RealServer;
  let setupContext: BrowserContext;
  let setupPage: Page;

  test.beforeAll(async ({ browser }) => {
    server = await startRealServer({
      address,
      hostname,
      port,
      ...(process.env.INFRATERNAL_TEST_DATA_ROOT ? { stateRoot: process.env.INFRATERNAL_TEST_DATA_ROOT } : {}),
    });
    setupContext = await browser.newContext({
      ignoreHTTPSErrors: true,
      viewport: { width: 1280, height: 800 },
    });
    setupPage = await setupContext.newPage();
    await enrol(setupPage, server);
  });

  test.afterAll(async () => {
    await setupContext?.close();
    await server?.dispose();
  });

  test("records safe URL, wrapped URL, OSC 8, file URL and mailto behavior", async ({ browser }) => {
    test.setTimeout(180_000);
    const outputPath = resolve(demoPath!);
    await mkdir(dirname(outputPath), { recursive: true });
    const recordingRoot = process.env.TERMINAL_LINKS_DEMO_TMP_ROOT ?? dirname(outputPath);
    await mkdir(recordingRoot, { recursive: true });
    const recordingDirectory = await mkdtemp(resolve(recordingRoot, "terminal-links-recording-"));
    const context = await browser.newContext({
      ignoreHTTPSErrors: true,
      viewport: { width: 1280, height: 800 },
      recordVideo: { dir: recordingDirectory, size: { width: 1280, height: 800 } },
    });
    const cookies = await setupContext.cookies(server.origin);
    await context.addCookies(cookies);
    await context.route("https://links.example.test/**", (route) => route.fulfill({
      status: 200,
      contentType: "text/html",
      body: "<!doctype html><title>Opened terminal link</title><main>Opened link</main>",
    }));
    await context.addInitScript(() => {
      const calls: string[] = [];
      (window as unknown as { __demoOpenCalls: string[] }).__demoOpenCalls = calls;
      const nativeOpen = window.open.bind(window);
      window.open = ((...args: Parameters<typeof window.open>) => {
        calls.push(String(args[0]));
        return String(args[0]).startsWith("mailto:") ? null : nativeOpen(...args);
      }) as typeof window.open;
    });

    const page = await context.newPage();
    const video = page.video();
    if (!video) throw new Error("the demo page did not start video recording");
    try {
      await page.goto(`${server.origin}/?theme=ink&bg=none`);
      await page.locator(".cl-viewport").waitFor();
      await expect(page.locator('.cl[data-view="console"]')).toBeVisible();
      await expect(page.locator("#terminal-host canvas").first()).toBeVisible();
      await page.waitForTimeout(3_000);

      const shortUrl = "https://links.example.test/docs?view=terminal";
      await printAtTop(page, shortUrl, server);
      const canvas = page.locator("#terminal-host canvas").first();
      const point = await hoverFirstCell(page, canvas);
      await expect(canvas).toHaveCSS("cursor", "pointer");
      await page.waitForTimeout(3_000);
      await openWithControlClick(page, context, point, shortUrl);
      await page.waitForTimeout(2_000);

      const wrappedUrl = "https://links.example.test/oauth/authorize?client_id=demo&state=display-only&redirect_uri=https%3A%2F%2Flinks.example.test%2Fcallback&response_type=code";
      await printAtTop(page, wrappedUrl, server);
      const wrappedPoint = await hoverFirstCell(page, canvas);
      await expect(canvas).toHaveCSS("cursor", "pointer");
      await page.waitForTimeout(4_000);
      await openWithControlClick(page, context, wrappedPoint, wrappedUrl);
      await page.waitForTimeout(2_000);

      const osc8Target = "https://links.example.test/real-account";
      const osc8Text = String.raw`\033]8;;${osc8Target}\007Sign in\033]8;;\007`;
      await printAtTop(page, osc8Text, server, true, "Sign in");
      const osc8Point = await hoverFirstCell(page, canvas);
      await expect(canvas).toHaveCSS("cursor", "pointer");
      await expect(page.locator(".tip-label:not(.is-leaving)")).toHaveText(osc8Target);
      await page.waitForTimeout(4_000);
      await openWithControlClick(page, context, osc8Point, osc8Target);
      await page.waitForTimeout(2_000);

      await printAtTop(page, "file:///home/demo/main.rs:42", server);
      const filePoint = await hoverFirstCell(page, canvas);
      await expect(canvas).toHaveCSS("cursor", "text");
      await page.waitForTimeout(3_000);
      await page.mouse.click(filePoint.x, filePoint.y);

      await printAtTop(page, "mailto:person@example.test", server);
      await hoverFirstCell(page, canvas);
      await expect(canvas).toHaveCSS("cursor", "pointer");
      await page.waitForTimeout(2_000);
      await page.keyboard.press("Control+Shift+K");
      const paletteInput = page.locator("#palette-input");
      await paletteInput.fill("Open link: example.test");
      await expect(page.locator(".result").filter({ hasText: "Open link: example.test…" })).toBeVisible();
      await page.waitForTimeout(5_000);
      await paletteInput.press("Enter");
      await page.keyboard.press("Escape");
      await page.waitForTimeout(2_000);
      expect(await page.evaluate(() => (window as unknown as { __demoOpenCalls: string[] }).__demoOpenCalls)).toContain(shortUrl);
      expect(await page.evaluate(() => (window as unknown as { __demoOpenCalls: string[] }).__demoOpenCalls)).toContain(wrappedUrl);
      expect(await page.evaluate(() => (window as unknown as { __demoOpenCalls: string[] }).__demoOpenCalls)).toContain(osc8Target);
      expect(await page.evaluate(() => (window as unknown as { __demoOpenCalls: string[] }).__demoOpenCalls)).not.toContain("file:///home/demo/main.rs:42");
      expect(await page.evaluate(() => (window as unknown as { __demoOpenCalls: string[] }).__demoOpenCalls)).toContain("mailto:person@example.test");
    } finally {
      await context.close();
      await video.saveAs(outputPath);
      await rm(recordingDirectory, { recursive: true, force: true });
    }
  });
});

/** Creates a temporary signed-in account before video capture, keeping the setup capability off-screen. */
async function enrol(page: Page, server: RealServer): Promise<void> {
  const cdp = await page.context().newCDPSession(page);
  await cdp.send("WebAuthn.enable");
  await cdp.send("WebAuthn.addVirtualAuthenticator", {
    options: {
      protocol: "ctap2",
      ctap2Version: "ctap2_1",
      transport: "internal",
      hasResidentKey: true,
      hasUserVerification: true,
      isUserVerified: true,
      automaticPresenceSimulation: true,
      hasPrf: true,
    },
  });
  await page.goto(server.origin + "/");
  await page.locator("#setup-token").fill(server.token);
  await page.getByRole("button", { name: "Continue", exact: true }).click();
  await page.locator("#setup-username").fill(personName("terminal_links_demo"));
  await page.locator("#setup-display-name").fill("Terminal links demo");
  await page.getByRole("button", { name: "Continue", exact: true }).click();
  await page.getByRole("button", { name: "Create passkey" }).click();
  await page.getByRole("heading", { name: "Save your recovery key" }).waitFor();
  await page.locator(".auth-check").click();
  await page.getByRole("button", { name: "Open infraternal" }).click();
  await page.locator(".cl-viewport").waitFor();
}

async function printAtTop(page: Page, value: string, server: RealServer, escaped = false, visibleMarker = value): Promise<void> {
  const host = page.locator(".terminal-host").first();
  const bounds = await host.boundingBox();
  if (!bounds) throw new Error("the real terminal host is not visible");
  await page.mouse.click(bounds.x + bounds.width / 2, bounds.y + bounds.height / 2);
  const format = escaped ? String.raw`printf '\033[2J\033[H%b\n' '${value}'` : String.raw`printf '\033[2J\033[H%s\n' '${value}'`;
  await page.keyboard.type(format, { delay: 2 });
  await page.keyboard.press("Enter");
  await expect.poll(() => [...(server.bridges.at(-1)?.output.values() ?? [])].join("").includes(visibleMarker), { timeout: 15_000 }).toBe(true);
  await page.waitForTimeout(600);
}

async function hoverFirstCell(page: Page, canvas: ReturnType<Page["locator"]>): Promise<{ x: number; y: number }> {
  const bounds = await canvas.boundingBox();
  if (!bounds) throw new Error("the real terminal canvas is not visible");
  const point = { x: bounds.x + Math.min(10, bounds.width / 4), y: bounds.y + Math.min(8, bounds.height / 4) };
  await page.mouse.move(point.x, point.y);
  return point;
}

async function openWithControlClick(page: Page, context: BrowserContext, point: { x: number; y: number }, target: string): Promise<void> {
  const popupEvent = context.waitForEvent("page", { timeout: 10_000 });
  await page.keyboard.down("Control");
  await page.mouse.click(point.x, point.y);
  await page.keyboard.up("Control");
  const popup = await popupEvent;
  await expect(popup).toHaveURL(target);
  await popup.close();
  await page.bringToFront();
}
