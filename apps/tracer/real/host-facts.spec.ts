/** Exercises the host facts action end to end on the real embedded agent and captures the production popover. */
import { tracerEvidencePath } from "../test/evidence-path";
import { execFileSync } from "node:child_process";
import { readFile, mkdir } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { expect, test, type Page } from "playwright/test";
import { personName, startRealServer, type RealServer } from "./server";

let server: RealServer;
let page: Page;

test.beforeAll(async ({ browser }) => {
  server = await startRealServer();
  const context = await browser.newContext({
    ignoreHTTPSErrors: true,
    viewport: { width: 1440, height: 1000 },
  });
  page = await context.newPage();
  const cdp = await context.newCDPSession(page);
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
  await page.locator("#setup-username").fill(personName("host_facts"));
  await page.locator("#setup-display-name").fill("Host facts");
  await page.getByRole("button", { name: "Continue", exact: true }).click();
  await page.getByRole("button", { name: "Create passkey" }).click();
  await page.getByRole("heading", { name: "Save your recovery key" }).waitFor();
  await page.locator(".auth-check").click();
  await page.getByRole("button", { name: "Open infraternal" }).click();
  await page.locator(".cl-viewport").waitFor();
});

test.afterAll(async () => {
  await page?.context().close();
  await server?.dispose();
});

test("the Host popover reports this server's OS release and kernel", async () => {
  const releaseText = await readFile("/etc/os-release", "utf8");
  const field = (name: string): string => {
    const line = releaseText.split("\n").find((candidate) => candidate.startsWith(`${name}=`));
    if (!line) throw new Error(`/etc/os-release has no ${name} field`);
    const value = line.slice(name.length + 1);
    return value.startsWith('"') || value.startsWith("'") ? value.slice(1, -1) : value;
  };
  const expectedSystem = `${field("NAME")} ${field("VERSION_ID")}`.trim();
  const expectedKernel = execFileSync("uname", ["-r"], { encoding: "utf8" }).trim();
  const factsReadCount = (): number => server.bridges
    .flatMap((bridge) => bridge.control)
    .filter((message) => message.dir === "up" && message.detail === "host.facts.read").length;

  expect(factsReadCount()).toBe(0);

  await page.locator(".ui-window-pill").first().click();
  const popover = page.locator(".canvas-popover");
  await expect(popover).toBeVisible();
  const valueByKey = (key: string) => popover
    .locator(".ui-kv-key", { hasText: key })
    .locator("xpath=..")
    .locator(".ui-kv-value");
  await expect(valueByKey("System")).toHaveText(expectedSystem, { timeout: 15_000 });
  await expect(valueByKey("Kernel")).toHaveText(expectedKernel);
  await expect(popover.locator(".canvas-popover-logo svg.ui-host-mark")).toBeVisible();
  await expect.poll(factsReadCount).toBeGreaterThan(0);

  const screenshot = process.env.HOST_FACTS_SCREENSHOT;
  if (screenshot) {
    const destination = resolve(screenshot);
    await mkdir(dirname(destination), { recursive: true });
    await popover.screenshot({ path: destination });
  }
  const openedCount = factsReadCount();
  await page.waitForTimeout(1_200);
  expect(factsReadCount() - openedCount).toBeLessThanOrEqual(1);
  await page.mouse.click(1_380, 930);
  await expect(popover).toHaveCount(0);
  const closedCount = factsReadCount();
  await page.waitForTimeout(1_200);
  expect(factsReadCount()).toBe(closedCount);
});

/** Configure only this fixture's host over the authenticated control wire; no test hook replaces admission. */
async function memoryFloor(floorMiB: number): Promise<void> {
  const { WebSocket } = await import("ws");
  const { WebSocketFrameDecoder, encodeMuxedFrame } = await import("../../../packages/protocol/src/codec");
  const cookies = await page.context().cookies(server.origin);
  const cookie = cookies.map((value) => `${value.name}=${value.value}`).join("; ");
  const socket = new WebSocket(server.backend.replace("http:", "ws:") + "/v1/ws", { headers: { Origin: server.origin, Cookie: cookie } });
  const decoder = new WebSocketFrameDecoder();
  try {
    await new Promise<void>((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error("host memory configure timed out")), 15_000);
      socket.on("error", (error) => { clearTimeout(timer); reject(error); });
      socket.on("message", (data) => decoder.feed(new Uint8Array(Buffer.from(data as Buffer)), (_stream, frame) => {
        if (frame.type === "Hello") socket.send(encodeMuxedFrame(0, { type: "Hello", version: 1, caps: 0n, clientInfo: "session-bounds-fixture" }));
        if (frame.type === "Welcome") socket.send(encodeMuxedFrame(0, { type: "Call", callId: 151, actionId: "host.memory.configure", inputJson: new TextEncoder().encode(JSON.stringify({ terminalMemoryFloorMiB: floorMiB, terminalMemoryFloorPercent: 5 })) }));
        if (frame.type === "Result" && frame.callId === 151) { clearTimeout(timer); if (frame.ok) resolve(); else reject(new Error("host memory configure refused")); }
      }));
    });
  } finally { socket.terminate(); }
}

test("low memory explains the refusal and opens the existing host sessions picker", async ({ browser }) => {
  await memoryFloor(17592186044415);
  try {
    await page.locator('[data-action="split-down"]').first().click();
    const toast = page.locator(".ui-toast");
    await expect(toast).toBeVisible();
    await expect(toast.locator(".ui-toast-message")).toHaveText(/.+ is low on memory \(\d+ MiB free, 1 session running\)\. Close sessions you no longer need\./);
    await expect(toast.getByRole("button", { name: "Sessions", exact: true })).toBeVisible();
    const captures = tracerEvidencePath("session-bounds");
    await mkdir(captures, { recursive: true });
    const screenshot = resolve(captures, "refusal-desktop.png");
    await page.screenshot({ path: screenshot });
    await test.info().attach("Production memory refusal", { path: screenshot, contentType: "image/png" });
    await toast.getByRole("button", { name: "Sessions", exact: true }).click();
    await expect(page.locator(".cl-sx-pop")).toBeVisible();
    await expect(page.locator(".cl-sx-pop")).toBeInViewport({ ratio: 0.5 });
    const mobile = await browser.newContext({ ignoreHTTPSErrors: true, viewport: { width: 393, height: 852 }, deviceScaleFactor: 3, hasTouch: true, isMobile: true, storageState: await page.context().storageState() });
    try {
      const phonePage = await mobile.newPage();
      await phonePage.goto(server.origin + "/");
      await phonePage.locator(".cl-viewport").waitFor();
      await phonePage.locator('[data-action="split-down"]').first().tap();
      const phoneToast = phonePage.locator(".ui-toast");
      await expect(phoneToast).toBeVisible();
      await expect(phoneToast.locator(".ui-toast-message")).toContainText("Close sessions you no longer need.");
      const phone = resolve(captures, "refusal-phone.png");
      await phonePage.screenshot({ path: phone });
      await test.info().attach("Production memory refusal on phone", { path: phone, contentType: "image/png" });
      await phoneToast.getByRole("button", { name: "Sessions", exact: true }).tap();
      await expect(phonePage.locator(".cl-sx-pop")).toBeVisible();
      await expect(phonePage.locator(".cl-sx-pop")).toBeInViewport({ ratio: 0.5 });
      const picker = resolve(captures, "sessions-phone.png");
      await phonePage.screenshot({ path: picker });
      await test.info().attach("Existing sessions picker on phone", { path: picker, contentType: "image/png" });
    } finally { await mobile.close(); }
  } finally { await memoryFloor(256); }
});
