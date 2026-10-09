/** Exercises the host facts action end to end on the real embedded agent and captures the production popover. */
import { execFileSync } from "node:child_process";
import { readFile, mkdir } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { expect, test, type Page } from "playwright/test";
import { startRealServer, type RealServer } from "./server";

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
  await page.locator("#setup-username").fill("host_facts");
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
