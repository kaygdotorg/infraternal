/** Captures every add-host mock state at the owner-requested phone and desktop sizes. */
import { mkdir, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { chromium, type BrowserContext, type Page } from "playwright";

const port = Number(process.env.TRACER_TEST_PORT ?? "4782");
const origin = `http://localhost:${port}`;
const outputDir = resolve(process.cwd(), "captures/proto-addhost");
const viewports = [
  { width: 393, height: 852 },
  { width: 1440, height: 900 },
] as const;
const themes = ["ink", "paper"] as const;
const manifest: string[] = ["capture\tstep\ttheme\tviewport\tscale"];

async function openFlow(context: BrowserContext, page: Page, theme: string, query = ""): Promise<void> {
  await context.request.post(`${origin}/__mock/open-terminal`);
  await page.goto(`${origin}/?mock=1&proto=addhost&theme=${theme}&bg=none${query}`);
  await page.locator(".addhost-window").waitFor({ state: "visible" });
}

async function settle(page: Page): Promise<void> {
  await page.waitForTimeout(280);
}

async function selectHost(page: Page, id: string): Promise<void> {
  const label = page.locator(`[data-host-row][data-host-id="${id}"] .addhost-host-select`);
  await label.scrollIntoViewIfNeeded();
  await label.click();
}

async function capture(page: Page, step: string, theme: string, width: number, height: number): Promise<void> {
  await settle(page);
  const filename = `${step}-${theme}-${width}x${height}.png`;
  await page.screenshot({ path: resolve(outputDir, filename), animations: "disabled" });
  manifest.push(`${filename}\t${step}\t${theme}\t${width}x${height}\t1x`);
}

async function captureRowCrop(theme: string, width: number, height: number): Promise<void> {
  const browser = await chromium.launch({ headless: true, args: ["--disable-renderer-backgrounding"] });
  const context = await browser.newContext({
    viewport: { width, height },
    deviceScaleFactor: 2,
    isMobile: width === 393,
    hasTouch: width === 393,
  });
  const page = await context.newPage();
  const filename = `discovery-row-2x-${theme}-${width}x${height}.png`;
  try {
    await openFlow(context, page, theme);
    const row = page.locator("[data-host-row][data-host-id='build-01']");
    await row.scrollIntoViewIfNeeded();
    await settle(page);
    await row.screenshot({ path: resolve(outputDir, filename), animations: "disabled", scale: "device" });
    manifest.push(`${filename}\tdiscovery-row-2x\t${theme}\t${width}x${height}\t2x`);
  } finally {
    await context.close().catch(() => undefined);
    await browser.close();
  }
}

async function captureVariant(theme: string, width: number, height: number): Promise<void> {
  const browser = await chromium.launch({ headless: true, args: ["--disable-renderer-backgrounding"] });
  const context = await browser.newContext({
    viewport: { width, height },
    deviceScaleFactor: 1,
    isMobile: width === 393,
    hasTouch: width === 393,
  });
  const page = await context.newPage();
  try {
    await openFlow(context, page, theme, "&empty=1");
    await capture(page, "entry-empty", theme, width, height);

    await openFlow(context, page, theme);
    await page.getByRole("button", { name: "Close add hosts" }).click();
    await page.locator("#sidebar-toggle").click();
    await page.locator("#sidebar").getByRole("button", { name: "Add hosts" }).waitFor({ state: "visible" });
    await capture(page, "entry-sidebar", theme, width, height);
    await page.locator("#sidebar").getByRole("button", { name: "Add hosts" }).click();
    await page.getByRole("button", { name: "Close add hosts" }).click();
    await page.keyboard.press("Control+k");
    await page.locator("#palette-input").fill("Add hosts");
    await page.getByRole("option", { name: /Add hosts/ }).waitFor({ state: "visible" });
    await capture(page, "entry-palette", theme, width, height);
    await page.getByRole("option", { name: /Add hosts/ }).click();

    await openFlow(context, page, theme);
    await capture(page, "discovery", theme, width, height);
    const disclosure = page.getByRole("button", { name: "Discovery sources" });
    await disclosure.scrollIntoViewIfNeeded();
    await disclosure.click();
    await capture(page, "discovery-sources", theme, width, height);
    await openFlow(context, page, theme);
    const ipAction = page.getByRole("button", { name: "Show IP for edge-arm" });
    await ipAction.scrollIntoViewIfNeeded();
    await ipAction.click();
    await capture(page, "discovery-ip", theme, width, height);

    await openFlow(context, page, theme);
    await page.getByRole("tab", { name: "Manual" }).click();
    await capture(page, "manual-entry", theme, width, height);

    await openFlow(context, page, theme);
    await selectHost(page, "nix-cache");
    await page.getByRole("button", { name: "Continue" }).click();
    await page.getByRole("textbox", { name: "SSH key or password for nix-cache" }).waitFor({ state: "visible" });
    await capture(page, "ssh-identity", theme, width, height);

    await openFlow(context, page, theme);
    await selectHost(page, "edge-arm");
    await page.getByRole("button", { name: "Continue" }).click();
    await page.getByRole("heading", { name: "Root access" }).waitFor({ state: "visible" });
    await capture(page, "root-consent", theme, width, height);
    await page.locator(".addhost-consent-label").first().click();
    await page.getByRole("button", { name: "Install as root" }).click();
    await page.locator("[data-bootstrap-step='sniff'][data-state='running']").waitFor({ state: "visible" });
    await capture(page, "bootstrap-progress", theme, width, height);
    await page.getByRole("heading", { name: "edge-arm is ready" }).waitFor({ state: "visible", timeout: 8_000 });
    await capture(page, "success-root", theme, width, height);

    await openFlow(context, page, theme);
    await selectHost(page, "edge-arm");
    await page.getByRole("button", { name: "Continue" }).click();
    await page.getByRole("button", { name: "Install as a user" }).click();
    await page.getByRole("heading", { name: "edge-arm is ready" }).waitFor({ state: "visible", timeout: 8_000 });
    await capture(page, "success-rootless", theme, width, height);
    await page.getByRole("button", { name: "Root available" }).click();
    const rootConfirmation = page.getByRole("dialog", { name: "Root access confirmation" });
    await rootConfirmation.waitFor({ state: "visible" });
    await capture(page, "root-confirmation", theme, width, height);
    await rootConfirmation.getByRole("button", { name: "Yes" }).click();
    await page.getByRole("button", { name: "Root active" }).waitFor({ state: "visible", timeout: 5_000 });
    await capture(page, "root-active", theme, width, height);

    const failures = [
      { step: "failure-unreachable", value: "ops@unreachable-01", heading: "Host unreachable" },
      { step: "failure-auth", value: "kayg@nix-cache", heading: "SSH key refused" },
      { step: "failure-mesh-policy", value: "root@pve01", heading: "SSH blocked by mesh policy" },
    ];
    for (const scenario of failures) {
      await openFlow(context, page, theme);
      await page.getByRole("tab", { name: "Manual" }).click();
      await page.getByRole("textbox", { name: "Host" }).fill(scenario.value);
      await page.getByRole("button", { name: "Add host", exact: true }).click();
      if (scenario.step === "failure-auth") await page.getByRole("button", { name: "Continue" }).click();
      await page.getByRole("heading", { name: scenario.heading }).waitFor({ state: "visible" });
      await capture(page, scenario.step, theme, width, height);
    }
  } finally {
    await context.close().catch(() => undefined);
    await browser.close();
  }
}

await mkdir(outputDir, { recursive: true });
for (const viewport of viewports) {
  for (const theme of themes) await captureVariant(theme, viewport.width, viewport.height);
}
for (const viewport of viewports) await captureRowCrop("ink", viewport.width, viewport.height);
await writeFile(resolve(outputDir, "manifest.txt"), `${manifest.join("\n")}\n`);
console.log(`Captured ${manifest.length - 3} states and 2 row crops in ${outputDir}`);
