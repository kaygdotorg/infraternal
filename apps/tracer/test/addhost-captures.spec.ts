/**
 * Captures of every add-host wizard state at 1440x900, 393x852 and 375x667 in ink and paper, for the TASTE review
 * (`ADDHOST_CAPTURE=1 TRACER_TEST_PORT=... bun x playwright test test/addhost-captures.spec.ts`). They are written to
 * the external job evidence directory. Skipped in ordinary runs: screenshots are for review, not assertions.
 */
import { tracerEvidencePath } from "./evidence-path";
import { mkdirSync } from "node:fs";
import { expect, test, type Page } from "playwright/test";

const OUT = tracerEvidencePath("addhost-wizard");
const SIZES = [{ name: "1440x900", width: 1440, height: 900, touch: false }, { name: "393x852", width: 393, height: 852, touch: true }, { name: "375x667", width: 375, height: 667, touch: true }];
const THEMES = ["ink", "paper"];
const port = process.env.TRACER_TEST_PORT ?? "4621";
/** `ADDHOST_CAPTURE_ONLY=choose|hostkey` re-takes only the shots whose name matches. */
const only = process.env.ADDHOST_CAPTURE_ONLY ? new RegExp(process.env.ADDHOST_CAPTURE_ONLY) : undefined;

test.skip(process.env.ADDHOST_CAPTURE !== "1", "captures are produced on request");
test.describe.configure({ mode: "serial" });

/** The test proxy sometimes drops an idle keep-alive socket between two captures; a control call is safe to repeat. */
async function control(page: Page, path: string, data?: Record<string, string>): Promise<void> {
  for (let attempt = 1; ; attempt++) {
    try { await page.request.post(path, data ? { data } : {}); return; } catch (error) { if (attempt >= 4) throw error; }
  }
}

type Setup = (page: Page) => Promise<void>;
const inWizard = (page: Page, name: string) => page.locator(".ah-float").getByRole("button", { name, exact: true });
const openWizard = async (page: Page): Promise<void> => {
  await page.evaluate(() => window.dispatchEvent(new CustomEvent("tracer:canvas-action", { detail: { action: "canvas:addhost", source: "keyboard" } })));
  await expect(page.locator(".ah-page[data-page='discovery']")).toBeVisible();
};
const typed = async (page: Page, host: string): Promise<void> => {
  await page.locator(".ui-chip-text").click();
  await page.keyboard.type(`${host} `, { delay: 5 });
  await inWizard(page, "Continue").click();
};
const pick = async (page: Page, id: string): Promise<void> => { await page.locator(`.ah-row[data-host='${id}']`).click(); };

interface Shot { name: string; settings?: Record<string, string>; query?: string; setup: Setup }
const shots: Shot[] = [
  { name: "discovery", setup: async (page) => { await openWizard(page); await expect(page.locator(".ah-row[data-host='o2']")).toBeVisible(); } },
  { name: "discovery-selected", setup: async (page) => { await openWizard(page); await pick(page, "o2"); await pick(page, "web-01"); await pick(page, "remoternal"); } },
  { name: "discovery-typed", setup: async (page) => { await openWizard(page); await page.locator(".ui-chip-text").click(); await page.keyboard.type("kayg@lab.example:2222 bu"); } },
  { name: "discovery-empty", settings: { discovery: "empty" }, setup: async (page) => { await openWizard(page); await expect(page.locator(".ah-empty")).toBeVisible(); } },
  { name: "discovery-loading", settings: { discovery: "hang" }, setup: async (page) => { await openWizard(page); await expect(page.locator(".ah-loading")).toBeVisible(); } },
  { name: "discovery-error", settings: { discovery: "error" }, setup: async (page) => { await openWizard(page); await expect(page.locator(".ah-load-error")).toBeVisible(); } },
  { name: "root-consent", setup: async (page) => { await openWizard(page); await pick(page, "remoternal"); await inWizard(page, "Continue").click(); await expect(page.locator(".ah-consent")).toBeVisible(); } },
  { name: "progress-detecting", setup: async (page) => { await openWizard(page); await pick(page, "web-01"); await inWizard(page, "Continue").click(); await expect(page.locator(".ah-stage-row[data-stage='detect'][data-state='done']")).toBeVisible({ timeout: 15_000 }); } },
  { name: "progress-batch", setup: async (page) => {
    await openWizard(page);
    for (const id of ["web-01", "o2", "db-01", "archive-01"]) await pick(page, id);
    await inWizard(page, "Continue").click();
    await inWizard(page, "Install as user").click().catch(() => undefined);
    await expect(page.locator(".ah-summary")).toContainText("3 of 4 ready", { timeout: 25_000 });
    await page.waitForTimeout(500);
  } },
  { name: "choose-server-key", setup: async (page) => { await openWizard(page); await typed(page, "needs-key.lab"); await expect(page.locator("[data-kv='server']")).toBeVisible({ timeout: 15_000 }); await page.waitForTimeout(500); } },
  { name: "choose-password", query: "&savedkey=1", setup: async (page) => { await openWizard(page); await typed(page, "needs-key.lab"); await expect(page.getByText("Sign in with a password")).toBeVisible({ timeout: 15_000 }); await page.getByText("Sign in with a password").click(); await page.waitForTimeout(500); } },
  { name: "choose-no-server-key", settings: { sshKey: "missing" }, setup: async (page) => { await openWizard(page); await typed(page, "needs-key.lab"); await expect(page.getByText("Use a key from your computer")).toBeVisible({ timeout: 15_000 }); await page.waitForTimeout(500); } },
  { name: "choose-error", setup: async (page) => { await openWizard(page); await typed(page, "needs-key.lab"); await expect(page.getByText("Use a key from your computer")).toBeVisible({ timeout: 15_000 }); await page.getByText("Use a key from your computer").click(); await inWizard(page, "Sign in").click(); await expect(page.locator(".ah-error")).toBeVisible(); } },
  { name: "hostkey", setup: async (page) => { await openWizard(page); await typed(page, "kayg@newkey.lab"); await expect(page.locator(".ah-keyblock")).toBeVisible({ timeout: 15_000 }); await page.waitForTimeout(500); } },
  { name: "hostkey-changed", setup: async (page) => { await openWizard(page); await typed(page, "kayg@changedkey.lab"); await expect(page.locator(".ah-keyblock")).toBeVisible({ timeout: 15_000 }); await page.waitForTimeout(500); } },
  { name: "failure-unreachable", setup: async (page) => { await openWizard(page); await pick(page, "archive-01"); await inWizard(page, "Continue").click(); await expect(page.getByRole("heading", { name: /isn't answering/ })).toBeVisible({ timeout: 15_000 }); await page.waitForTimeout(500); } },
  { name: "failure-mesh-policy", setup: async (page) => { await openWizard(page); await pick(page, "pve01"); await inWizard(page, "Continue").click(); await expect(page.getByRole("heading", { name: /can't connect to/ })).toBeVisible({ timeout: 15_000 }); await page.waitForTimeout(500); } },
  { name: "failure-unsupported", setup: async (page) => { await openWizard(page); await typed(page, "unsupported.lab"); await expect(page.getByRole("heading", { name: /can't run the infraternal agent/ })).toBeVisible({ timeout: 15_000 }); await page.waitForTimeout(500); } },
  { name: "failure-install", setup: async (page) => { await openWizard(page); await typed(page, "broken.lab"); await expect(page.getByRole("heading", { name: /didn't finish/ })).toBeVisible({ timeout: 15_000 }); await page.waitForTimeout(500); } },
  { name: "install-command", setup: async (page) => { await openWizard(page); await pick(page, "archive-01"); await inWizard(page, "Continue").click(); await expect(page.getByRole("heading", { name: /isn't answering/ })).toBeVisible({ timeout: 15_000 }); await page.waitForTimeout(700); await inWizard(page, "Install from the host").click(); await expect(page.locator(".ah-install .ui-kv")).toBeVisible({ timeout: 15_000 }); await page.waitForTimeout(500); } },
  { name: "install-unavailable", settings: { install: "off" }, setup: async (page) => { await openWizard(page); await pick(page, "archive-01"); await inWizard(page, "Continue").click(); await expect(page.getByRole("heading", { name: /isn't answering/ })).toBeVisible({ timeout: 15_000 }); await page.waitForTimeout(700); await inWizard(page, "Install from the host").click(); await expect(page.locator(".ah-install .ah-note")).toBeVisible({ timeout: 15_000 }); await page.waitForTimeout(500); } },
  { name: "close-confirm", setup: async (page) => { await openWizard(page); await pick(page, "web-01"); await inWizard(page, "Continue").click(); await expect(page.locator(".ah-run[data-state='running']")).toBeVisible({ timeout: 10_000 }); await page.locator(".ah-close").click(); await expect(page.locator(".ah-foot")).toContainText("If you close this now"); } },
];

for (const size of SIZES) {
  for (const theme of THEMES) {
    test(`captures ${size.name} ${theme}`, async ({ browser }) => {
      test.setTimeout(30 * 60_000);
      mkdirSync(OUT, { recursive: true });
      const context = await browser.newContext({ baseURL: `http://localhost:${port}`, viewport: { width: size.width, height: size.height }, hasTouch: size.touch, isMobile: size.touch, deviceScaleFactor: 1 });
      const page = await context.newPage();
      try {
        for (const shot of shots) {
          if (only && !only.test(shot.name)) continue;
          await control(page, "/__mock/bootstrap/reset");
          if (shot.settings) await control(page, "/__mock/bootstrap/config", shot.settings);
          await page.goto(`/?mock=1&proto=clusters&scene=3&theme=${theme}&bg=none${shot.query ?? ""}`);
          await expect(page.locator(".cl-mockup")).toBeVisible({ timeout: 20_000 });
          await page.waitForTimeout(500);
          await shot.setup(page);
          await page.waitForTimeout(450);
          await page.screenshot({ path: `${OUT}/${shot.name}-${theme}-${size.name}.png` });
        }
      } finally {
        await context.close();
      }
    });
  }
}
