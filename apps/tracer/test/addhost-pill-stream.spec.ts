/**
 * The machine pill on the host's own setup stream (#189, D255): no demo script, the real wizard against the test
 * double, whose `instant*` hosts publish the terminal at once and set up behind it (`instant-fail*` fails the join
 * stage the first time). Covers what the break-it review found missing: a failure after the prompt, the retry, and
 * the end state (system icon), with typing never blocked and reduced motion honoured.
 */
import { expect, test, type Page } from "playwright/test";
import { tracerEvidencePath } from "./evidence-path";

const URL = "/?mock=1&proto=clusters&scene=3&theme=ink&bg=none";

async function addHost(page: Page, name: string, theme = "ink"): Promise<void> {
  await page.request.post("/__mock/bootstrap/reset");
  await page.goto(URL.replace("theme=ink", `theme=${theme}`));
  await expect(page.locator(".cl-mockup")).toBeVisible({ timeout: 45_000 });
  await page.evaluate(() => window.dispatchEvent(new CustomEvent("tracer:canvas-action", { detail: { action: "canvas:addhost", source: "keyboard" } })));
  await expect(page.locator(".ah-page[data-page='discovery']")).toBeVisible();
  await page.locator(".ui-chip-text").click();
  await page.keyboard.insertText(`${name} `);
  await page.locator(".ah-float").getByRole("button", { name: "Continue", exact: true }).click();
}

const pillOf = (page: Page, name: string) => page.locator(".ui-window-pill", { hasText: name }).first();
const arcs = (page: Page) => page.locator(".ui-window .ui-setup-ring .ui-setup-fill").evaluateAll((els) => els.map((e) => (e as HTMLElement).dataset.state));

test("a failure after the prompt is explained in the pill, and Try again finishes into the system icon", async ({ page }) => {
  test.setTimeout(120_000);
  await addHost(page, "instant-fail.lab");
  // The window opened with its prompt; setup went on behind it and the join stage failed.
  await expect(page.locator('.ui-window .ui-setup-fill[data-state="failed"]')).toHaveCount(1, { timeout: 30_000 });
  expect(await arcs(page)).toEqual(["done", "failed", "pending", "pending"]);
  await expect(page.locator('.ui-window .ui-setup-ring[data-phase="tick"]')).toHaveCount(0);
  // The wizard's own "ready" toast would contradict the failure: it is not shown.
  await expect(page.locator(".ui-toast")).not.toContainText(/ready|added/i);

  await pillOf(page, "instant-fail.lab").click();
  const tip = page.getByRole("dialog", { name: "Setup of instant-fail.lab" });
  await expect(tip).toBeVisible();
  await expect(tip).toContainText("couldn't join this server");
  await expect(tip).toContainText("Your other sessions keep working.");
  await tip.getByRole("button", { name: "Try again" }).click();

  // The retry's events fill the arcs again, then tick, then the system icon.
  await expect(page.locator('.ui-window .ui-setup-fill[data-state="failed"]')).toHaveCount(0, { timeout: 10_000 });
  await page.waitForSelector(".ui-window .ui-setup-ring", { state: "detached", timeout: 20_000 });
  const mark = pillOf(page, "instant-fail.lab").locator(".ui-window-mark");
  await expect(mark.locator("svg")).toHaveCount(1);
  expect(await mark.evaluate((el) => getComputedStyle(el.querySelector("svg")!).opacity)).toBe("1");
});

test("a host that sets up cleanly goes circle, tick, system icon, and typing is never blocked", async ({ page }) => {
  test.setTimeout(120_000);
  const seen: string[] = [];
  await page.exposeFunction("__phase", (phase: string) => { if (seen.at(-1) !== phase) seen.push(phase); });
  await page.addInitScript(() => {
    new MutationObserver(() => {
      const ring = document.querySelector<HTMLElement>(".ui-window .ui-setup-ring");
      if (ring) void (window as unknown as { __phase(p: string): void }).__phase(ring.dataset.phase!);
    }).observe(document, { subtree: true, attributes: true, attributeFilter: ["data-phase"], childList: true });
  });
  await addHost(page, "instant.lab");
  await page.waitForSelector(".ui-window .ui-setup-ring", { timeout: 30_000 });
  // The prompt takes input while the ring is up.
  await page.keyboard.type("echo hi");
  await page.waitForSelector(".ui-window .ui-setup-ring", { state: "detached", timeout: 20_000 });
  expect(seen).toEqual(["ring", "tick", "rest"]);
  await expect(pillOf(page, "instant.lab").locator(".ui-window-mark svg")).toHaveCount(1);
  await expect(page.locator(".ui-window[data-setup]")).toHaveCount(0);
});

test("reduced motion: the failure and the retry still show, with no flight", async ({ page }) => {
  test.setTimeout(120_000);
  await page.emulateMedia({ reducedMotion: "reduce" });
  await addHost(page, "instant-fail.lab");
  await expect(page.locator('.ui-window .ui-setup-fill[data-state="failed"]')).toHaveCount(1, { timeout: 30_000 });
  expect(await page.locator(".ui-setup-fly").count()).toBe(0);
  await pillOf(page, "instant-fail.lab").click();
  await page.getByRole("dialog", { name: "Setup of instant-fail.lab" }).getByRole("button", { name: "Try again" }).click();
  await page.waitForSelector(".ui-window .ui-setup-ring", { state: "detached", timeout: 20_000 });
});

// An exhausted attempt is authoritative even though the existing terminal stays open.
for (const [width, height] of [[1440, 900], [393, 852], [375, 667]] as const) {
  for (const theme of ["ink", "paper"]) {
    test(`review exhausted setup does not offer an enabled retry at ${width}px ${theme}`, async ({ page }) => {
      await page.setViewportSize({ width, height });
      const errors: string[] = [];
      page.on("pageerror", (error) => errors.push(error.message));
      await page.routeWebSocket("**/v1/bootstrap/setup/ws", (client) => {
        const server = client.connectToServer();
        server.onMessage((data) => {
          if (typeof data !== "string") { client.send(data); return; }
          const message = JSON.parse(data) as { setup?: { state?: string; attempt?: number; retry_available?: boolean } };
          if (message.setup?.state === "failed") {
            message.setup.attempt = 8;
            message.setup.retry_available = false;
          }
          client.send(JSON.stringify(message));
        });
      });
      await addHost(page, "instant-fail.lab", theme);
      await expect(page.locator('.ui-window .ui-setup-fill[data-state="failed"]')).toHaveCount(1, { timeout: 30_000 });
      await pillOf(page, "instant-fail.lab").click();
      const tip = page.getByRole("dialog", { name: "Setup of instant-fail.lab" });
      await expect(tip).toBeVisible();
      await expect(tip.getByRole("button", { name: "Try again", disabled: false })).toHaveCount(0);
      await expect(tip).toContainText("retry limit");
      await expect(tip).toContainText("Remove this host, then add it again");
      await expect(tip.getByRole("button", { name: "Remove host" })).toBeVisible();
      expect(errors).toEqual([]);
      await page.screenshot({ path: tracerEvidencePath(`exhausted-retry-${width}-${theme}.png`) });
    });
  }
}
