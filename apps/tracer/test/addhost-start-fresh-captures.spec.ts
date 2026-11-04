/** Captures for the leftovers, already-running, stuck-install and re-enroll screens (#169, #305), at phone and desktop size in the ink theme. */
import { tracerEvidencePath } from "./evidence-path";
import { expect, test, type Page } from "playwright/test";
import { resolve } from "node:path";

const OUT = tracerEvidencePath("addhost-start-fresh");
const SIZES = [{ name: "desktop", width: 1440, height: 900 }, { name: "phone", width: 393, height: 852 }];
const PORT = process.env.TRACER_TEST_PORT ?? "4621";

async function reach(page: Page, host: string, size: { width: number; height: number }): Promise<void> {
  await page.request.post("/__mock/bootstrap/reset", { maxRetries: 1 });
  await page.setViewportSize(size);
  await page.goto("/?mock=1&proto=clusters&scene=3&theme=ink&bg=none");
  await expect(page.locator(".cl-mockup")).toBeVisible({ timeout: 45_000 });
  await page.waitForTimeout(400);
  await page.evaluate(() => window.dispatchEvent(new CustomEvent("tracer:canvas-action", { detail: { action: "canvas:addhost", source: "keyboard" } })));
  await expect(page.locator(".ah-page[data-page='discovery']")).toBeVisible({ timeout: 45_000 });
  await page.locator(".ui-chip-text").click();
  await page.keyboard.type(`${host} `, { delay: 5 });
  await page.locator(".ah-float").getByRole("button", { name: "Continue", exact: true }).click();
}

for (const size of SIZES) {
  test(`captures ${size.name}`, async ({ page }) => {
    test.setTimeout(180_000);
    await reach(page, "stale.lab", size);
    await expect(page.getByRole("heading", { name: "This host has leftovers from an earlier setup" })).toBeVisible({ timeout: 30_000 });
    await page.waitForTimeout(600);
    await page.screenshot({ path: resolve(OUT, `leftovers-${size.name}-ink.png`) });
    await page.locator(".ah-details summary").click();
    await page.waitForTimeout(400);
    await page.screenshot({ path: resolve(OUT, `leftovers-details-${size.name}-ink.png`) });
    await page.locator(".ah-float").getByRole("button", { name: "Start fresh", exact: true }).click();
    await page.waitForTimeout(250);
    await page.screenshot({ path: resolve(OUT, `start-fresh-progress-${size.name}-ink.png`) });
    await reach(page, "running.lab", size);
    await expect(page.getByRole("heading", { name: "Setup is already running on this host" })).toBeVisible({ timeout: 30_000 });
    await page.waitForTimeout(600);
    await page.screenshot({ path: resolve(OUT, `running-${size.name}-ink.png`) });
  });
}

for (const size of SIZES) {
  test(`captures stuck-upgrade replacement at ${size.name} and keeps its label aligned`, async ({ browser }) => {
    test.setTimeout(180_000);
    const context = await browser.newContext({
      baseURL: `http://localhost:${PORT}`,
      viewport: { width: size.width, height: size.height },
      deviceScaleFactor: 2,
      hasTouch: size.name === "phone",
      isMobile: size.name === "phone",
    });
    const page = await context.newPage();
    try {
      await page.request.post("/__mock/bootstrap/reset", { maxRetries: 1 });
      await page.goto("/?mock=1&proto=clusters&scene=3&theme=ink&bg=none");
      await expect(page.locator(".cl-mockup")).toBeVisible({ timeout: 45_000 });
      await page.waitForTimeout(400);
      await page.evaluate(() => window.dispatchEvent(new CustomEvent("tracer:canvas-action", { detail: { action: "canvas:addhost", source: "keyboard" } })));
      await expect(page.locator(".ah-page[data-page='discovery']")).toBeVisible({ timeout: 45_000 });
      await page.locator(".ui-chip-text").click();
      await page.keyboard.type("stuck.lab ", { delay: 5 });
      await page.locator(".ah-float").getByRole("button", { name: "Continue", exact: true }).click();

      await expect(page.getByRole("heading", { name: "A stuck infraternal agent was found on stuck.lab" })).toBeVisible({ timeout: 30_000 });
      await expect(page.locator(".ah-page[data-page='failure'] .ah-lede")).toContainText(/build-node.*setup attempt d831a93a \(process 254\).*2026-11-02T04:05:06Z/);
      await expect(page.locator(".ah-page[data-page='failure'] .ah-text")).toHaveText("1 open terminal session will carry over.");
      const replace = page.locator(".ah-float footer").getByRole("button", { name: "Replace the stuck install", exact: true });
      await expect(replace).toBeVisible();
      const alignment = await replace.evaluate((button) => {
        const label = button.querySelector("span");
        if (!label) throw new Error("replacement button has no text label");
        const buttonBounds = button.getBoundingClientRect();
        const labelBounds = label.getBoundingClientRect();
        return {
          horizontal: Math.abs((buttonBounds.left + buttonBounds.right - labelBounds.left - labelBounds.right) / 2),
          vertical: Math.abs((buttonBounds.top + buttonBounds.bottom - labelBounds.top - labelBounds.bottom) / 2),
        };
      });
      expect(alignment.horizontal).toBeLessThanOrEqual(0.5);
      expect(alignment.vertical).toBeLessThanOrEqual(0.5);
      // Let the page transition finish so the outgoing page is not in the capture.
      await page.waitForTimeout(600);
      await page.screenshot({ path: resolve(OUT, `stuck-replacement-${size.name}-2x-ink.png`) });

      await replace.click();
      // The outgoing page can still be in the DOM while the transition runs.
      await expect(page.locator(".ah-page[data-page='progress']").first()).toBeVisible();
      await expect(page.locator(".ah-run[data-state='done']")).toBeVisible({ timeout: 30_000 });
    } finally {
      await context.close();
    }
  });
}

// D335: a machine another server enrolled names that server and the sessions that end, and joins as a new host.
for (const size of SIZES) {
  test(`captures re-enrollment from another server at ${size.name} and keeps its text aligned`, async ({ browser }) => {
    test.setTimeout(180_000);
    const context = await browser.newContext({
      baseURL: `http://localhost:${PORT}`,
      viewport: { width: size.width, height: size.height },
      deviceScaleFactor: 2,
      hasTouch: size.name === "phone",
      isMobile: size.name === "phone",
    });
    const page = await context.newPage();
    try {
      await page.request.post("/__mock/bootstrap/reset", { maxRetries: 1 });
      await page.goto("/?mock=1&proto=clusters&scene=3&theme=ink&bg=none");
      await expect(page.locator(".cl-mockup")).toBeVisible({ timeout: 45_000 });
      await page.waitForTimeout(400);
      await page.evaluate(() => window.dispatchEvent(new CustomEvent("tracer:canvas-action", { detail: { action: "canvas:addhost", source: "keyboard" } })));
      await expect(page.locator(".ah-page[data-page='discovery']")).toBeVisible({ timeout: 45_000 });
      await page.locator(".ui-chip-text").click();
      await page.keyboard.type("foreign.lab ", { delay: 5 });
      await page.locator(".ah-float").getByRole("button", { name: "Continue", exact: true }).click();

      const failure = page.locator(".ah-page[data-page='failure']");
      await expect(page.getByRole("heading", { name: "foreign.lab is enrolled with another server" })).toBeVisible({ timeout: 30_000 });
      await expect(failure.locator(".ah-lede")).toHaveText("It belongs to monitor01.example. Join it to this server as a new host with a new key. Its old infraternal agent is stopped, and deleted with its key once the machine has joined.");
      await expect(failure.locator(".ah-text")).toHaveText("1 open terminal session will end.");
      // Title, lede and the sessions line share one left edge (owner, 2026-11-01).
      const edges = await failure.evaluate((page) => [".ah-title", ".ah-lede", ".ah-text"].map((selector) => {
        const node = page.querySelector(selector);
        if (!node) throw new Error(`missing ${selector}`);
        return node.getBoundingClientRect().left;
      }));
      for (const edge of edges) expect(Math.abs(edge - edges[0]!)).toBeLessThanOrEqual(0.5);
      const join = page.locator(".ah-float footer").getByRole("button", { name: "Join as a new host", exact: true });
      await expect(join).toBeVisible();
      const alignment = await join.evaluate((button) => {
        const label = button.querySelector("span");
        if (!label) throw new Error("join button has no text label");
        const buttonBounds = button.getBoundingClientRect();
        const labelBounds = label.getBoundingClientRect();
        return {
          horizontal: Math.abs((buttonBounds.left + buttonBounds.right - labelBounds.left - labelBounds.right) / 2),
          vertical: Math.abs((buttonBounds.top + buttonBounds.bottom - labelBounds.top - labelBounds.bottom) / 2),
        };
      });
      expect(alignment.horizontal).toBeLessThanOrEqual(0.5);
      expect(alignment.vertical).toBeLessThanOrEqual(0.5);
      // Let the page transition finish so the outgoing page is not in the capture.
      await page.waitForTimeout(600);
      await page.screenshot({ path: resolve(OUT, `reenroll-${size.name}-2x-ink.png`) });

      await join.click();
      // The outgoing page can still be in the DOM while the transition runs.
      await expect(page.locator(".ah-page[data-page='progress']").first()).toBeVisible();
      await expect(page.locator(".ah-run[data-state='done']")).toBeVisible({ timeout: 30_000 });
    } finally {
      await context.close();
    }
  });
}

// #305: a live install says joining disconnects it; a set-aside install is offered back.
for (const size of SIZES) {
  for (const scene of [
    { host: "live.lab", heading: "live.lab is enrolled with another server", lede: /^Its infraternal agent is running and may be connected to monitor01\.example now\./, button: "Disconnect and join here", shot: "reenroll-live" },
    { host: "aside.lab", heading: "aside.lab's infraternal agent was set aside", lede: /^An earlier add-host set it aside and could not put it back\. Nothing was deleted\.$/, button: "Put it back", shot: "set-aside" },
  ]) {
    test(`captures ${scene.shot} at ${size.name} and keeps its text aligned`, async ({ browser }) => {
      test.setTimeout(180_000);
      const context = await browser.newContext({
        baseURL: `http://localhost:${PORT}`,
        viewport: { width: size.width, height: size.height },
        deviceScaleFactor: 2,
        hasTouch: size.name === "phone",
        isMobile: size.name === "phone",
      });
      const page = await context.newPage();
      try {
        await page.request.post("/__mock/bootstrap/reset", { maxRetries: 1 });
        await page.goto("/?mock=1&proto=clusters&scene=3&theme=ink&bg=none");
        await expect(page.locator(".cl-mockup")).toBeVisible({ timeout: 45_000 });
        await page.waitForTimeout(400);
        await page.evaluate(() => window.dispatchEvent(new CustomEvent("tracer:canvas-action", { detail: { action: "canvas:addhost", source: "keyboard" } })));
        await expect(page.locator(".ah-page[data-page='discovery']")).toBeVisible({ timeout: 45_000 });
        await page.locator(".ui-chip-text").click();
        await page.keyboard.type(`${scene.host} `, { delay: 5 });
        await page.locator(".ah-float").getByRole("button", { name: "Continue", exact: true }).click();

        const failure = page.locator(".ah-page[data-page='failure']");
        await expect(page.getByRole("heading", { name: scene.heading })).toBeVisible({ timeout: 30_000 });
        await expect(failure.locator(".ah-lede")).toHaveText(scene.lede);
        const edges = await failure.evaluate((page) => [".ah-title", ".ah-lede", ".ah-text"].flatMap((selector) => {
          const node = page.querySelector(selector);
          return node ? [node.getBoundingClientRect().left] : [];
        }));
        for (const edge of edges) expect(Math.abs(edge - edges[0]!)).toBeLessThanOrEqual(0.5);
        const action = page.locator(".ah-float footer").getByRole("button", { name: scene.button, exact: true });
        await expect(action).toBeVisible();
        const alignment = await action.evaluate((button) => {
          const label = button.querySelector("span");
          if (!label) throw new Error("action button has no text label");
          const buttonBounds = button.getBoundingClientRect();
          const labelBounds = label.getBoundingClientRect();
          return {
            horizontal: Math.abs((buttonBounds.left + buttonBounds.right - labelBounds.left - labelBounds.right) / 2),
            vertical: Math.abs((buttonBounds.top + buttonBounds.bottom - labelBounds.top - labelBounds.bottom) / 2),
          };
        });
        expect(alignment.horizontal).toBeLessThanOrEqual(0.5);
        expect(alignment.vertical).toBeLessThanOrEqual(0.5);
        await page.waitForTimeout(600);
        await page.screenshot({ path: resolve(OUT, `${scene.shot}-${size.name}-2x-ink.png`) });
      } finally {
        await context.close();
      }
    });
  }
}
