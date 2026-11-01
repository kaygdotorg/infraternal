/**
 * The clickable "switch to the Infraternal Multiplexer?" mockup (#251, D315) in a production build: the question, the
 * three icon buttons with their names, the confirmation and the restoring undo on a live terminal, and the docs page.
 * Captures (2× desktop, 3× phone, ink and paper) go to the external evidence directory for the owner's review.
 */
import { mkdirSync } from "node:fs";
import { expect, test, type Page } from "playwright/test";
import { tracerEvidencePath } from "./evidence-path";

const OUT = tracerEvidencePath("startup-demo");
const SIZES = [
  { name: "desktop", width: 1440, height: 900, scale: 2, touch: false },
  { name: "phone", width: 393, height: 852, scale: 3, touch: true },
  { name: "small-phone", width: 375, height: 667, scale: 3, touch: true },
] as const;
const QUESTION = "tmux started automatically. Would you like to switch to the Infraternal Multiplexer instead?";
const GUARD = '[ -n "$INFRATERNAL_SESSION" ] || exec tmux new-session -s main';

const screen = (page: Page): Promise<string> => page.evaluate(() => (window as unknown as { __tracerTestDouble: { screenText(): string } }).__tracerTestDouble.screenText());
const choice = (page: Page, name: string) => page.locator(".ui-toast-icons").getByRole("button", { name, exact: true });

for (const size of SIZES) for (const theme of ["ink", "paper"] as const) {
  test(`${size.name} ${theme}: ✓ confirms and restores, ✗ keeps, ? opens the page`, async ({ browser }) => {
    mkdirSync(OUT, { recursive: true });
    const context = await browser.newContext({ viewport: { width: size.width, height: size.height }, deviceScaleFactor: size.scale, hasTouch: size.touch, isMobile: size.touch });
    const page = await context.newPage();
    const errors: string[] = [];
    page.on("pageerror", (error) => errors.push(error.message));
    const shot = (label: string) => page.screenshot({ path: `${OUT}/${size.name}-${theme}-${label}.png` });
    try {
      const url = `/?mock=1&proto=clusters&startup-demo=1&fixture=none&bg=none&theme=${theme}`;
      await page.goto(url);
      await expect(page.locator(".ui-toast-message")).toHaveText(QUESTION, { timeout: 30_000 });
      // The question names the three choices, and none of them says "guard".
      for (const name of ["Switch to the Infraternal Multiplexer", "Keep tmux, don't ask again on this host", "About the Infraternal Multiplexer"]) {
        const button = choice(page, name);
        await expect(button).toBeVisible();
        await expect(button).toHaveAttribute("data-tip", name);
      }
      expect(await page.locator(".ui-toast").innerText()).not.toMatch(/guard/i);
      await page.waitForTimeout(400);
      await shot("question");

      // ✓ asks first and writes nothing until confirmed.
      await choice(page, "Switch to the Infraternal Multiplexer").click();
      await expect(page.locator(".ui-confirm-tip")).toBeVisible();
      await expect(page.locator(".ui-confirm-tip")).toContainText(GUARD);
      expect(await screen(page)).not.toContain("INFRATERNAL_SESSION");
      await page.waitForTimeout(300);
      await shot("confirm");
      await page.locator(".ui-confirm-yes").click();
      await expect(page.locator(".ui-toast-message")).toContainText("Switched. tmux no longer starts in Infraternal terminals");
      await expect.poll(() => screen(page)).toContain("INFRATERNAL_SESSION");
      await page.waitForTimeout(300);
      await shot("switched");
      await page.getByRole("button", { name: "Restore .zshrc", exact: true }).click();
      await expect(page.locator(".ui-toast-message")).toHaveText(".zshrc restored. tmux starts automatically again.");
      await expect.poll(() => screen(page)).toContain("3:  exec tmux new-session -s main");

      // ? opens the docs page and leaves the question up; ✗ closes it for good.
      await page.goto(url);
      await expect(page.locator(".ui-toast-message")).toHaveText(QUESTION, { timeout: 30_000 });
      const [docs] = await Promise.all([context.waitForEvent("page"), choice(page, "About the Infraternal Multiplexer").click()]);
      await docs.waitForLoadState();
      // The page is this server's own (an instance carries the docs for the version it runs), never another site's.
      expect(new URL(docs.url()).origin + new URL(docs.url()).pathname).toBe(new URL(page.url()).origin + "/docs/multiplexer/");
      await expect(docs.getByRole("heading", { level: 1, name: "The Infraternal Multiplexer" })).toBeVisible();
      await docs.setViewportSize({ width: size.width, height: size.height });
      await docs.screenshot({ path: `${OUT}/${size.name}-${theme}-docs.png` });
      await docs.close();
      await expect(page.locator(".ui-toast-message")).toHaveText(QUESTION);
      await choice(page, "Keep tmux, don't ask again on this host").click();
      await expect(page.locator(".ui-toast")).toBeHidden();
      expect(errors).toEqual([]);
    } finally {
      await context.close();
    }
  });
}
