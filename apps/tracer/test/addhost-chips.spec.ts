/**
 * The add-host field's chips (#87): a typed `user@host` becomes a chip and is selected without a tick. Typed
 * delimiters, Tab, Enter, Continue and paste all end a token; an invalid token shows a quiet hint and never blocks
 * the chips beside it; Backspace on an empty field returns the last chip to editable text.
 * Captures of the field (1440x900 and 393x852, ink and paper) are written to `captures/addhost-chips/` when
 * `ADDHOST_CHIPS_CAPTURE=1` is set: evidence for a person to read, so ordinary runs skip them.
 */
import { mkdirSync } from "node:fs";
import { expect, test, type Page } from "playwright/test";

const port = process.env.TRACER_TEST_PORT ?? "4621";
const OUT = "captures/addhost-chips";
const SIZES = [{ name: "1440x900", width: 1440, height: 900 }, { name: "393x852", width: 393, height: 852 }];
const THEMES = ["ink", "paper"] as const;

async function open(page: Page, theme: string = "ink", width = 1440, height = 900): Promise<void> {
  await page.request.post("/__mock/bootstrap/reset");
  await page.setViewportSize({ width, height });
  await page.goto(`/?mock=1&proto=clusters&scene=3&theme=${theme}&bg=none`);
  await expect(page.locator(".cl-mockup")).toBeVisible({ timeout: 20_000 });
  await page.waitForTimeout(400);
}

async function openWizard(page: Page): Promise<void> {
  await page.evaluate(() => window.dispatchEvent(new CustomEvent("tracer:canvas-action", { detail: { action: "canvas:addhost", source: "keyboard" } })));
  await expect(page.locator(".ah-page[data-page='discovery']")).toBeVisible();
}

const field = (page: Page) => page.locator(".ui-chip-text");
const chips = (page: Page) => page.locator(".ui-chip-flow .ui-chip");
const continueButton = (page: Page) => page.locator(".ah-float").getByRole("button", { name: "Continue", exact: true });
const hint = (page: Page) => page.locator(".ah-hint");

/** Pastes plain text into the field the way a clipboard paste does. */
async function paste(page: Page, text: string): Promise<void> {
  await page.evaluate((value) => {
    const data = new DataTransfer();
    data.setData("text/plain", value);
    document.querySelector(".ui-chip-text")!.dispatchEvent(new ClipboardEvent("paste", { clipboardData: data, bubbles: true, cancelable: true }));
  }, text);
}

test("typing kayg@o2 and clicking Continue proceeds with that host, with no tick", async ({ page }) => {
  await open(page);
  await openWizard(page);
  await field(page).click();
  await page.keyboard.type("kayg@o2", { delay: 5 });
  // The pending token already counts: one host, Continue enabled, nothing chipped yet.
  await expect(continueButton(page)).toBeEnabled();
  await expect(page.locator(".ah-count")).toHaveText("1 host");
  await continueButton(page).click();
  // The flow moved on: the discovery page is gone and the typed host is the one being added.
  await expect(page.locator(".ah-page[data-page='discovery']")).toHaveCount(0, { timeout: 15_000 });
  await expect(page.locator(".ah-run, .ah-float h1").filter({ hasText: /o2/ }).first()).toBeVisible({ timeout: 15_000 });
});

test("a@h1 b@h2,c@h3 gives chips for the ended targets; the last one waits as text until it is ended", async ({ page }) => {
  await open(page);
  await openWizard(page);
  await field(page).click();
  await page.keyboard.type("a@h1 b@h2,c@h3", { delay: 5 });
  await expect(chips(page)).toHaveCount(2);
  await expect(chips(page).nth(0)).toHaveAttribute("data-chip", "a@h1");
  await expect(chips(page).nth(1)).toHaveAttribute("data-chip", "b@h2");
  await expect(field(page)).toHaveValue("c@h3");
  await expect(page.locator(".ah-count")).toHaveText("3 hosts");
  await page.keyboard.type(" ", { delay: 5 });
  await expect(chips(page)).toHaveCount(3);
  await expect(field(page)).toHaveValue("");
});

test("pasting three lines gives three chips", async ({ page }) => {
  await open(page);
  await openWizard(page);
  await field(page).click();
  await paste(page, "a@h1\nb@h2\nc@h3");
  await expect(chips(page)).toHaveCount(3);
  await expect(field(page)).toHaveValue("");
  await expect(continueButton(page)).toBeEnabled();
});

test("an invalid token shows the hint and never blocks the chips beside it", async ({ page }) => {
  await open(page);
  await openWizard(page);
  await field(page).click();
  await page.keyboard.type("a@h1 kayg@ ", { delay: 5 });
  await expect(chips(page)).toHaveCount(1);
  await expect(hint(page)).toHaveAttribute("data-show", "true");
  await expect(hint(page)).toHaveText("Type user@host, for example kayg@o2");
  await expect(continueButton(page)).toBeEnabled();
  await field(page).fill("");
  await expect(hint(page)).toHaveAttribute("data-show", "false");
  // Mid-typing never shows the hint; ending the token does.
  await page.keyboard.type("@o2", { delay: 5 });
  await expect(hint(page)).toHaveAttribute("data-show", "false");
  await page.keyboard.press("Enter");
  await expect(hint(page)).toHaveAttribute("data-show", "true");
  await expect(continueButton(page)).toBeEnabled();
});

test("with only an invalid token the hint shows once it is ended, and Continue stays disabled", async ({ page }) => {
  await open(page);
  await openWizard(page);
  await field(page).click();
  await page.keyboard.type("kayg@", { delay: 5 });
  // Still typing: no hint yet.
  await expect(hint(page)).toHaveAttribute("data-show", "false");
  await page.keyboard.press("Enter");
  await expect(hint(page)).toHaveAttribute("data-show", "true");
  await expect(continueButton(page)).toBeDisabled();
  await expect(page.locator(".ah-count")).toHaveText("");
});

test("a token that names a discovered host chips at once and is ticked in the list", async ({ page }) => {
  await open(page);
  await openWizard(page);
  await field(page).click();
  await page.keyboard.type("remoternal", { delay: 5 });
  await expect(chips(page)).toHaveCount(1);
  await expect(chips(page).first()).toHaveAttribute("data-chip", "remoternal");
  await expect(field(page)).toHaveValue("");
  await expect(page.locator(".ah-row[data-host='remoternal'] input")).toBeChecked();
});

test("Backspace on an empty field turns the last chip back into text", async ({ page }) => {
  await open(page);
  await openWizard(page);
  await field(page).click();
  await page.keyboard.type("a@h1 b@h2:2222 ", { delay: 5 });
  await expect(chips(page)).toHaveCount(2);
  await page.keyboard.press("Backspace");
  await expect(chips(page)).toHaveCount(1);
  await expect(field(page)).toHaveValue("b@h2:2222");
  await expect(continueButton(page)).toBeEnabled();
});

test("Tab ends a typed token", async ({ page }) => {
  await open(page);
  await openWizard(page);
  await field(page).click();
  await page.keyboard.type("kayg@o2", { delay: 5 });
  await page.keyboard.press("Tab");
  await expect(chips(page)).toHaveCount(1);
  // kayg owns the listed o2, so the typed login names that host: its chip is the host's own.
  await expect(chips(page).first()).toHaveAttribute("data-chip", "o2");
});

test("a listed host ticked in the list becomes a chip, and removing the chip unticks it", async ({ page }) => {
  await open(page);
  await openWizard(page);
  await page.locator(".ah-row[data-host='db-01']").click();
  await expect(chips(page).filter({ hasText: "db-01" })).toHaveCount(1);
  await page.locator(".ui-chip[data-chip='db-01'] .ui-chip-remove").click();
  await expect(page.locator(".ah-row[data-host='db-01'] input")).not.toBeChecked();
});

for (const size of SIZES) {
  for (const theme of THEMES) {
    test(`captures ${size.name} ${theme}`, async ({ page }) => {
      test.skip(process.env.ADDHOST_CHIPS_CAPTURE !== "1", "captures are produced on request");
      mkdirSync(OUT, { recursive: true });
      await open(page, theme, size.width, size.height);
      await openWizard(page);
      await field(page).click();
      await page.keyboard.type("a@h1 b@h2 c@h3", { delay: 5 });
      await expect(chips(page)).toHaveCount(2);
      await expect(field(page)).toHaveValue("c@h3");
      await page.waitForTimeout(400);
      await page.screenshot({ path: `${OUT}/chips-${size.name}-${theme}.png` });
      await field(page).fill("");
      await page.keyboard.type("kayg@", { delay: 5 });
      await expect(hint(page)).toHaveAttribute("data-show", "true");
      await page.waitForTimeout(400);
      await page.screenshot({ path: `${OUT}/hint-${size.name}-${theme}.png` });
    });
  }
}

test("a token typed while the host list is still loading chips when the list arrives", async ({ page }) => {
  // The double answers discovery late (its "hang" mode, 5 s): the person types before any host is listed.
  await page.request.post("/__mock/bootstrap/reset");
  await page.request.post("/__mock/bootstrap/config", { data: { discovery: "hang" } });
  await page.setViewportSize({ width: 1440, height: 900 });
  await page.goto("/?mock=1&proto=clusters&scene=3&theme=ink&bg=none");
  await expect(page.locator(".cl-mockup")).toBeVisible({ timeout: 20_000 });
  await openWizard(page);
  await field(page).click();
  await page.keyboard.type("remoternal", { delay: 5 });
  await expect(page.locator(".ah-note.ah-loading")).toBeVisible();
  await expect(chips(page)).toHaveCount(1, { timeout: 15_000 });
  await expect(chips(page).first()).toHaveAttribute("data-chip", "remoternal");
  await expect(page.locator(".ah-row[data-host='remoternal'] input")).toBeChecked();
});
