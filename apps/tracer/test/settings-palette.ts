/** Opens a Settings window through the palette, the way a person does (#304): the words are typed and the row for the window is pressed.
 *  Pressing Enter on the first row is not enough, because the same words also match "Open shell on ..." rows. */
import { expect, type Page } from "playwright/test";

export async function paletteOpen(page: Page, words: string, target: string): Promise<void> {
  await page.keyboard.press("Control+Shift+K");
  await expect(page.locator("#palette-input")).toBeFocused({ timeout: 10_000 });
  await page.keyboard.type(words);
  const row = page.locator(`#palette-results .result[data-action="canvas:settings:${target}"]`);
  await expect(row).toBeVisible({ timeout: 10_000 });
  await row.click();
}
