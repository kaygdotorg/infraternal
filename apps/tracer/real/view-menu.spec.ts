/** Generated Settings section cards are navigation rather than workspace memberships (#243). */
import { expect, test } from "playwright/test";
import { pair } from "./layout-devices";


test("Settings section cards have no workspace-window count", async ({ browser }) => {
  const fixture = await pair(browser);
  try {
    await fixture.page.locator("#capsule").click();
    await expect(fixture.page.locator('.cl-viewrow[data-view="settings"] .cl-viewrow-meta')).toHaveText("");
    await fixture.mobile.locator("#capsule").click();
    await expect(fixture.mobile.locator('.cl-viewrow[data-view="settings"] .cl-viewrow-meta')).toHaveText("");
  } finally { await fixture.dispose(); }
});
