/**
 * Icon and text share one centre line (#282, TASTE "Icon and text share one centre line"): on representative screens, every
 * icon that sits beside text in a row is within 0.5 px of the text's centre, both of its first line box and of its capital
 * letters (icon-text-audit.ts). Run on a desktop and a phone page, in the default font.
 *
 * The audit is generic: it pairs every icon with the text beside it, whatever component drew the row, so a new component that
 * nudges its icon with a margin is caught the same way as the shared ones.
 */
import { expect, test, type Page } from "playwright/test";
import { auditIconText, type IconTextPair } from "./icon-text-audit";

const sleep = (page: Page, ms: number): Promise<void> => page.waitForTimeout(ms);
const mock = (query: string): string => `/?mock=1&proto=clusters&${query}&theme=ink&bg=none`;
const sidebar = async (page: Page): Promise<void> => { await page.locator("#sidebar-toggle").click(); await sleep(page, 800); };

const STATES: Array<[string, string, (page: Page) => Promise<void>]> = [
  ["sidebar", mock("scene=3"), sidebar],
  ["palette", mock("scene=3"), async (p) => { await p.keyboard.press("Control+Shift+K"); await sleep(p, 600); }],
  ["window details popover", mock("scene=3"), async (p) => { await p.locator(".ui-window-pill").first().click(); await sleep(p, 900); }],
  ["settings: typing (toolbar and shortcuts)", mock("scene=1"), async (p) => {
    // Waits for the mockup's live terminal to take the keys first, then for the palette and for the row it will run, not for fixed
    // times: on a slow or busy device the terminal attaches seconds late and takes the focus from a palette opened before that, so
    // the typed words went nowhere and Enter ran the first row (the all-views overview, which has no Settings window at reading size).
    await expect(p.locator("textarea:focus")).toHaveCount(1, { timeout: 20_000 });
    await p.keyboard.press("Control+Shift+K");
    await expect(p.locator("#palette-input")).toBeFocused();
    await p.keyboard.type("Terminal Typing", { delay: 6 });
    await expect(p.locator("#palette-results .result").first()).toContainText("Terminal › Typing");
    await p.keyboard.press("Enter");
    await expect(p.locator("#palette")).toBeHidden();
    await sleep(p, 1600);
  }],
];

for (const [size, viewport, scale, mobile] of [["desktop", { width: 1440, height: 900 }, 2, false], ["phone", { width: 393, height: 852 }, 3, true]] as const) {
  test.describe(`${size}: every icon sits on its text's centre line`, () => {
    test.use({ viewport, deviceScaleFactor: scale, isMobile: mobile, hasTouch: mobile });
    test.setTimeout(90_000);
    for (const [name, url, run] of STATES) {
      test(name, async ({ page }) => {
        if (mobile && /palette|toolbar/.test(name)) test.skip(true, "reached by keyboard: desktop only");
        await page.goto(url);
        await expect(page.locator(".cl-mockup, .ui-window").first()).toBeVisible({ timeout: 25_000 });
        await sleep(page, 900);
        await run(page);
        const pairs: IconTextPair[] = await page.evaluate(auditIconText);
        const bad = pairs.filter((p) => Math.abs(p.box) > 0.5 || Math.abs(p.cap) > 0.5);
        expect(bad, `${pairs.length} icon/text pairs on "${name}"; off by more than 0.5 px:\n${bad.map((p) => `  box ${p.box}, cap ${p.cap}  "${p.sample}"  icon ${p.icon}  text ${p.text}`).join("\n")}`).toEqual([]);
      });
    }
  });
}
