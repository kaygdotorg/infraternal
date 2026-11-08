/**
 * A program in the terminal copies with OSC 52 (`printf '\e]52;c;<base64>\a'`, or a multiplexer or editor over SSH),
 * and the text must end up on the page's clipboard (#440). Runs on the production tracer build, through the same live
 * output path as real PTY bytes, at a desktop and a phone viewport.
 *
 * Two outcomes are checked: the browser allows the write (the text is on the clipboard and a short "Copied" notice
 * shows), and the browser refuses it because no gesture or permission is present (the text waits behind a "Copy"
 * action; its tap is the gesture, and the text lands then).
 */
import { expect, test, type BrowserContext, type Page } from "playwright/test";
import { mkdirSync } from "node:fs";
import { tracerEvidencePath } from "./evidence-path";

const VIEWPORTS = [
  { name: "desktop", width: 1440, height: 900, dpr: 2, touch: false },
  { name: "phone", width: 393, height: 852, dpr: 3, touch: true },
] as const;
const OUT = tracerEvidencePath("osc52");
/** Text with spaces, a newline and non-ASCII, so a wrong decode (latin1, lost line break) shows. */
const COPIED = "kubectl get pods -n prod\nnaïve ✓ 日本";
const base64 = (text: string): string => Buffer.from(text, "utf8").toString("base64");
const copySequence = (text: string, targets = "c", end = "\u0007"): string => `\u001b]52;${targets};${base64(text)}${end}`;

for (const viewport of VIEWPORTS) {
  test.describe(`${viewport.name} ${viewport.width}x${viewport.height}`, () => {
    test.use({
      viewport: { width: viewport.width, height: viewport.height },
      deviceScaleFactor: viewport.dpr,
      hasTouch: viewport.touch,
      isMobile: viewport.touch,
    });

    /** Opens the single-terminal screen on the test double and waits until the terminal is attached. */
    async function open(context: BrowserContext): Promise<Page> {
      const page = await context.newPage();
      await context.request.post("/__mock/reset");
      await context.request.post("/__mock/open-terminal");
      await page.goto("/?mock=1&proto=product&bg=none&fixture=none&theme=ink");
      await expect.poll(() => page.evaluate(() => window.__tracerProductTestDouble?.isConnected() === true), { timeout: 30_000 }).toBe(true);
      return page;
    }
    const output = async (context: BrowserContext, text: string): Promise<void> => {
      expect((await context.request.post("/__mock/live-query-output", { data: { text } })).ok()).toBe(true);
    };
    const clipboard = (page: Page): Promise<string> => page.evaluate(() => navigator.clipboard.readText());

    test("a remote copy lands on the clipboard and says so", async ({ context }) => {
      mkdirSync(OUT, { recursive: true });
      await context.grantPermissions(["clipboard-read", "clipboard-write"]);
      const page = await open(context);
      await page.evaluate(() => navigator.clipboard.writeText("before"));
      // A copy in two output frames, with an unrelated sequence and the string terminator (ESC \) in between.
      const sequence = copySequence(COPIED, "c", "\u001b\\");
      await output(context, `\u001b[2J\u001b[Hhello\r\n${sequence.slice(0, 9)}`);
      await output(context, `${sequence.slice(9)}\r\ndone\r\n`);
      await expect.poll(() => clipboard(page), { timeout: 10_000 }).toBe(COPIED);
      await expect(page.locator(".ui-toast")).toContainText("Copied");
      await page.screenshot({ path: `${OUT}/${viewport.name}-copied.png` });
    });

    test("a read request and an empty write leave the clipboard alone", async ({ context }) => {
      await context.grantPermissions(["clipboard-read", "clipboard-write"]);
      const page = await open(context);
      await page.evaluate(() => navigator.clipboard.writeText("keep me"));
      await output(context, "\u001b]52;c;?\u0007\u001b]52;c;\u0007\u001b]52;c;@@not-base64@@\u0007\u001b]52;0;" + base64("cut buffer") + "\u0007");
      await output(context, `${copySequence("marker")}`);
      await expect.poll(() => clipboard(page), { timeout: 10_000 }).toBe("marker");
      expect(await page.locator(".ui-toast").count()).toBe(1);
    });

    test("when the browser refuses the write, a Copy action waits and its tap completes the copy", async ({ context }) => {
      mkdirSync(OUT, { recursive: true });
      // Reading is granted so the test can look; writing is not, as on a page that has had no gesture.
      await context.grantPermissions(["clipboard-read"]);
      const page = await open(context);
      await page.evaluate(() => {
        const real = navigator.clipboard.writeText.bind(navigator.clipboard);
        // Refuse until the tap: a write outside a gesture is rejected by Safari and by a Chromium page without permission.
        navigator.clipboard.writeText = async (text: string) => {
          if (!navigator.userActivation.isActive) throw new DOMException("Needs a gesture", "NotAllowedError");
          await real(text);
        };
        document.execCommand = () => false;
      });
      await page.evaluate(() => navigator.clipboard.writeText("untouched").catch(() => undefined));
      await output(context, `\u001b[2J\u001b[Hremote\r\n${copySequence(COPIED)}`);
      const toast = page.locator(".ui-toast").filter({ hasText: /copy/i });
      await expect(toast).toBeVisible({ timeout: 10_000 });
      const action = toast.locator(".ui-toast-action", { hasText: "Copy" });
      await expect(action).toBeVisible();
      expect(await clipboard(page)).not.toBe(COPIED);
      await page.screenshot({ path: `${OUT}/${viewport.name}-copy-prompt.png` });
      // The action stays inside the viewport and is a real tap target.
      const box = (await action.boundingBox())!;
      expect(box.x).toBeGreaterThanOrEqual(0);
      expect(box.x + box.width).toBeLessThanOrEqual(viewport.width);
      expect(box.height).toBeGreaterThanOrEqual(viewport.touch ? 32 : 20);
      if (viewport.touch) await action.tap(); else await action.click();
      await expect.poll(() => clipboard(page), { timeout: 10_000 }).toBe(COPIED);
      await expect(page.locator(".ui-toast")).toContainText("Copied");
      await page.screenshot({ path: `${OUT}/${viewport.name}-copy-done.png` });
    });

    test("a copy in replayed output after a reconnect does not touch the clipboard", async ({ context }) => {
      await context.grantPermissions(["clipboard-read", "clipboard-write"]);
      const page = await open(context);
      await output(context, `\u001b[2J\u001b[Hold\r\n${copySequence("first")}`);
      await expect.poll(() => clipboard(page), { timeout: 10_000 }).toBe("first");
      await page.evaluate(() => navigator.clipboard.writeText("user copied this since"));
      expect((await context.request.post("/__mock/drop-sockets")).ok()).toBe(true);
      await expect.poll(() => page.evaluate(() => window.__tracerProductTestDouble?.isConnected() === true), { timeout: 30_000 }).toBe(true);
      await output(context, "after reconnect\r\n");
      await expect(async () => expect(await page.evaluate(() => window.__tracerProductTestDouble?.screenText() ?? "")).toContain("after reconnect")).toPass({ timeout: 15_000 });
      expect(await clipboard(page)).toBe("user copied this since");
    });
  });
}
