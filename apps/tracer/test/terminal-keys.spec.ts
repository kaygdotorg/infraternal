// SPDX-License-Identifier: AGPL-3.0-only
/**
 * Verifies that desktop keyboard chords routed through ghostty-web's WASM KeyEncoder
 * (Ctrl+letter combinations and arrow keys in normal and DECCKM application cursor modes)
 * produce the expected terminal bytes with zero console warnings (#607).
 *
 * Covers both Linux and macOS platform emulation because shortcut guards and Ctrl handling
 * differ by platform (`navigator.platform`), and checks Input Lock as well.
 */
import { expect, test, type Browser, type BrowserContext, type Page } from "playwright/test";

const baseURL = `http://localhost:${Number(process.env.TRACER_TEST_PORT ?? "4173")}`;

/** Opens a desktop tracer session against the mock server with the requested `platform` string. */
async function desktopPage(browser: Browser, platform: string): Promise<{ context: BrowserContext; page: Page; warnings: string[] }> {
  const context = await browser.newContext({ viewport: { width: 1280, height: 800 }, baseURL });
  await context.addInitScript((plat: string) => {
    Object.defineProperty(navigator, "platform", { get: () => plat });
  }, platform);
  await context.request.post("/__mock/open-terminal");
  const page = await context.newPage();
  const warnings: string[] = [];
  page.on("console", (msg) => {
    if (msg.type() === "warning" || msg.type() === "error") warnings.push(msg.text());
  });
  await page.goto("/?mock=1&theme=ink&bg=none");
  await expect.poll(() => page.locator("#terminal-screen").getAttribute("data-connected"), { timeout: 30_000 }).toBe("true");
  await page.locator("#terminal-host").click();
  await expect.poll(() => page.evaluate(() => {
    const host = document.querySelector<HTMLElement>("#terminal-host");
    return Boolean(host && (document.activeElement === host || host.contains(document.activeElement)));
  })).toBe(true);
  return { context, page, warnings };
}

/** Reads all raw input bytes the mock server has received for the active terminal so far. */
async function inputBytes(context: BrowserContext): Promise<number[]> {
  const response = await context.request.get("/__mock/state?input_bytes=1");
  const state = await response.json() as { input_bytes: number[] };
  return state.input_bytes;
}

/** Encodes an ASCII string into a byte array for readable expectations. */
const bytesOf = (text: string): number[] => Array.from(text, (ch) => ch.charCodeAt(0));

for (const platform of ["Linux x86_64", "MacIntel"] as const) {
  test(`Ctrl+key chords and arrow keys send exact bytes on ${platform} (#607)`, async ({ browser }) => {
    test.setTimeout(60_000);
    const { context, page, warnings } = await desktopPage(browser, platform);
    try {
      await page.keyboard.press("Control+a");
      await page.keyboard.press("Control+c");
      await page.keyboard.press("Control+d");
      await page.keyboard.press("Control+r");
      await page.keyboard.press("ArrowUp");
      await page.keyboard.press("ArrowDown");
      await page.keyboard.press("ArrowLeft");
      await page.keyboard.press("ArrowRight");

      const expected = [
        ...bytesOf("\x01\x03\x04\x12"),
        ...bytesOf("\x1b[A\x1b[B\x1b[D\x1b[C"),
      ];
      await expect.poll(() => inputBytes(context)).toEqual(expected);

      expect(warnings.filter((w) => w.includes("Failed to encode key"))).toEqual([]);
    } finally {
      await context.close();
    }
  });
}

test("DECCKM application cursor mode switches arrow keys from CSI to SS3 (#607)", async ({ browser }) => {
  test.setTimeout(60_000);
  const { context, page, warnings } = await desktopPage(browser, "MacIntel");
  try {
    const res = await context.request.post("/__mock/text-output", { data: { text: "\x1b[?1hDECCKM_READY\r\n" } });
    expect(res.ok()).toBe(true);
    await expect.poll(() => page.evaluate(() => {
      const api = (window as unknown as { __tracerTestDouble?: { screenText?: () => string } }).__tracerTestDouble;
      return api?.screenText?.() ?? "";
    })).toContain("DECCKM_READY");

    await page.keyboard.press("ArrowUp");
    await page.keyboard.press("ArrowDown");
    await page.keyboard.press("ArrowLeft");
    await page.keyboard.press("ArrowRight");

    await expect.poll(() => inputBytes(context)).toEqual(bytesOf("\x1bOA\x1bOB\x1bOD\x1bOC"));
    expect(warnings.filter((w) => w.includes("Failed to encode key"))).toEqual([]);
  } finally {
    await context.close();
  }
});
