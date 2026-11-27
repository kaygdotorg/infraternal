// SPDX-License-Identifier: AGPL-3.0-only
/**
 * Real-shell browser regression for Ctrl+key combinations and arrow keys (#607).
 *
 * Drives a real PTY shell through the production `infraternal` server and tracer bundle:
 * 1. Captures raw bytes arriving at the shell (`stty raw -echo; dd` + `od -An -tx1`) for
 *    Ctrl+A, Ctrl+R, Ctrl+C, Ctrl+D and ArrowUp/Down/Left/Right — both without and with
 *    Input Lock active.
 * 2. Runs `sleep 100`, presses `Ctrl+C`, and asserts the shell interrupts it immediately
 *    with exit status 130.
 */
import { expect, test, type Page } from "playwright/test";
import { enrol } from "./layout-devices";
import { watchLayout } from "./layout-observer";
import { startRealServer, type RealServer } from "./server";

/** Focuses the console window's terminal host and types `line` followed by Enter. */
async function typeLine(page: Page, line: string): Promise<void> {
  const host = page.locator('.cl[data-view="console"] .terminal-host');
  await host.click();
  await host.locator("textarea").focus();
  await page.keyboard.type(line, { delay: 10 });
  await page.keyboard.press("Enter");
}

/** The real server instance started per test and disposed afterwards. */
let server: RealServer;
test.beforeEach(async () => { server = await startRealServer({ port: Number(process.env.TRACER_TEST_PORT ?? 4679) }); });
test.afterEach(async () => { await server.dispose(); });

/** All terminal output bytes the production server relayed to the browser so far. */
const output = (): string => server.bridges.flatMap((bridge) => [...bridge.output.values()]).join("");

test("real shell receives exact Ctrl+key and arrow bytes and interrupts sleep 100 (#607)", async ({ browser }) => {
  test.setTimeout(120_000);
  const context = await browser.newContext({ viewport: { width: 1440, height: 900 }, ignoreHTTPSErrors: true });
  const warnings: string[] = [];
  try {
    const page = watchLayout(await context.newPage());
    page.on("console", (msg) => {
      if (msg.type() === "warning" || msg.type() === "error") warnings.push(msg.text());
    });
    await enrol(page, server);
    await typeLine(page, "echo keys-ready");
    await expect.poll(output, { timeout: 15_000 }).toContain("keys-ready");

    // 1. Capture exact raw bytes for Ctrl+A (01), Ctrl+R (12), Ctrl+C (03), Ctrl+D (04),
    //    and ArrowUp/Down/Left/Right (1b 5b 41/42/44/43) = 16 bytes total.
    await typeLine(
      page,
      "stty -echo raw; dd bs=1 count=16 2>/dev/null | od -An -tx1 | tr -d '\\n' | sed 's/^/HEX_RAW:/;s/$/:END_RAW/'; stty sane; echo",
    );
    await expect.poll(output, { timeout: 15_000 }).toContain("stty -echo raw");
    // sleep: give the shell a brief moment to execute `stty raw` before the probe keys arrive.
    await page.waitForTimeout(300);

    await page.keyboard.press("Control+a");
    await page.keyboard.press("Control+r");
    await page.keyboard.press("Control+c");
    await page.keyboard.press("Control+d");
    await page.keyboard.press("ArrowUp");
    await page.keyboard.press("ArrowDown");
    await page.keyboard.press("ArrowLeft");
    await page.keyboard.press("ArrowRight");

    await expect.poll(output, { timeout: 15_000 }).toMatch(/HEX_RAW:\s*01 12 03 04 1b 5b 41 1b 5b 42 1b 5b 44 1b 5b 43\s*:END_RAW/);

    // 2. Same check with Input Lock active (Ctrl+Shift+L).
    await page.keyboard.press("Control+Shift+L");
    await expect.poll(() => page.locator("#stage").getAttribute("data-locked")).not.toBeNull();

    await typeLine(
      page,
      "stty -echo raw; dd bs=1 count=7 2>/dev/null | od -An -tx1 | tr -d '\\n' | sed 's/^/HEX_LOCK:/;s/$/:END_LOCK/'; stty sane; echo",
    );
    await expect.poll(output, { timeout: 15_000 }).toContain("HEX_LOCK:");
    // Wait for dd to start (avoid matching the echoed command string itself by waiting for the command line).
    // sleep: allow the shell to switch the PTY into raw mode before sending the 7 locked probe bytes.
    await page.waitForTimeout(300);

    await page.keyboard.press("Control+c");
    await page.keyboard.press("ArrowUp");
    await page.keyboard.press("ArrowDown");

    await expect.poll(output, { timeout: 15_000 }).toMatch(/HEX_LOCK:\s*03 1b 5b 41 1b 5b 42\s*:END_LOCK/);

    // Release Input Lock.
    await page.keyboard.press("Control+Shift+L");
    await expect.poll(() => page.locator("#stage").getAttribute("data-locked")).toBeNull();

    // 3. Running `sleep 100` + Ctrl+C interrupts immediately with exit status 130.
    await typeLine(page, "sleep 100; echo SLEEP_STATUS=$?");
    await expect.poll(output, { timeout: 15_000 }).toContain("sleep 100");
    // sleep: let the shell spawn `sleep 100` before sending SIGINT via Ctrl+C.
    await page.waitForTimeout(300);
    await page.keyboard.press("Control+c");
    await expect.poll(output, { timeout: 10_000 }).toContain("SLEEP_STATUS=130");

    expect(warnings.filter((w) => w.includes("Failed to encode key"))).toEqual([]);
  } finally {
    await context.close();
  }
});
