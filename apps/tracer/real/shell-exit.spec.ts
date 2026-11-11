// SPDX-License-Identifier: AGPL-3.0-only
/**
 * What a window does when its shell ends, on the production server, the real infraternal agent and a real login
 * shell (#497, D357). A shell that exits by itself (`exit`, Ctrl-D), whatever its status, closes its window like
 * closing a terminal tab, and no toast reports it: `exit` after a Ctrl-C ends with 130 and still closes. Only a shell
 * killed by a signal (from outside, or a crash) keeps its window, with its final screen and the ended strip.
 *
 * Run it as root as well as rootless: a root host opens the person's shell through its login worker, a rootless one
 * opens it directly, and the owner hit the wrong status on both kinds of host.
 */
import { expect, test, type Page } from "playwright/test";
import { tracerEvidencePath } from "../test/evidence-path";
import { enrol, windows } from "./layout-devices";
import { watchLayout } from "./layout-observer";
import { startRealServer, type RealServer } from "./server";

/** Every toast message the page shows, recorded as it appears, so a toast that is quickly taken down is still seen. */
async function recordToasts(page: Page): Promise<() => Promise<string[]>> {
  await page.evaluate(() => {
    const w = window as unknown as { __toasts: string[] };
    w.__toasts = [];
    const seen = new WeakSet<Element>();
    const scan = (): void => {
      for (const message of document.querySelectorAll(".ui-toast-message")) {
        if (seen.has(message)) continue;
        seen.add(message);
        w.__toasts.push(message.textContent ?? "");
      }
    };
    new MutationObserver(scan).observe(document.body, { childList: true, subtree: true, characterData: true });
    scan();
  });
  return () => page.evaluate(() => (window as unknown as { __toasts: string[] }).__toasts);
}

/** Types one line into the console window's shell. */
async function typeLine(page: Page, line: string): Promise<void> {
  const host = page.locator('.cl[data-view="console"] .terminal-host');
  await host.click();
  await host.locator("textarea").focus();
  await page.keyboard.type(line, { delay: 10 });
  await page.keyboard.press("Enter");
}

/** The real server of the running test: each test starts its own and stops it afterwards. */
let server: RealServer;
test.beforeEach(async () => { server = await startRealServer({ port: Number(process.env.TRACER_TEST_PORT ?? 4673) }); });
test.afterEach(async () => { await server.dispose(); });

/** The terminal output the server relayed so far, as text. */
const output = (): string => server.bridges.flatMap((bridge) => [...bridge.output.values()]).join("");

/** Signs up on a fresh page, waits for a live prompt, runs `steps`, then checks the window closed with no exit toast. */
async function closesQuietly(browser: import("playwright/test").Browser, shot: string, steps: (page: Page) => Promise<void>): Promise<void> {
  const context = await browser.newContext({ viewport: { width: 1440, height: 900 }, ignoreHTTPSErrors: true });
  try {
    const page = watchLayout(await context.newPage());
    await enrol(page, server);
    const toasts = await recordToasts(page);
    await typeLine(page, "echo exit-ready");
    await expect.poll(output, { timeout: 15_000 }).toContain("exit-ready");
    await steps(page);
    await expect(windows(page)).toHaveCount(0, { timeout: 15_000 });
    // sleep: the relay shows a toast on a mutation callback; a quiet second after the close proves none follows it.
    await page.waitForTimeout(1_000);
    expect((await toasts()).filter((message) => /exit|error|status|signal/i.test(message))).toEqual([]);
    await page.screenshot({ path: tracerEvidencePath(shot) });
  } finally { await context.close(); }
}

test("a plain exit closes the window and shows no error", async ({ browser }) => {
  test.setTimeout(120_000);
  await closesQuietly(browser, "shell-exit-clean.png", (page) => typeLine(page, "exit"));
});

test("exit after a Ctrl-C (status 130) closes the window too (D357)", async ({ browser }) => {
  test.setTimeout(120_000);
  await closesQuietly(browser, "shell-exit-after-ctrl-c.png", async (page) => {
    // The shell prints the status it exits with; `$?` expands only when the trap runs, so the typed line has no digits.
    await typeLine(page, "trap 'echo exit-status-$?' EXIT");
    await typeLine(page, "sleep 30; echo slept-$((1+1))");
    await expect.poll(output, { timeout: 15_000 }).toContain("sleep 30");
    await page.keyboard.press("Control+C");
    // The interrupted `sleep` leaves 130 as the last status, and a plain `exit` returns it.
    await typeLine(page, "exit");
  });
  expect(output()).not.toContain("slept-2");
  expect(/exit-status-(\d+)/.exec(output())?.[1]).toBe("130");
});

test("exit with a failing status closes the window too (D357)", async ({ browser }) => {
  test.setTimeout(120_000);
  await closesQuietly(browser, "shell-exit-status-3.png", (page) => typeLine(page, "exit 3"));
});

test("a HUP-killed child leaves a normal status 129, which still closes", async ({ browser }) => {
  await closesQuietly(browser, "shell-exit-status-129.png", (page) => typeLine(page, "sh -c 'kill -HUP $$'; exit"));
});

test("an actual shell signal preserves the window and reports its signal", async ({ browser }) => {
  const context = await browser.newContext({ viewport: { width: 393, height: 852 }, ignoreHTTPSErrors: true });
  try {
    const page = watchLayout(await context.newPage());
    await enrol(page, server);
    const toasts = await recordToasts(page);
    await typeLine(page, "echo shell-pid-$$");
    await expect.poll(() => /shell-pid-(\d+)/.exec(output())?.[1]).toBeTruthy();
    process.kill(Number(/shell-pid-(\d+)/.exec(output())![1]), "SIGKILL");
    await expect.poll(toasts).toContain("Shell was stopped by signal 9. Open a new shell to continue.");
    await expect(windows(page)).toHaveCount(1);
    await page.screenshot({ path: tracerEvidencePath("shell-exit-killed-393.png") });
  } finally { await context.close(); }
});
