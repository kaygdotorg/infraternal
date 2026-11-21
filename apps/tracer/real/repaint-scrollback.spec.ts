/**
 * A host repaint keeps the scrollback the device already holds (#569, D381, D130). Production server binary, real PTY,
 * the production tracer, and a 300 ms round trip through the bridge.
 *
 * The typed program prints {@link HISTORY_ROWS} numbered rows, then waits for keys: `F` starts `yes` inside a scroll
 * region that does not start at the top, so the flood redraws in place and never adds a row to the history, and any
 * other key is printed. During the flood each key makes the infraternal agent drop its queued raw output and send a
 * repaint (Snapshot). Before #569 the browser reset its terminal for each repaint, so the history fell from thousands of
 * rows to the 256 the host sends. The check reads the history through the `?probe=1` page's counts: how many rows it
 * holds, how many of them are the printed rows, and how many "output skipped" markers it carries. The
 * server's Snapshot count proves the keys exercised the repaint path, so the spec cannot pass because no repaint
 * happened.
 */
import { expect, test, type Page } from "playwright/test";
import { writeFile } from "node:fs/promises";
import { personName, startRealServer, type RealServer } from "./server";

test.describe.configure({ mode: "serial" });
/** The real server this file starts with a 150 ms delay each way; disposed after the test. */
let server: RealServer;
/** The signed-in page whose single terminal floods. */
let page: Page;

/** Rows of history printed before the flood. */
const HISTORY_ROWS = Number(process.env.REPAINT_HISTORY_ROWS ?? 500);
/** Set to measure the cost of a repaint with the history at its limit; the history is then evicted, so it is not compared. */
const COST_ONLY = process.env.REPAINT_COST_ONLY === "1";
/**
 * The history must hold more than the 256 rows the host sends with a repaint, or a repaint could not cut it. The
 * terminal's history is limited in bytes, so it holds only a few hundred to a thousand rows, more at a narrow width, so the page is narrow; {@link HISTORY_ROWS}
 * stays under that limit so the check does not mistake normal eviction of old rows for a cut.
 */
const MIN_HISTORY_ROWS = 400;
/** Every printed row starts with this, so the oldest history row can be recognised. */
const HISTORY_PREFIX = "HIST-";
/**
 * The typed program: `seq` prints the history, `ESC [2r` then keeps the flood off row 1 and out of the history, `F`
 * starts `yes`, `S` stops it and ends, and any other key is printed. `-icanon` keeps output processing on.
 */
const PROGRAM =
  `bash --norc -c 'stty -icanon -echo; seq -f "${HISTORY_PREFIX}%06g" 1 ${HISTORY_ROWS}; printf "\\033[2r\\033[2;1H"; flood_pid=; ` +
  "while IFS= read -rsn1 c; do if [ \"$c\" = F ]; then yes & flood_pid=$!; elif [ \"$c\" = S ]; then " +
  "kill \"$flood_pid\" 2>/dev/null || :; wait \"$flood_pid\" 2>/dev/null || :; break; else printf \"%s\" \"$c\"; fi; done; stty sane'";
/** Keys typed during the flood. */
const KEYS = 12;
/** A step that does not finish within this long counts as a frozen terminal. */
const FREEZE_MS = 15_000;
/** The program's start on a loaded VM. */
const START_MS = 90_000;

test.beforeAll(async ({ browser }) => {
  server = await startRealServer({ latencyMs: 150, recordFlow: true });
  const context = await browser.newContext({ ignoreHTTPSErrors: true, viewport: { width: 640, height: 800 } });
  page = await context.newPage();
  const cdp = await context.newCDPSession(page);
  await cdp.send("WebAuthn.enable");
  await cdp.send("WebAuthn.addVirtualAuthenticator", { options: { protocol: "ctap2", ctap2Version: "ctap2_1", transport: "internal", hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true, hasPrf: true } });
  // Probe mode is the single-terminal screen, the same one the same-session flood spec measures.
  await page.goto(server.origin + "/?theme=ink&bg=none&probe=1");
  await page.locator("#setup-token").fill(server.token);
  await page.getByRole("button", { name: "Continue", exact: true }).click();
  await page.locator("#setup-username").fill(personName("repaint_scrollback"));
  await page.locator("#setup-display-name").fill("Repaint scrollback");
  await page.getByRole("button", { name: "Continue", exact: true }).click();
  await page.getByRole("button", { name: "Create passkey" }).click();
  await page.getByRole("heading", { name: "Save your recovery key" }).waitFor();
  await page.locator(".auth-check").click();
  await page.getByRole("button", { name: "Open infraternal" }).click();
  await page.locator(".terminal-host").first().waitFor();
});
test.afterAll(async () => { await page?.context().close(); await server?.dispose(); });

/** The newest open bridge with an attached terminal stream. */
function terminalBridge() {
  const bridge = server.bridges.filter((candidate) => !candidate.closed && candidate.attached.size > 0).at(-1);
  if (!bridge) throw new Error("no active terminal bridge");
  return bridge;
}

/** Snapshots the server has sent to the browser on `bridge` so far (the flow trace keeps only those). */
function snapshotsSent(bridge: ReturnType<typeof terminalBridge>): number {
  return (bridge.flowTimes ?? []).filter((event) => event.type === "Snapshot").length;
}

/** The history counts of the page's terminal. */
async function history() {
  const summary = await page.evaluate((prefix) => window.__tracerPerformanceProbe?.scrollbackSummary(prefix), HISTORY_PREFIX);
  if (!summary) throw new Error("the probe page has no terminal");
  return summary;
}

test("a repaint during an output flood keeps the history from before it", async () => {
  test.setTimeout(180_000);
  await expect.poll(() => server.bridges.filter((b) => !b.closed).at(-1)?.attached.size ?? 0, { timeout: FREEZE_MS }).toBe(1);
  await page.locator("#probe-panel").evaluate((element) => { (element as HTMLElement).hidden = true; });
  const bridge = terminalBridge();
  bridge.flowFilter = new Set(["down:backend-receive:Snapshot"]);
  bridge.skipOutputText = true;
  const routeKept = (): boolean => server.bridges.filter((c) => !c.closed && c.attached.size > 0).at(-1)?.id === bridge.id;
  const started = bridge.outputBytesSeen ?? 0;
  await page.locator(".terminal-host").first().click({ position: { x: 60, y: 60 } });
  await page.keyboard.type(PROGRAM + "\n", { delay: 2 });
  await expect.poll(() => bridge.outputBytesSeen ?? 0, { timeout: FREEZE_MS }).toBeGreaterThan(started);
  // The program has printed its history once the page's history holds all of its rows (a loaded VM can take a while).
  await expect.poll(async () => (await history()).printedRows, { timeout: START_MS }).toBeGreaterThanOrEqual(MIN_HISTORY_ROWS);
  // sleep: the last printed rows may still be arriving; read the history once it has settled.
  await page.waitForTimeout(1500);
  const before = await history();

  const floodStart = bridge.outputBytesSeen ?? 0;
  await page.keyboard.press("F");
  await expect.poll(() => (bridge.outputBytesSeen ?? 0) - floodStart, { timeout: START_MS }).toBeGreaterThan(256 * 1024);
  const snapshotsBefore = (bridge.flowTimes ?? []).filter((event) => event.type === "Snapshot").length;
  /** The history's row count after each key, so a loss that builds up over repaints shows. */
  const rowsAfterKey: number[] = [];
  const keepBytesAfterKey: number[] = [];
  for (let key = 0; key < KEYS; key += 1) {
    await page.keyboard.press(String.fromCharCode(97 + key));
    // sleep: pace keys like a person typing, so each one meets a fresh flood and gets its own repaint.
    await page.waitForTimeout(500);
    const now = await history();
    rowsAfterKey.push(now.rows);
    keepBytesAfterKey.push(now.lastKeepBytes);
  }
  // sleep: let the last key's repaint (300 ms round trip) arrive and paint before the history is read.
  await page.waitForTimeout(1500);
  const snapshots = (bridge.flowTimes ?? []).filter((event) => event.type === "Snapshot").length - snapshotsBefore;
  const after = await history();
  const summary = { keys: KEYS, snapshots, routeKept: routeKept(), before, after, rowsAfterKey, keepBytesAfterKey };
  console.log("REPAINT_SCROLLBACK " + JSON.stringify(summary));
  await writeFile(test.info().outputPath("repaint-scrollback.json"), JSON.stringify(summary));

  const bytesBeforeStop = bridge.outputBytesSeen ?? 0;
  await page.keyboard.press("S");
  await expect.poll(() => bridge.outputBytesSeen ?? 0, { timeout: FREEZE_MS }).toBeGreaterThan(bytesBeforeStop);
  // sleep: the flood has stopped; let the last output paint so the scroll position below is not pulled back down.
  await page.waitForTimeout(2000);
  // What a person sees when they scroll back: a little way up (the repaints' marker rows), and all the way up.
  const canvas = page.locator(".terminal-host canvas").first();
  const box = await canvas.boundingBox();
  if (box) await page.mouse.move(box.x + box.width / 2, box.y + box.height / 2);
  await page.mouse.wheel(0, -17 * 60);
  // sleep: the scroll animates; wait for it to settle before the picture.
  await page.waitForTimeout(1000);
  await canvas.screenshot({ path: test.info().outputPath("scrolled-back-a-little.png") });
  await page.mouse.wheel(0, -1_000_000);
  // sleep: same.
  await page.waitForTimeout(1500);
  await canvas.screenshot({ path: test.info().outputPath("scrolled-back-to-the-top.png") });

  expect(routeKept(), "the flood must not cost the browser its route").toBe(true);
  expect(snapshots, "keys during the flood must make the server repaint").toBeGreaterThanOrEqual(KEYS / 4);
  if (COST_ONLY) return;
  expect(after.rows, "the repaints must not cut the history").toBeGreaterThanOrEqual(before.rows);
  expect(after.printedRows, "every printed row is still in the history").toBeGreaterThanOrEqual(before.printedRows);
  expect(after.skippedMarkers, "skipped output is marked where it was dropped").toBeGreaterThanOrEqual(1);
});
