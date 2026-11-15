/**
 * A terminal reopened at another width must not show old-width bytes (#521).
 *
 * J745 reopened a tab at a different pane width and saw a prompt line's wrapped tail written over its start: the shim
 * replayed raw PTY bytes laid out for the old width into the new one. These specs drive the real server, shim and a
 * production tracer build. They type a line that wraps at width A, leave the page, and come back at width B. Then they
 * check, from the browser's own WebSocket frames, that the reopened screen is a host repaint taken after the tab's
 * Resize, which the shim's engine has reflowed. A same-size reopen must keep the raw replay with no repaint, and a live
 * resize with no reconnect must keep streaming. Each case logs a timing receipt: AttachTerm to the replay fence, and to
 * the last repaint. Screenshots go under the tracer evidence directory for review at 393 px and 1440 px.
 */
import { expect, test, type Page } from "playwright/test";
import { WebSocketFrameDecoder } from "../../../packages/protocol/src/codec";
import { enrol } from "./layout-devices";
import { watchLayout } from "./layout-observer";
import { startRealServer } from "./server";
import { tracerEvidencePath } from "../test/evidence-path";

/** What one terminal WebSocket carried, in order, with the browser-side arrival time of each event. */
interface Connection {
  order: string[];
  attachAt?: number;
  fenceAt?: number;
  lastRepaintAt?: number;
  snapshots: number;
  approximate: number;
}

/** Records attach, resize, replay-fence and repaint frames on every terminal socket of `page`; never terminal text. */
function observe(page: Page): Connection[] {
  const connections: Connection[] = [];
  page.on("websocket", (socket) => {
    if (!socket.url().endsWith("/v1/ws")) return;
    const connection: Connection = { order: [], snapshots: 0, approximate: 0 };
    connections.push(connection);
    const up = new WebSocketFrameDecoder(), down = new WebSocketFrameDecoder();
    socket.on("framesent", ({ payload }) => {
      if (typeof payload === "string") return;
      up.feed(new Uint8Array(payload), (_stream, frame) => {
        if (frame.type === "AttachTerm") { connection.attachAt ??= performance.now(); connection.order.push("attach"); }
        if (frame.type === "Resize") connection.order.push(`resize:${frame.cols}x${frame.rows}`);
      });
    });
    socket.on("framereceived", ({ payload }) => {
      if (typeof payload === "string") return;
      down.feed(new Uint8Array(payload), (_stream, frame) => {
        if (frame.type === "Snapshot") {
          connection.snapshots++;
          connection.lastRepaintAt = performance.now();
          connection.order.push("snapshot");
        }
        if (frame.type !== "Event") return;
        const notice = JSON.parse(new TextDecoder().decode(frame.eventJson));
        if (notice.type === "terminal.replay_complete") {
          connection.fenceAt ??= performance.now();
          connection.order.push(`fence:${notice.cols}x${notice.rows}`);
        }
        if (notice.type === "terminal.snapshot" && notice.approximate === true) connection.approximate++;
      });
    });
  });
  return connections;
}

/** The Resize sizes a connection sent, in order. */
function sizes(connection: Connection): string[] {
  return connection.order.filter((step) => step.startsWith("resize:"));
}

/** Content-free timing receipt: milliseconds from AttachTerm to the replay fence and to the last repaint. */
function timing(connection: Connection): { fenceMs?: number; repaintMs?: number } {
  const since = (at?: number) => (at === undefined || connection.attachAt === undefined ? undefined : Math.round((at - connection.attachAt) * 10) / 10);
  return { fenceMs: since(connection.fenceAt), repaintMs: since(connection.lastRepaintAt) };
}

/** Opens a session at `typeWidth`, types a line that wraps there, and returns the page and its observed sockets. */
async function wrappedSession(browser: import("playwright/test").Browser, typeWidth: number) {
  const server = await startRealServer({ port: Number(process.env.TRACER_TEST_PORT ?? 4857) });
  const context = await browser.newContext({ viewport: { width: typeWidth, height: 852 }, ignoreHTTPSErrors: true });
  const page = watchLayout(await context.newPage());
  const connections = observe(page);
  await enrol(page, server);
  const host = page.locator('.cl[data-view="console"] .terminal-host');
  await expect(host.locator("textarea")).toHaveCount(1);
  await host.click();
  await host.locator("textarea").focus();
  // About 70 columns of command after the prompt: wraps at a phone width, fits at 1440 px.
  await page.keyboard.type("printf '%s-%s\\n' j751 reflow-0123456789-abcdefghij-0123456789-done");
  await page.keyboard.press("Enter");
  await expect.poll(() => server.bridges.flatMap((bridge) => [...bridge.output.values()]).join("")).toContain("j751-reflow-0123456789-abcdefghij-0123456789-done");
  // sleep: let the prompt after the command reach the browser before the page is left.
  await page.waitForTimeout(1_000);
  return { server, context, page, host, connections };
}

/** Leaves the page, changes the viewport while no renderer is attached, and opens the same URL again. */
async function reopen(page: Page, connections: Connection[], width: number): Promise<Connection> {
  const url = page.url();
  const before = connections.length;
  await page.goto("about:blank");
  await page.setViewportSize({ width, height: 852 });
  await page.goto(url);
  await expect(page.locator('.cl[data-view="console"] .terminal-host textarea')).toHaveCount(1);
  await expect.poll(() => connections.length).toBeGreaterThan(before);
  await expect.poll(() => connections.at(-1)?.fenceAt).toBeDefined();
  // sleep: give a late repaint (the Resize answered after the fence) time to arrive before the frame order is judged.
  await page.waitForTimeout(1_500);
  return connections.at(-1)!;
}

for (const [from, to] of [[393, 1440], [1440, 393]] as const) test(`a session reopened ${to > from ? "wider" : "narrower"} (${from} → ${to} px) is repainted at its new size`, async ({ browser }) => {
  test.setTimeout(120_000);
  const { server, context, page, connections } = await wrappedSession(browser, from);
  try {
    await page.screenshot({ path: tracerEvidencePath(`j751-typed-${from}.png`) });
    const current = await reopen(page, connections, to);
    console.log("J751_REOPEN_RECEIPT", JSON.stringify({ from, to, ...timing(current), snapshots: current.snapshots, approximate: current.approximate, order: current.order }));
    await page.screenshot({ path: tracerEvidencePath(`j751-reopened-${from}-to-${to}.png`) });
    const resize = current.order.indexOf(sizes(current)[0]!);
    expect(resize).toBeGreaterThanOrEqual(0);
    // The last thing that painted the screen is a host repaint taken after the tab reported its new size.
    expect(current.order.lastIndexOf("snapshot")).toBeGreaterThan(resize);
  } finally { await context.close(); await server.dispose(); }
});

test("a session reopened at the same size keeps the raw replay", async ({ browser }) => {
  test.setTimeout(120_000);
  const { server, context, page, connections } = await wrappedSession(browser, 1440);
  try {
    const current = await reopen(page, connections, 1440);
    console.log("J751_SAME_SIZE_RECEIPT", JSON.stringify({ ...timing(current), snapshots: current.snapshots, order: current.order }));
    expect(current.snapshots).toBe(0);
  } finally { await context.close(); await server.dispose(); }
});

test("a live resize without a reconnect keeps streaming and adds no repaint", async ({ browser }) => {
  test.setTimeout(120_000);
  const { server, context, page, connections } = await wrappedSession(browser, 393);
  try {
    const live = connections.at(-1)!;
    // A new session is spawned at a placeholder size its opener never saw: opening it needs no repaint either.
    expect(live.snapshots).toBe(0);
    const before = live.snapshots;
    const count = connections.length;
    await page.setViewportSize({ width: 1440, height: 852 });
    await expect.poll(() => sizes(live).length).toBeGreaterThan(1);
    // sleep: a repaint, if the shim wrongly sent one, arrives within a round trip of the Resize.
    await page.waitForTimeout(1_500);
    await page.screenshot({ path: tracerEvidencePath("j751-live-resize-393-to-1440.png") });
    console.log("J751_LIVE_RESIZE_RECEIPT", JSON.stringify({ order: live.order }));
    expect(connections.length).toBe(count);
    expect(live.snapshots).toBe(before);
  } finally { await context.close(); await server.dispose(); }
});
