/** Independent #257 checks retain geometry and cursor evidence from the real browser/server/PTY path. */
import { expect, test, type Page } from "playwright/test";
import { WebSocketFrameDecoder } from "../../../packages/protocol/src/codec";
import { enrol } from "./layout-devices";
import { watchLayout } from "./layout-observer";
import { startRealServer } from "./server";
import { everShown, FLOATING_NOTE, NOTE, recordNote } from "../test/stale-note-recorder";
import { tracerEvidencePath } from "../test/evidence-path";

/** Keep only public geometry and cursor boundaries; sign-in and terminal contents never enter the receipt. */
function observe(page: Page) {
  const connections: Array<{ sizes: Array<{ cols: number; rows: number }>; fences: Array<{ out_seq: string; cols?: number; rows?: number }>; suffixes: number; snapshots: number; order: string[] }> = [];
  page.on("websocket", (socket) => {
    if (!socket.url().endsWith("/v1/ws")) return;
    const connection = { sizes: [] as Array<{ cols: number; rows: number }>, fences: [] as Array<{ out_seq: string; cols?: number; rows?: number }>, suffixes: 0, snapshots: 0, order: [] as string[] };
    connections.push(connection);
    const up = new WebSocketFrameDecoder(), down = new WebSocketFrameDecoder();
    socket.on("framesent", ({ payload }) => {
      if (typeof payload === "string") return;
      up.feed(new Uint8Array(payload), (_stream, frame) => {
        if (frame.type === "Resize") {
          connection.sizes.push({ cols: frame.cols, rows: frame.rows });
          connection.order.push(`resize:${frame.cols}x${frame.rows}`);
        }
      });
    });
    socket.on("framereceived", ({ payload }) => {
      if (typeof payload === "string") return;
      down.feed(new Uint8Array(payload), (_stream, frame) => {
        if (frame.type === "Event") {
          const notice = JSON.parse(new TextDecoder().decode(frame.eventJson));
          if (notice.type === "terminal.replay_complete") {
            connection.fences.push({ out_seq: notice.out_seq, cols: notice.cols, rows: notice.rows });
            connection.order.push(`fence:${notice.cols}x${notice.rows}@${notice.out_seq}`);
          }
        }
        if (frame.type === "Snapshot") { connection.snapshots++; connection.order.push(`snapshot:${frame.outSeq}`); }
        if (frame.type === "Output" && connection.fences.length > 0) { connection.suffixes += frame.bytes.length; connection.order.push(`live:${frame.bytes.length}`); }
      });
    });
  });
  return connections;
}

for (const surface of ["canvas", "network", "probe", "restart"] as const) for (const workload of ["idle", "silent"] as const) test(`review: unchanged-size restore of a real ${workload} shell on ${surface} has no stale note`, async ({ browser }) => {
  test.setTimeout(90_000);
  const server = await startRealServer({ port: Number(process.env.TRACER_TEST_PORT ?? 4857), ...(surface === "network" ? { upgradeDelayMs: 500 } : {}) });
  const context = await browser.newContext({ viewport: { width: 1440, height: 900 }, ignoreHTTPSErrors: true });
  try {
    const page = watchLayout(await context.newPage());
    const connections = observe(page);
    await enrol(page, server);
    const mockResize = await context.request.post(`${server.origin}/__mock/resize-session`, { data: { cols: 50, rows: 12 } });
    expect([404, 405]).toContain(mockResize.status());
    expect(mockResize.headers()["x-infraternal-test-double"]).toBeUndefined();
    if (surface === "probe") {
      await expect.poll(() => server.bridges.flatMap((bridge) => [...bridge.attached.values()].flat()).length).toBeGreaterThan(0);
      const hex = server.bridges.flatMap((bridge) => [...bridge.attached.values()].flat()).at(-1)!;
      expect(hex).toMatch(/^[0-9a-f]{32}$/);
      const id = `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
      await page.goto(`${server.origin}/?probe=1&n=1&session=${id}&theme=ink&bg=none`);
    }
    const host = page.locator(surface !== "probe" ? '.cl[data-view="console"] .terminal-host' : '.terminal-host');
    await expect(host.locator("textarea")).toHaveCount(1);
    await host.click();
    await host.locator("textarea").focus();
    await page.keyboard.type(workload === "idle" ? "printf 'review-ready\\n'" : "sleep 120");
    await page.keyboard.press("Enter");
    await expect.poll(() => server.bridges.flatMap((bridge) => [...bridge.output.values()]).join("")).toContain(workload === "idle" ? "review-ready" : "sleep 120");
    // Let the initial fit, shell command and prompt finish before testing reload silence.
    await page.waitForTimeout(2_000);
    const previous = connections.at(-1)!;
    const size = previous.sizes.at(-1)!;
    expect(size).toBeDefined();
    await recordNote(page);
    const before = connections.length;
    if (surface === "restart") await server.restart();
    else await page.reload();
    await expect(host.locator("textarea")).toHaveCount(1);
    await expect.poll(() => connections.length).toBeGreaterThan(before);
    await expect.poll(() => connections.at(-1)?.fences.length ?? 0).toBeGreaterThan(0);
    // This is a functional silence observation, not a latency measurement. The upper bound is 1500 ms.
    await page.waitForTimeout(3_000);
    const current = connections.at(-1)!;
    console.log("RELOAD_RECEIPT", JSON.stringify({ surface, workload, previousSize: size, ...current, noteMoments: await everShown(page) }));
    expect(current.sizes.at(-1)).toEqual(size);
    if (current.fences[0]?.cols !== undefined) expect({ cols: current.fences[0].cols, rows: current.fences[0].rows }).toEqual(size);
    await page.screenshot({ path: tracerEvidencePath(`review-real-${surface}-${workload}-reload.png`) });
    expect(await everShown(page)).toBe(0);
    await expect(page.locator(NOTE)).toHaveCount(0);
    expect(new Set(server.bridges.flatMap((bridge) => [...bridge.attached.values()].flat())).size).toBe(1);
  } finally { await context.close(); await server.dispose(); }
});

for (const upgradeDelayMs of [0, 500]) test(`review: a resized silent real canvas restore shows the stale note${upgradeDelayMs ? " after delayed upgrade" : ""}`, async ({ browser }) => {
  test.setTimeout(90_000);
  const server = await startRealServer({ port: Number(process.env.TRACER_TEST_PORT ?? 4857), upgradeDelayMs });
  const context = await browser.newContext({ viewport: { width: 1440, height: 900 }, ignoreHTTPSErrors: true });
  try {
    const page = watchLayout(await context.newPage());
    const connections = observe(page);
    await enrol(page, server);
    const host = page.locator('.cl[data-view="console"] .terminal-host');
    await expect(host.locator("textarea")).toHaveCount(1);
    await host.click();
    await host.locator("textarea").focus();
    await page.keyboard.type("sleep 120");
    await page.keyboard.press("Enter");
    await expect.poll(() => server.bridges.flatMap((bridge) => [...bridge.output.values()]).join("")).toContain("sleep 120");
    await page.waitForTimeout(2_000);
    const url = page.url();
    const before = connections.length;
    // Change this viewer's geometry only after leaving: the old renderer cannot send the new size.
    await page.goto("about:blank");
    await page.setViewportSize({ width: 1100, height: 700 });
    await page.goto(url);
    await expect(host.locator("textarea")).toHaveCount(1);
    await expect.poll(() => connections.length).toBeGreaterThan(before);
    await expect.poll(() => connections.at(-1)?.fences.length ?? 0).toBeGreaterThan(0);
    await page.waitForTimeout(3_000);
    const current = connections.at(-1)!;
    console.log("RESIZED_RESTORE_RECEIPT", JSON.stringify({ upgradeDelayMs, ...current }));
    expect(current.sizes.at(-1)).not.toEqual({ cols: current.fences.at(-1)?.cols, rows: current.fences.at(-1)?.rows });
    expect(current.suffixes).toBe(0);
    await page.screenshot({ path: tracerEvidencePath(`review-real-canvas-resized-restore${upgradeDelayMs ? "-delayed" : ""}.png`) });
    await expect(page.locator(NOTE)).toHaveCount(1);
    await expect(page.locator(FLOATING_NOTE)).toHaveCount(0);
    await host.locator("textarea").focus();
    await page.keyboard.press("Control+C");
    await expect(page.locator(NOTE)).toHaveCount(0);
  } finally { await context.close(); await server.dispose(); }
});
