/** Independent #199 review: a stopped upstream must not leave an open browser route silently accepting input. */
import { expect, test } from "playwright/test";

for (const direction of ["both", "up", "down"] as const) test(`typing recovers when the old browser route stays open and ${direction} stops`, async ({ page }, testInfo) => {
  test.setTimeout(60_000);
  const retry = <T>(call: () => Promise<T>): Promise<T> => call().catch(() => call());
  const request = page.context().request;
  await retry(() => request.post("/__mock/reset"));
  await retry(() => request.post("/__mock/open-terminal"));
  let stopped = false;
  let routes = 0;
  let supersededRoutes = 0;
  let stoppedRoutes = 0;
  await page.routeWebSocket(/\/v1\/ws(?:\?|$)/, (socket) => {
    const id = ++routes;
    const superseded = () => stopped && id <= supersededRoutes;
    const upstream = socket.connectToServer();
    // An intermediary can retain its browser socket when the old backend ends.
    // New routes remain healthy; only this superseded route stops forwarding.
    socket.onMessage((message) => { if (!superseded() || direction === "down") upstream.send(message); else if (direction !== "both") stoppedRoutes++; });
    upstream.onMessage((message) => { if (!superseded() || direction === "up") socket.send(message); else if (direction !== "both") stoppedRoutes++; });
    upstream.onClose(() => {
      if (superseded()) { stoppedRoutes++; return; }
      socket.close();
    });
  });
  await page.goto("/?theme=ink&bg=none");
  const card = page.locator('.cl[data-view="console"] .ui-window').first();
  await expect(card).toHaveAttribute("data-status", "live", { timeout: 30_000 });
  await card.locator(".terminal-host textarea").focus();
  await page.keyboard.type("before-route-stop");
  const state = async () => await (await retry(() => request.get("/__mock/state"))).json() as { echoed_text: string };
  await expect.poll(async () => (await state()).echoed_text).toContain("before-route-stop");
  stopped = true;
  supersededRoutes = routes;
  if (direction === "both") await retry(() => request.post("/__mock/drop-sockets"));
  await expect.poll(() => stoppedRoutes).toBeGreaterThan(0);
  // This is a functional eventual-recovery oracle, not a latency measurement.
  // The backend is available throughout; no reload or focus change assists it.
  await page.keyboard.type("after-route-stop");
  try {
    await expect.poll(async () => (await state()).echoed_text, { timeout: 10_000 }).toContain("after-route-stop");
    expect((await state()).echoed_text.split("after-route-stop")).toHaveLength(2);
  } finally {
    console.log(`route recovery: routes=${routes} stopped_routes=${stoppedRoutes} window_status=${await card.getAttribute("data-status")} connected=${await page.locator("#terminal-screen").getAttribute("data-connected")}`);
    await page.screenshot({ path: testInfo.outputPath("route-after-stop.png") });
  }
});
