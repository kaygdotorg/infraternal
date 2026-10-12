/** Independent #168 review: an earlier census cannot end a shell created after that census [D13,D178]. */
import { expect, test } from "playwright/test";
import { decodeMuxedFrame, encodeMuxedFrame } from "../../../packages/protocol/src/codec";

test("an open result overtaking an earlier census keeps the new shell usable", async ({ page }, testInfo) => {
  test.setTimeout(60_000);
  const retry = <T>(call: () => Promise<T>): Promise<T> => call().catch(() => call());
  await retry(() => page.request.post("/__mock/reset"));
  await retry(() => page.request.post("/__mock/open-terminal"));
  let subscription: number | undefined;
  let opened: string | undefined;
  let completed = false;
  await page.routeWebSocket(/\/v1\/ws(?:\?|$)/, (socket) => {
    const server = socket.connectToServer();
    server.onMessage((message) => {
      if (typeof message === "string") { socket.send(message); return; }
      const { frame } = decodeMuxedFrame(message);
      if (frame.type === "Event") {
        const event = JSON.parse(new TextDecoder().decode(frame.eventJson)) as { type?: string };
        if (event.type === "terminal.sessions.snapshot") {
          subscription = frame.subId;
          // The daemon puts censuses on its bulk queue, while open Results use
          // the priority control queue. Keep that permitted ordering explicit.
          return;
        }
      }
      socket.send(message);
      if (frame.type === "Result" && frame.ok) {
        const result = JSON.parse(new TextDecoder().decode(frame.json)) as { session_id?: string };
        if (!result.session_id || opened) return;
        opened = result.session_id;
        setTimeout(() => {
          if (subscription === undefined) return;
          const send = (ids: string[]): void => socket.send(Buffer.from(encodeMuxedFrame(0, {
            type: "Event", subId: subscription!, eventJson: new TextEncoder().encode(JSON.stringify({
              topic: "terminal.sessions", type: "terminal.sessions.snapshot", session_ids: ids,
            })),
          })));
          send([]);
          setTimeout(() => { send([opened!]); completed = true; }, 400);
        }, 200);
      }
    });
  });
  await page.goto("/?theme=ink&bg=none");
  await expect.poll(() => completed, { timeout: 30_000 }).toBe(true);
  await page.waitForTimeout(1_000);
  const screenshot = testInfo.outputPath("census-ordering.png");
  await page.screenshot({ path: screenshot, animations: "disabled" });
  await testInfo.attach("census-ordering", { path: screenshot, contentType: "image/png" });
  const win = page.locator(".ui-window").first();
  await expect(win.locator(".cl-sx-strip")).toHaveCount(0);
  await expect(win).toHaveAttribute("data-status", "live");
  await expect(page.locator(".capsule-session")).toHaveText("· 1 session");
});
