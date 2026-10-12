/** Independently checks remote-host invalidation after reconnect using completed replies, not cumulative read counts (#194). */
import { expect, test } from "playwright/test";
import { decodeMuxedFrame, encodeMuxedFrame } from "../../../packages/protocol/src/codec";

test("an open palette removes withdrawn admission after opening its shell and reconnecting", async ({ page }) => {
  await page.request.post("/__mock/reset");
  const id = "11111111-2222-3333-4444-555555555555";
  let admitted = true, emptyReplies = 0, subscriptions = 0, routed = false;
  let push: (() => void) | undefined;
  await page.routeWebSocket(/\/v1\/ws(?:\?|$)/, (socket) => {
    const server = socket.connectToServer();
    let subscription: number | undefined;
    socket.onMessage((message) => {
      if (typeof message !== "string") {
        const { frame } = decodeMuxedFrame(message);
        if (frame.type === "Call" && frame.actionId === "remote.host.list") {
          socket.send(Buffer.from(encodeMuxedFrame(0, {
            type: "Result", callId: frame.callId, ok: true,
            json: new TextEncoder().encode(JSON.stringify({ hosts: admitted ? [{ id, name: "review-withdrawn-host", online: false }] : [], next: null })),
          })));
          if (!admitted) emptyReplies++;
          return;
        }
        if (frame.type === "Subscribe" && JSON.parse(new TextDecoder().decode(frame.filterJson)).topic === "remote.hosts") {
          subscriptions++;
          subscription = frame.subId;
          push = () => socket.send(Buffer.from(encodeMuxedFrame(0, {
            type: "Event", subId: subscription!, eventJson: new TextEncoder().encode('{"type":"changed"}'),
          })));
          return;
        }
        if (frame.type === "Call" && frame.actionId === "ssh.session.open") {
          const input = JSON.parse(new TextDecoder().decode(frame.inputJson)) as { host_id?: string };
          if (input.host_id === id) {
            routed = true;
            // This admitted host is offline. Keep the fixture's embedded session intact.
            socket.send(Buffer.from(encodeMuxedFrame(0, {
              type: "Result", callId: frame.callId, ok: false,
              json: new TextEncoder().encode('{"error":"unavailable"}'),
            })));
            return;
          }
        }
      }
      server.send(message);
    });
    server.onMessage((message) => socket.send(message));
  });
  await page.goto("/?mock=1&proto=product&fresh=1&bg=none");
  await expect.poll(() => subscriptions, { timeout: 20000 }).toBe(1);
  await page.keyboard.press("Control+Shift+K");
  await page.locator("#palette-input").fill("Open shell on review-withdrawn-host");
  const row = page.locator("#palette-results [role=option]").filter({ hasText: "Open shell on review-withdrawn-host" });
  await expect(row).toBeVisible();
  await row.click();
  await expect.poll(() => routed).toBe(true);
  await page.request.post("/__mock/drop-sockets");
  await expect.poll(() => subscriptions).toBe(2);
  await page.keyboard.press("Control+Shift+K");
  await page.locator("#palette-input").fill("Open shell on review-withdrawn-host");
  await expect(row).toBeVisible();
  admitted = false;
  push?.();
  await expect.poll(() => emptyReplies).toBeGreaterThan(0);
  await expect(row).toHaveCount(0);
});
