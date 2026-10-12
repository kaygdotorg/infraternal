/** Independently verifies #194's admitted-host selection through the New window entry point. */
import { expect, test } from "playwright/test";
import { decodeMuxedFrame, encodeMuxedFrame } from "../../../packages/protocol/src/codec";

test("New window offers an admitted host without a saved window", async ({ page }) => {
  await page.request.post("/__mock/reset");
  const id = "11111111-2222-3333-4444-555555555555";
  let reads = 0;
  await page.routeWebSocket(/\/v1\/ws(?:\?|$)/, (socket) => {
    const server = socket.connectToServer();
    socket.onMessage((message) => {
      if (typeof message !== "string") {
        const { frame } = decodeMuxedFrame(message);
        if (frame.type === "Call" && frame.actionId === "remote.host.list") {
          reads++;
          socket.send(Buffer.from(encodeMuxedFrame(0, {
            type: "Result", callId: frame.callId, ok: true,
            json: new TextEncoder().encode(JSON.stringify({
              hosts: [{ id, name: "review-offline-host", online: false }], next: null,
            })),
          })));
          return;
        }
        if (frame.type === "Subscribe" && JSON.parse(new TextDecoder().decode(frame.filterJson)).topic === "remote.hosts") return;
      }
      server.send(message);
    });
    server.onMessage((message) => socket.send(message));
  });
  await page.goto("/?mock=1&proto=product&fresh=1&bg=none");
  await expect.poll(() => reads, { timeout: 20000 }).toBeGreaterThan(0);
  // Establish that admission completed before exercising the other required entry point.
  await page.keyboard.press("Control+Shift+K");
  const remote = page.getByRole("option").filter({ hasText: "Open shell on review-offline-host" });
  await expect(remote).toHaveCount(1);
  await page.keyboard.press("Escape");
  await page.getByRole("button", { name: "New window", exact: true }).click();
  await expect(remote).toBeVisible();
});
