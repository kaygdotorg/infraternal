/** Exercises the production canvas host data path with fresh storage, remote removal, reconnect and UUID routing. */
import { expect, test } from "playwright/test";
import { decodeMuxedFrame, encodeMuxedFrame } from "../../../packages/protocol/src/codec";

test("admitted hosts from another browser remain discoverable without saved windows", async ({ page }, info) => {
  await page.request.post("/__mock/reset");
  const id = "11111111-2222-3333-4444-555555555555";
  let admitted = true, subscription: number | undefined, reads = 0;
  let push: (() => void) | undefined;
  let routed: string | undefined;
  await page.routeWebSocket(/\/v1\/ws(?:\?|$)/, (socket) => {
    const server = socket.connectToServer();
    push = () => { if (subscription !== undefined) socket.send(Buffer.from(encodeMuxedFrame(0, { type: "Event", subId: subscription, eventJson: new TextEncoder().encode('{"type":"changed"}') }))); };
    socket.onMessage((message) => {
      if (typeof message === "string") { server.send(message); return; }
      const { frame } = decodeMuxedFrame(message);
      if (frame.type === "Call" && frame.actionId === "remote.host.list") {
        reads++;
        socket.send(Buffer.from(encodeMuxedFrame(0, { type: "Result", callId: frame.callId, ok: true, json: new TextEncoder().encode(JSON.stringify({ hosts: admitted ? [{ id, name: "another-device-host", user: "operator", online: false, os: "Debian" }] : [], next: null })) })));
        return;
      }
      if (frame.type === "Subscribe" && JSON.parse(new TextDecoder().decode(frame.filterJson)).topic === "remote.hosts") { subscription = frame.subId; return; }
      if (frame.type === "Call" && frame.actionId === "ssh.session.open") {
        const input = JSON.parse(new TextDecoder().decode(frame.inputJson)) as { host_id?: string };
        if (input.host_id) routed = input.host_id;
      }
      server.send(message);
    });
    server.onMessage((message) => socket.send(message));
  });
  await page.goto("/?mock=1&proto=product&fresh=1&bg=none");
  await expect.poll(() => reads, { timeout: 20000 }).toBeGreaterThan(0);
  const palette = async () => { await page.keyboard.press("Control+Shift+K"); await page.locator("#palette-input").fill("Open shell on another-device-host"); };
  await palette();
  const row = page.locator("#palette-results [role=option]").filter({ hasText: "Open shell on another-device-host" });
  await expect(row).toHaveCount(1); await expect(row).toContainText("offline");
  await page.screenshot({ path: info.outputPath("admitted-offline-host.png"), animations: "disabled" });
  await info.attach("admitted-offline-host", { path: info.outputPath("admitted-offline-host.png"), contentType: "image/png" });
  await row.click();
  await expect.poll(() => routed).toBe(id);
  await page.request.post("/__mock/drop-sockets");
  await expect.poll(() => reads).toBeGreaterThan(1);
  await palette(); await expect(row).toHaveCount(1);
  admitted = false; push?.();
  await expect.poll(() => reads).toBeGreaterThan(2);
  await expect(row).toHaveCount(0);
});
