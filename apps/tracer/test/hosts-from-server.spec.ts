/** Exercises the production canvas host data path with fresh storage, remote removal, reconnect and UUID routing. */
import { expect, test } from "playwright/test";
import { decodeMuxedFrame, encodeMuxedFrame } from "../../../packages/protocol/src/codec";

test("admitted hosts from another browser remain discoverable without saved windows", async ({ page }, info) => {
  await page.request.post("/__mock/reset");
  const id = "11111111-2222-3333-4444-555555555555";
  let admitted = true, subscription: number | undefined, reads = 0, subscriptions = 0, emptyReplies = 0;
  let push: (() => void) | undefined;
  let routed: string | undefined;
  let askedAfterPaint: boolean | undefined;
  await page.addInitScript(() => {
    Reflect.set(window, "__hostPainted", false);
    for (const name of ["fillRect", "fillText", "drawImage"] as const) {
      const draw = CanvasRenderingContext2D.prototype[name];
      Reflect.set(CanvasRenderingContext2D.prototype, name, function(this: CanvasRenderingContext2D, ...args: unknown[]) {
        const result = Reflect.apply(draw, this, args);
        if (this.canvas.isConnected && this.canvas.closest("#terminal-host")) Reflect.set(window, "__hostPainted", true);
        return result;
      });
    }
  });
  await page.routeWebSocket(/\/v1\/ws(?:\?|$)/, (socket) => {
    const server = socket.connectToServer();
    push = () => { if (subscription !== undefined) socket.send(Buffer.from(encodeMuxedFrame(0, { type: "Event", subId: subscription, eventJson: new TextEncoder().encode('{"type":"changed"}') }))); };
    socket.onMessage(async (message) => {
      if (typeof message === "string") { server.send(message); return; }
      const { frame } = decodeMuxedFrame(message);
      if (frame.type === "Call" && frame.actionId === "remote.host.list") {
        reads++;
        askedAfterPaint ??= await page.evaluate(() => Reflect.get(window, "__hostPainted") === true);
        socket.send(Buffer.from(encodeMuxedFrame(0, { type: "Result", callId: frame.callId, ok: true, json: new TextEncoder().encode(JSON.stringify({ hosts: admitted ? [{ id, name: "another-device-host", user: "operator", online: false, os: "Debian" }] : [], next: null })) })));
        if (!admitted) emptyReplies++;
        return;
      }
      if (frame.type === "Subscribe" && JSON.parse(new TextDecoder().decode(frame.filterJson)).topic === "remote.hosts") { subscriptions++; subscription = frame.subId; return; }
      if (frame.type === "Call" && frame.actionId === "ssh.session.open") {
        const input = JSON.parse(new TextDecoder().decode(frame.inputJson)) as { host_id?: string };
        if (input.host_id === id) {
          routed = input.host_id;
          // An offline infraternal agent refuses the open; forwarding it would replace the fixture's embedded session.
          socket.send(Buffer.from(encodeMuxedFrame(0, { type: "Result", callId: frame.callId, ok: false, json: new TextEncoder().encode('{"error":"unavailable"}') })));
          return;
        }
      }
      server.send(message);
    });
    server.onMessage((message) => socket.send(message));
  });
  await page.goto("/?mock=1&proto=product&fresh=1&bg=none");
  await expect.poll(() => reads, { timeout: 20000 }).toBeGreaterThan(0);
  const palette = async () => { await page.keyboard.press("Control+Shift+K"); await page.locator("#palette-input").fill("Open shell on another-device-host"); };
  await expect.poll(() => askedAfterPaint).toBe(true);
  await palette();
  const row = page.locator("#palette-results [role=option]").filter({ hasText: "Open shell on another-device-host" });
  await expect(row).toHaveCount(1); await expect(row).toContainText("offline");
  await page.screenshot({ path: info.outputPath("admitted-offline-host.png"), animations: "disabled" });
  await info.attach("admitted-offline-host", { path: info.outputPath("admitted-offline-host.png"), contentType: "image/png" });
  await row.click();
  await expect.poll(() => routed).toBe(id);
  await page.request.post("/__mock/drop-sockets");
  await expect.poll(() => subscriptions).toBe(2);
  await palette(); await expect(row).toHaveCount(1);
  admitted = false; push?.();
  await expect.poll(() => emptyReplies).toBeGreaterThan(0);
  await expect(row).toHaveCount(0);
});
