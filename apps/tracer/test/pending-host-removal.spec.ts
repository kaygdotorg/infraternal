/** Production-build proof that denied hosts retain status without offering shell access. */
import { expect, test } from "playwright/test";
import { decodeMuxedFrame, encodeMuxedFrame } from "../../../packages/protocol/src/codec";
import { tracerEvidencePath } from "./evidence-path";

for (const viewport of [{ width: 1440, height: 900 }, { width: 393, height: 852 }, { width: 375, height: 667 }]) {
  for (const theme of ["ink", "paper"]) {
    /** Pending, unreachable and delivered states reuse the existing palette row layout. */
    test(`pending host ${viewport.width} ${theme}`, async ({ browser }) => {
      const context = await browser.newContext({ viewport, hasTouch: viewport.width < 500, isMobile: viewport.width < 500, deviceScaleFactor: viewport.width < 500 ? 3 : 2 });
      const page = await context.newPage();
      try {
        await page.request.post("/__mock/reset");
        const id = "11111111-2222-3333-4444-555555555555";
        let state = "pending";
        let push: (() => void) | undefined;
        await page.routeWebSocket(/\/v1\/ws(?:\?|$)/, (socket) => {
          const server = socket.connectToServer();
          socket.onMessage((message) => {
            if (typeof message !== "string") {
              const { frame } = decodeMuxedFrame(message);
              if (frame.type === "Call" && frame.actionId === "remote.host.list") {
                socket.send(Buffer.from(encodeMuxedFrame(0, { type: "Result", callId: frame.callId, ok: true, json: new TextEncoder().encode(JSON.stringify({ hosts: state ? [{ id, name: "pending-worker", online: false, state }] : [], next: null })) })));
                return;
              }
              if (frame.type === "Subscribe" && JSON.parse(new TextDecoder().decode(frame.filterJson)).topic === "remote.hosts") {
                push = () => socket.send(Buffer.from(encodeMuxedFrame(0, { type: "Event", subId: frame.subId, eventJson: new TextEncoder().encode('{"type":"changed"}') })));
                return;
              }
            }
            server.send(message);
          });
          server.onMessage((message) => socket.send(message));
        });
        await page.goto(`/?mock=1&proto=product&fresh=1&bg=none&theme=${theme}`);
        await expect.poll(() => Boolean(push), { timeout: 20000 }).toBe(true);
        await page.keyboard.press("Control+Shift+K");
        await page.locator("#palette-input").fill("pending-worker");
        const row = page.locator("#palette-results [role=option]").filter({ hasText: "pending-worker" });
        await expect(row).toHaveCount(1);
        await expect(row).toContainText("removal pending");
        await expect(row.locator(".result-hint")).toBeVisible();
        await expect(row).toHaveAttribute("data-action", "");
        const label = await row.locator(".result-label").boundingBox();
        const icon = await row.locator(".result-icon").boundingBox();
        expect(label).not.toBeNull(); expect(icon).not.toBeNull();
        expect(Math.abs(label!.y + label!.height / 2 - icon!.y - icon!.height / 2)).toBeLessThanOrEqual(0.5);
        await page.screenshot({ path: tracerEvidencePath("pending-host", `${viewport.width}-${theme}-pending.png`) });
        state = "retired-unreachable"; push?.();
        await expect(row).toContainText("retired-unreachable");
        const expiredLabel = await row.locator(".result-label").boundingBox();
        expect(Math.abs(expiredLabel!.x - label!.x)).toBeLessThanOrEqual(0.5);
        await page.screenshot({ path: tracerEvidencePath("pending-host", `${viewport.width}-${theme}-unreachable.png`) });
        state = ""; push?.();
        await expect(row).toHaveCount(0);
      } finally { await context.close(); }
    });
  }
}
