/** Production-build proof of the owner-only D369 Forget flow and its machine-cleanup warning. */
import { expect, test } from "playwright/test";
import { decodeMuxedFrame, encodeMuxedFrame } from "../../../packages/protocol/src/codec";
import { tracerEvidencePath } from "./evidence-path";

for (const viewport of [{ width: 1440, height: 900 }, { width: 393, height: 852 }, { width: 375, height: 667 }]) {
  for (const theme of ["ink", "paper"]) {
    /** The existing pending row gains Forget only after its cleanup certificate expires. */
    test(`forget retired host ${viewport.width} ${theme}`, async ({ browser }) => {
      const context = await browser.newContext({ viewport, hasTouch: viewport.width < 500, isMobile: viewport.width < 500, deviceScaleFactor: 2 });
      const page = await context.newPage();
      try {
        await page.request.post("/__mock/reset");
        const id = "11111111-2222-3333-4444-555555555555";
        let state = "pending";
        let forgotten = false;
        let push: (() => void) | undefined;
        await page.route("**/remote/hosts/actions", (route) => route.fulfill({ json: { id: "remote.host.remove", label: "Remove host" } }));
        await page.route("**/remote/hosts/forget", async (route) => {
          expect(route.request().postDataJSON()).toEqual({ host_id: id });
          forgotten = true;
          state = "";
          await route.fulfill({ json: { host_id: id, state: "forgotten", message: "Host forgotten. The machine itself was not changed." } });
          push?.();
        });
        await page.routeWebSocket(/\/v1\/ws(?:\?|$)/, (socket) => {
          const server = socket.connectToServer();
          socket.onMessage((message) => {
            if (typeof message !== "string") {
              const { frame } = decodeMuxedFrame(message);
              if (frame.type === "Call" && frame.actionId === "remote.host.list") {
                socket.send(Buffer.from(encodeMuxedFrame(0, { type: "Result", callId: frame.callId, ok: true, json: new TextEncoder().encode(JSON.stringify({ hosts: state ? [{ id, name: "retired-worker", online: false, state }] : [], next: null })) })));
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
        await page.locator("#palette-input").fill("retired-worker");
        const row = page.locator("#palette-results [role=option]").filter({ hasText: "retired-worker" });
        await expect(row).toContainText("removal pending");
        await expect(row).toHaveAttribute("data-action", "");
        state = "retired-unreachable"; push?.();
        await expect(row).toContainText("Forget");
        await page.locator(".palette").evaluate((el) => Promise.all(el.getAnimations({ subtree: true }).map((a) => a.finished.catch(() => undefined))));
        const label = await row.locator(".result-label").boundingBox();
        const icon = await row.locator(".result-icon").boundingBox();
        expect(Math.abs(label!.y + label!.height / 2 - icon!.y - icon!.height / 2)).toBeLessThanOrEqual(0.5);
        await page.screenshot({ path: tracerEvidencePath("forget-host", `${viewport.width}-${theme}-row.png`) });
        await row.click();
        await expect(page.getByText("Forget retired-worker?", { exact: true })).toBeVisible();
        await expect(page.getByText("Remove this host from the list and stop its pending cleanup. Keep the audit record. This does not touch the machine itself or uninstall infraternal from it.", { exact: true })).toBeVisible();
        expect(forgotten).toBe(false);
        const confirmation = page.locator(".ui-confirm-tip");
        await expect(confirmation).toHaveAttribute("data-open", "true");
        await confirmation.evaluate((el) => Promise.all(el.getAnimations({ subtree: true }).map((a) => a.finished.catch(() => undefined))));
        const title = await confirmation.locator(".ui-confirm-tip-message").boundingBox();
        const effect = await confirmation.locator(".ui-confirm-tip-detail").boundingBox();
        expect(Math.abs(title!.x - effect!.x)).toBeLessThanOrEqual(0.5);
        const bounds = await confirmation.boundingBox();
        expect(bounds!.x).toBeGreaterThanOrEqual(0);
        expect(bounds!.x + bounds!.width).toBeLessThanOrEqual(viewport.width);
        expect(bounds!.y).toBeGreaterThanOrEqual(0);
        expect(bounds!.y + bounds!.height).toBeLessThanOrEqual(viewport.height);
        for (const button of await confirmation.getByRole("button").all()) {
          const box = await button.boundingBox();
          expect(box!.x).toBeGreaterThanOrEqual(bounds!.x);
          expect(box!.x + box!.width).toBeLessThanOrEqual(bounds!.x + bounds!.width);
          expect(box!.y).toBeGreaterThanOrEqual(bounds!.y);
          expect(box!.y + box!.height).toBeLessThanOrEqual(bounds!.y + bounds!.height);
        }
        await page.screenshot({ path: tracerEvidencePath("forget-host", `${viewport.width}-${theme}-confirmation.png`) });
        await page.getByRole("button", { name: "Keep", exact: true }).click();
        expect(forgotten).toBe(false);
        await page.keyboard.press("Control+Shift+K");
        await page.locator("#palette-input").fill("retired-worker");
        await row.click();
        await page.getByRole("button", { name: "Forget", exact: true }).click();
        await expect.poll(() => forgotten).toBe(true);
        await page.keyboard.press("Control+Shift+K");
        await page.locator("#palette-input").fill("retired-worker");
        await expect(row).toHaveCount(0);
        // The same inventory row remains status-only when the server withholds owner actions.
        state = "retired-unreachable";
        await page.route("**/remote/hosts/actions", (route) => route.fulfill({ status: 403, body: "" }));
        push = undefined;
        await page.reload();
        await expect.poll(() => Boolean(push), { timeout: 20000 }).toBe(true);
        await page.keyboard.press("Control+Shift+K");
        await page.locator("#palette-input").fill("retired-worker");
        await expect(row).toContainText("retired-unreachable");
        await expect(row).not.toContainText("Forget");
        await expect(row).toHaveAttribute("data-action", "");
      } finally { await context.close(); }
    });
  }
}
