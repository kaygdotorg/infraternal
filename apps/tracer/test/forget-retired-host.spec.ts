/** Production-build proof of the owner-only D369 Forget flow and its machine-cleanup warning. */
import { expect, test } from "playwright/test";
import { decodeMuxedFrame, encodeMuxedFrame } from "../../../packages/protocol/src/codec";
import { tracerEvidencePath } from "./evidence-path";

for (const viewport of [{ width: 1440, height: 900 }, { width: 393, height: 852 }, { width: 375, height: 667 }]) {
  for (const theme of ["ink", "paper"]) {
    /** The owner can forget immediately, including while cleanup can still be delivered. */
    test(`forget pending host ${viewport.width} ${theme}`, async ({ browser }) => {
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
        await expect(row).toContainText("Forget");
        await expect(row.locator(".result-icon")).toHaveText("×");
        await expect(row.locator(".result-hint")).toHaveText("removal pending · access revoked");
        await page.locator(".palette").evaluate((el) => Promise.all(el.getAnimations({ subtree: true }).map((a) => a.finished.catch(() => undefined))));
        const hintFits = await row.locator(".result-hint").evaluate((el) => el.scrollWidth <= el.clientWidth);
        expect(hintFits, "the pending hint must fit without truncation on phones").toBe(true);
        const centreOffset = await row.evaluate((element) => {
          const label = element.querySelector(".result-label")!.getBoundingClientRect();
          const icon = element.querySelector(".result-icon")!.getBoundingClientRect();
          return Math.abs(label.y + label.height / 2 - icon.y - icon.height / 2);
        });
        expect(centreOffset).toBeLessThanOrEqual(0.5);
        await page.screenshot({ path: tracerEvidencePath("forget-host", `${viewport.width}-${theme}-row.png`) });
        await row.click();
        await expect(page.getByText("Forget retired-worker?", { exact: true })).toBeVisible();
        const guidance = page.locator(".ui-confirm-tip-detail");
        for (const words of ["stops automatic cleanup", "stop and remove its service unit", "agent files", "identity key"]) {
          await expect(guidance).toContainText(words);
        }
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
        state = "pending";
        await page.route("**/remote/hosts/actions", (route) => route.fulfill({ status: 403, body: "" }));
        push = undefined;
        await page.reload();
        await expect.poll(() => Boolean(push), { timeout: 20000 }).toBe(true);
        await page.keyboard.press("Control+Shift+K");
        await page.locator("#palette-input").fill("retired-worker");
        await expect(row).toContainText("removal pending");
        await expect(row).toHaveAttribute("data-action", "");
        state = "retired-unreachable"; push?.();
        await expect(row).toContainText("retired-unreachable");
        await expect(row).toHaveAttribute("data-action", "");
      } finally { await context.close(); }
    });
  }
}

/** A closed admin window answers Forget with 428, and the page offers the passkey tap instead of a dead end (#563). */
test("forget on a closed admin window offers the passkey renewal", async ({ page }) => {
  await page.request.post("/__mock/reset");
  const id = "11111111-2222-3333-4444-555555555555";
  let forgets = 0;
  let push: (() => void) | undefined;
  await page.route("**/remote/hosts/actions", (route) => route.fulfill({ json: { id: "remote.host.remove", label: "Remove host" } }));
  await page.route("**/remote/hosts/reauth/start", (route) => route.fulfill({ json: { ceremony: "fixture-ceremony", options: { publicKey: { challenge: "AQID", rpId: "localhost", allowCredentials: [] } } } }));
  await page.route("**/remote/hosts/forget", (route) => { forgets += 1; return route.fulfill({ status: 428 }); });
  await page.routeWebSocket(/\/v1\/ws(?:\?|$)/, (socket) => {
    const server = socket.connectToServer();
    socket.onMessage((message) => {
      if (typeof message !== "string") {
        const { frame } = decodeMuxedFrame(message);
        if (frame.type === "Call" && frame.actionId === "remote.host.list") {
          socket.send(Buffer.from(encodeMuxedFrame(0, { type: "Result", callId: frame.callId, ok: true, json: new TextEncoder().encode(JSON.stringify({ hosts: [{ id, name: "retired-worker", online: false, state: "retired-unreachable" }], next: null })) })));
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
  await page.goto("/?mock=1&proto=product&fresh=1&bg=none");
  await expect.poll(() => Boolean(push), { timeout: 20000 }).toBe(true);
  await page.keyboard.press("Control+Shift+K");
  await page.locator("#palette-input").fill("retired-worker");
  await page.locator("#palette-results [role=option]").filter({ hasText: "retired-worker" }).click();
  await page.getByRole("button", { name: "Forget", exact: true }).click();
  await expect(page.getByRole("button", { name: "Confirm with passkey", exact: true })).toBeVisible();
  expect(forgets).toBe(1);
  await page.getByRole("button", { name: "Keep host", exact: true }).click();
  await expect(page.locator(".ui-toast").filter({ hasText: "Passkey confirmation was cancelled" })).toBeVisible();
  expect(forgets, "a cancelled renewal never retries the forget").toBe(1);
});
