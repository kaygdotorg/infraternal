/** Pending removal keeps its ownership-checked uninstall command available to people. */
import { expect, test, type Page } from "playwright/test";
import { decodeMuxedFrame, encodeMuxedFrame } from "../../../packages/protocol/src/codec";
import { tracerEvidencePath } from "./evidence-path";

/**
 * Remove the offline fixture host through the real palette, with the server answering `pending` and the given
 * `host_cleanup`. Returns the manual command the answer carries.
 */
async function removeOffline(page: Page, hostCleanup: "unreachable" | "pending"): Promise<string> {
  await page.request.post("/__mock/reset");
  const id = "11111111-2222-3333-4444-555555555555";
  const manual = `/usr/local/bin/infraternal --bootstrap-uninstall ${id.replaceAll("-", "")}`;
  let pending = false;
  let push: (() => void) | undefined;
  await page.route("**/remote/hosts/actions", route => route.fulfill({ json: { id: "remote.host.remove", label: "Remove host" } }));
  await page.route("**/remote/hosts/remove/start", route => route.fulfill({ json: { review: "fixture-review", action: { host_id: id, host: "offline-worker", uninstall: true } } }));
  await page.route("**/remote/hosts/remove/finish", route => { pending = true; push?.(); return route.fulfill({ json: { state: "pending", host_id: id, host_cleanup: hostCleanup, message: "offline-worker: revoked, cleanup pending.", manual } }); });
  await page.routeWebSocket(/\/v1\/ws(?:\?|$)/, socket => {
    const server = socket.connectToServer();
    socket.onMessage(message => {
      if (typeof message !== "string") {
        const { frame } = decodeMuxedFrame(message);
        if (frame.type === "Subscribe" && JSON.parse(new TextDecoder().decode(frame.filterJson)).topic === "remote.hosts") {
          push = () => socket.send(Buffer.from(encodeMuxedFrame(0, { type: "Event", subId: frame.subId, eventJson: new TextEncoder().encode('{"type":"changed"}') })));
          return;
        }
        if (frame.type === "Call" && frame.actionId === "remote.host.list") {
          socket.send(Buffer.from(encodeMuxedFrame(0, { type: "Result", callId: frame.callId, ok: true, json: new TextEncoder().encode(JSON.stringify({ hosts: [{ id, name: "offline-worker", online: false, ...(pending ? { state: "pending" } : {}) }], next: null })) })));
          return;
        }
      }
      server.send(message);
    });
    server.onMessage(message => socket.send(message));
  });
  const metadata = page.waitForResponse(response => response.url().endsWith("/remote/hosts/actions"));
  await page.goto("/?mock=1&proto=product&fresh=1&bg=none");
  await (await metadata).finished();
  await expect.poll(() => Boolean(push)).toBe(true);
  await page.keyboard.press("Control+Shift+K");
  await page.locator("#palette-input").fill("Remove host: offline-worker");
  await page.getByRole("option").filter({ hasText: "Remove host: offline-worker" }).click();
  await page.getByRole("button", { name: "Remove", exact: true }).click();
  return manual;
}

for (const width of [1440, 393]) {
  test.describe(`pending command at ${width}`, () => {
    test.use({ viewport: { width, height: width < 500 ? 852 : 900 }, deviceScaleFactor: width < 500 ? 3 : 2, hasTouch: width < 500, isMobile: width < 500, permissions: ["clipboard-read", "clipboard-write"] });
    /** The real production toast copies the command without withdrawing the pending host. */
    test("pending removal offers Copy command", async ({ page }) => {
      const manual = await removeOffline(page, "unreachable");
      await expect(page.locator(".ui-toast-message").filter({ hasText: "revoked, cleanup pending" })).toBeVisible();
      await page.screenshot({ animations: "disabled", path: tracerEvidencePath("pending-command", `${width}-before-copy.png`) });
      const copy = page.getByRole("button", { name: "Copy command", exact: true });
      await expect(copy).toBeVisible();
      const toast = copy.locator("..").locator("..");
      await expect(toast).toContainText("pending");
      const boxes = await toast.evaluate(element => {
        const button = element.querySelector(".ui-toast-action")!.getBoundingClientRect();
        const close = element.querySelector(".ui-toast-close")!.getBoundingClientRect();
        const parent = element.getBoundingClientRect();
        return { closeRight: close.right, buttonLeft: button.left, buttonRight: button.right, parentLeft: parent.left, parentRight: parent.right };
      });
      expect(boxes.buttonLeft).toBeGreaterThanOrEqual(boxes.parentLeft - 0.5);
      expect(boxes.buttonRight).toBeLessThanOrEqual(boxes.parentRight + 0.5);
      expect(Math.abs(boxes.buttonRight - boxes.closeRight), "toast actions share the trailing edge").toBeLessThanOrEqual(0.5);
      await page.screenshot({ animations: "disabled", path: tracerEvidencePath("pending-command", `${width}.png`) });
      await page.evaluate(() => navigator.clipboard.writeText("fixture-before-copy"));
      await copy.click();
      // The confirmation follows the write promise; read only after that event.
      await expect(page.getByText("Command copied. Run it on offline-worker.")).toBeVisible();
      expect(await page.evaluate(() => navigator.clipboard.readText())).toBe(manual);
      await page.keyboard.press("Control+Shift+K");
      await page.locator("#palette-input").fill("offline-worker");
      await expect(page.getByRole("option").filter({ hasText: "offline-worker" })).toContainText("removal pending");
    });
    /** A pending uninstall is waiting, not done: the toast shows the info mark, never the success tick (#409). */
    test("pending uninstall toast is neutral", async ({ page }) => {
      await removeOffline(page, "pending");
      const toast = page.locator(".ui-toast").filter({ hasText: "uninstalls infraternal as soon as it connects" });
      await expect(toast).toBeVisible();
      await expect(toast).toHaveAttribute("data-icon", "true");
      await expect(toast).not.toHaveAttribute("data-tone", "error");
      await expect(toast.locator(".ui-toast-glyph")).toBeVisible();
      await expect(toast.locator(".ui-toast-glyph svg path")).toHaveAttribute("d", "M12 11v5M12 7.8v.01");
      await expect(toast.locator(".ui-toast-marker")).toBeHidden();
      await expect(toast.getByRole("button", { name: "Copy command", exact: true })).toBeVisible();
      await page.screenshot({ animations: "disabled", path: tracerEvidencePath("pending-command", `${width}-neutral.png`) });
    });
  });
}
