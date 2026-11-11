/** Pending removal keeps its ownership-checked uninstall command available to people. */
import { generateKeyPairSync } from "node:crypto";
import { expect, test, type Page } from "playwright/test";
import { decodeMuxedFrame, encodeMuxedFrame } from "../../../packages/protocol/src/codec";
import { tracerEvidencePath } from "./evidence-path";

/**
 * Remove the offline fixture host through the real palette, with the server answering `pending` and the given
 * `host_cleanup`. Returns the manual command the answer carries.
 */
async function removeOffline(page: Page, hostCleanup: "unreachable" | "pending", expired: boolean | "finish" = false): Promise<string> {
  await page.request.post("/__mock/reset");
  const id = "11111111-2222-3333-4444-555555555555";
  const manual = `/usr/local/bin/infraternal --bootstrap-uninstall ${id.replaceAll("-", "")}`;
  let pending = false;
  let renewed = !expired;
  let push: (() => void) | undefined;
  await page.route("**/remote/hosts/actions", route => route.fulfill({ json: { id: "remote.host.remove", label: "Remove host" } }));
  await page.route("**/remote/hosts/remove/start", route => (renewed || expired === "finish") ? route.fulfill({ json: { review: "fixture-review", action: { host_id: id, host: "offline-worker", uninstall: true } } }) : route.fulfill({ status: 428 }));
  await page.route("**/remote/hosts/reauth/start", route => route.fulfill({ json: { ceremony: "fixture-ceremony", options: { publicKey: { challenge: "AQID", rpId: "localhost", allowCredentials: [] } } } }));
  await page.route("**/remote/hosts/reauth/finish", route => { renewed = true; return route.fulfill({ json: { ok: true } }); });
  await page.route("**/remote/hosts/remove/finish", route => { if (!renewed) return route.fulfill({ status: 428 }); pending = true; push?.(); return route.fulfill({ json: { state: "pending", host_id: id, host_cleanup: hostCleanup, message: "offline-worker: revoked, cleanup pending.", manual } }); });
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
    /** Expired admin authority requests a fresh user gesture before invoking WebAuthn, including on phones (#498). */
    test("expired window offers a passkey tap without asking to sign in", async ({ page }) => {
      await removeOffline(page, "pending", true);
      await expect(page.getByRole("button", { name: "Confirm with passkey", exact: true })).toBeVisible();
      const prompt = page.locator('.ui-confirm-tip[data-open="true"]');
      await expect(prompt).toContainText("15 minutes");
      const edges = await prompt.evaluate(element => {
        const title = element.querySelector(".ui-confirm-tip-message")!.getBoundingClientRect();
        const effect = element.querySelector(".ui-confirm-tip-detail")!.getBoundingClientRect();
        const yes = element.querySelector(".ui-confirm-yes")!.getBoundingClientRect();
        const no = element.querySelector(".ui-confirm-no")!.getBoundingClientRect();
        return { title: title.left, effect: effect.left, yes: yes.top + yes.height / 2, no: no.top + no.height / 2 };
      });
      expect(Math.abs(edges.title - edges.effect)).toBeLessThanOrEqual(0.5);
      expect(Math.abs(edges.yes - edges.no)).toBeLessThanOrEqual(0.5);
      await expect(page.locator(".ui-toast").filter({ hasText: "Sign in again" })).toHaveCount(0);
      await page.screenshot({ animations: "disabled", path: tracerEvidencePath("removal-passkey", `${width}-prompt.png`) });
    });
    /** Closing the admin window after review still asks for a tap before any removal (#498). */
    test("window expiring between review and removal requests a passkey", async ({ page }) => {
      await removeOffline(page, "pending", "finish");
      await expect(page.getByRole("button", { name: "Confirm with passkey", exact: true })).toBeVisible();
      await page.getByRole("button", { name: "Keep host", exact: true }).click();
      await expect(page.locator(".ui-toast").filter({ hasText: "The host was not removed" })).toBeVisible();
    });
    /** A platform credential request made from the confirmation click continues the same removal (#498). */
    test("passkey tap continues removal with a fresh user gesture", async ({ page }) => {
      const cdp = await page.context().newCDPSession(page);
      await cdp.send("WebAuthn.enable");
      const { authenticatorId } = await cdp.send("WebAuthn.addVirtualAuthenticator", { options: { protocol: "ctap2", transport: "internal", hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true } });
      const { privateKey } = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
      await cdp.send("WebAuthn.addCredential", { authenticatorId, credential: { credentialId: Buffer.from("j507-platform-credential").toString("base64"), isResidentCredential: true, rpId: "localhost", privateKey: privateKey.export({ type: "pkcs8", format: "der" }).toString("base64"), userHandle: "AQID", signCount: 0 } });
      await page.addInitScript(() => {
        const get = navigator.credentials.get.bind(navigator.credentials);
        navigator.credentials.get = options => {
          (window as unknown as { passkeyActivation: boolean }).passkeyActivation = navigator.userActivation.isActive;
          return get(options);
        };
      });
      await removeOffline(page, "pending", true);
      await page.getByRole("button", { name: "Confirm with passkey", exact: true }).click();
      await expect(page.locator(".ui-toast").filter({ hasText: "uninstalls infraternal as soon as it connects" })).toBeVisible();
      expect(await page.evaluate(() => (window as unknown as { passkeyActivation: boolean }).passkeyActivation)).toBe(true);
      await cdp.detach();
    });
    /** Dismissing the tap leaves the host alone and explains the cancellation (#498). */
    test("cancelled renewal keeps the host", async ({ page }) => {
      await removeOffline(page, "pending", true);
      await page.getByRole("button", { name: "Keep host", exact: true }).click();
      await expect(page.locator(".ui-toast").filter({ hasText: "Passkey confirmation was cancelled. The host was not removed." })).toBeVisible();
    });
    /** A cancelled platform prompt sends no proof and never retries the removal (#498). */
    test("cancelled platform prompt leaves removal untouched", async ({ page }) => {
      let renewals = 0;
      let removals = 0;
      page.on("request", request => {
        const path = new URL(request.url()).pathname;
        if (path === "/remote/hosts/reauth/finish") renewals += 1;
        if (path === "/remote/hosts/remove/finish") removals += 1;
      });
      await page.addInitScript(() => {
        navigator.credentials.get = () => Promise.reject(new DOMException("cancelled", "NotAllowedError"));
      });
      await removeOffline(page, "pending", true);
      await page.getByRole("button", { name: "Confirm with passkey", exact: true }).click();
      await expect(page.locator(".ui-toast").filter({ hasText: "Passkey confirmation was cancelled or timed out." })).toBeVisible();
      expect(renewals).toBe(0);
      expect(removals).toBe(0);
    });
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
