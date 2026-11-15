/**
 * Production-build proof that removals of different hosts run in parallel in the browser (#519). The server admits eight
 * at once; the page used to refuse a second one while any was running. Each case drives the real palette against a
 * routed server whose `remove/finish` answers are held until the test lets them go, so "in flight" is observable.
 */
import { generateKeyPairSync } from "node:crypto";
import { expect, test, type Page } from "playwright/test";
import { decodeMuxedFrame, encodeMuxedFrame } from "../../../packages/protocol/src/codec";
import { tracerEvidencePath } from "./evidence-path";

const HOSTS = [
  { id: "11111111-2222-3333-4444-555555555555", name: "worker-one" },
  { id: "22222222-3333-4444-5555-666666666666", name: "worker-two" },
] as const;

/** What a case can watch and steer on the routed server. */
interface Fixture {
  /** Paths seen, in order, as `path:host_id` for the removal steps. */
  calls: string[];
  /** Lets every held `remove/finish` answer go. */
  release(): void;
  /** Makes the next `remove/start` answers 428 until a renewal finishes. */
  expire(): void;
}

/** Routes the removal endpoints and a two-host list, then opens the product. */
async function open(page: Page, options: { held?: boolean } = {}): Promise<Fixture> {
  await page.request.post("/__mock/reset");
  const calls: string[] = [];
  let open = true;
  let renewed = false;
  let release!: () => void;
  const gate = new Promise<void>((resolve) => { release = resolve; });
  const gone = new Set<string>();
  let push: (() => void) | undefined;
  await page.route("**/remote/hosts/actions", (route) => route.fulfill({ json: { id: "remote.host.remove", label: "Remove host" } }));
  let starts = 0;
  let bothStarted!: () => void;
  const both = new Promise<void>((resolve) => { bothStarted = resolve; });
  await page.route("**/remote/hosts/remove/start", async (route) => {
    const id = (route.request().postDataJSON() as { host_id: string }).host_id;
    calls.push(`start:${id}`);
    if (!open && !renewed) {
      // Answer both refusals together, as two removals racing one closed window would see them.
      if (++starts === 2) bothStarted();
      await both;
      return route.fulfill({ status: 428 });
    }
    const host = HOSTS.find((h) => h.id === id)!;
    return route.fulfill({ json: { review: `review-${id}`, action: { host_id: id, host: host.name, uninstall: true } } });
  });
  await page.route("**/remote/hosts/reauth/start", (route) => { calls.push("reauth:start"); return route.fulfill({ json: { ceremony: "fixture-ceremony", options: { publicKey: { challenge: "AQID", rpId: "localhost", allowCredentials: [] } } } }); });
  await page.route("**/remote/hosts/reauth/finish", (route) => { calls.push("reauth:finish"); renewed = true; return route.fulfill({ json: { ok: true } }); });
  await page.route("**/remote/hosts/remove/finish", async (route) => {
    const id = (route.request().postDataJSON() as { host_id: string }).host_id;
    calls.push(`finish:${id}`);
    if (!open && !renewed) return route.fulfill({ status: 428 });
    if (options.held) await gate;
    gone.add(id);
    push?.();
    return route.fulfill({ json: { state: "removed", host_id: id, host_cleanup: "done", message: `${HOSTS.find((h) => h.id === id)!.name} was removed.` } });
  });
  await page.routeWebSocket(/\/v1\/ws(?:\?|$)/, (socket) => {
    const server = socket.connectToServer();
    socket.onMessage((message) => {
      if (typeof message !== "string") {
        const { frame } = decodeMuxedFrame(message);
        if (frame.type === "Subscribe" && JSON.parse(new TextDecoder().decode(frame.filterJson)).topic === "remote.hosts") {
          push = () => socket.send(Buffer.from(encodeMuxedFrame(0, { type: "Event", subId: frame.subId, eventJson: new TextEncoder().encode('{"type":"changed"}') })));
          return;
        }
        if (frame.type === "Call" && frame.actionId === "remote.host.list") {
          const hosts = HOSTS.filter((h) => !gone.has(h.id)).map((h) => ({ id: h.id, name: h.name, online: false }));
          socket.send(Buffer.from(encodeMuxedFrame(0, { type: "Result", callId: frame.callId, ok: true, json: new TextEncoder().encode(JSON.stringify({ hosts, next: null })) })));
          return;
        }
      }
      server.send(message);
    });
    server.onMessage((message) => socket.send(message));
  });
  const metadata = page.waitForResponse((response) => response.url().endsWith("/remote/hosts/actions"));
  await page.goto("/?mock=1&proto=product&fresh=1&bg=none");
  await (await metadata).finished();
  await expect.poll(() => Boolean(push)).toBe(true);
  return { calls, release, expire: () => { open = false; } };
}

/** Starts "Remove host: <name>" from the palette and confirms the first card. */
async function remove(page: Page, name: string): Promise<void> {
  await page.keyboard.press("Control+Shift+K");
  await page.locator("#palette-input").fill(`Remove host: ${name}`);
  await page.getByRole("option").filter({ hasText: `Remove host: ${name}` }).click();
  await page.getByRole("button", { name: "Remove", exact: true }).click();
}

for (const width of [1440, 393]) {
  test.describe(`parallel removal at ${width}`, () => {
    test.use({ viewport: { width, height: width < 500 ? 852 : 900 }, deviceScaleFactor: width < 500 ? 3 : 2, hasTouch: width < 500, isMobile: width < 500 });

    /** The owner's report: a second host's removal must start while the first is still waiting on its answer. */
    test("two hosts are removed at the same time and each says so once", async ({ page }) => {
      const fixture = await open(page, { held: true });
      await remove(page, HOSTS[0].name);
      await expect.poll(() => fixture.calls).toContain(`finish:${HOSTS[0].id}`);
      await remove(page, HOSTS[1].name);
      await expect.poll(() => fixture.calls).toContain(`finish:${HOSTS[1].id}`);
      await expect(page.locator(".ui-toast").filter({ hasText: "still running" })).toHaveCount(0);
      fixture.release();
      for (const host of HOSTS) await expect(page.locator(".ui-toast").filter({ hasText: `${host.name} was removed.` })).toHaveCount(1);
      await page.screenshot({ animations: "disabled", path: tracerEvidencePath("parallel-removal", `${width}-two-done.png`) });
    });

    /** The same host is never reviewed twice while its removal is running, and the person is told why. */
    test("the same host cannot be removed twice at once", async ({ page }) => {
      const fixture = await open(page, { held: true });
      await remove(page, HOSTS[0].name);
      await expect.poll(() => fixture.calls).toContain(`finish:${HOSTS[0].id}`);
      await remove(page, HOSTS[0].name);
      await expect(page.locator(".ui-toast").filter({ hasText: `${HOSTS[0].name} is already being removed.` })).toBeVisible();
      expect(fixture.calls.filter((call) => call === `start:${HOSTS[0].id}`)).toHaveLength(1);
      fixture.release();
    });

    /** One closed admin window, two removals, one passkey prompt; both finish after it. */
    test("two removals that find the window closed share one passkey prompt", async ({ page }) => {
      const cdp = await page.context().newCDPSession(page);
      await cdp.send("WebAuthn.enable");
      const { authenticatorId } = await cdp.send("WebAuthn.addVirtualAuthenticator", { options: { protocol: "ctap2", transport: "internal", hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true } });
      const { privateKey } = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
      await cdp.send("WebAuthn.addCredential", { authenticatorId, credential: { credentialId: Buffer.from("j746-platform-credential").toString("base64"), isResidentCredential: true, rpId: "localhost", privateKey: privateKey.export({ type: "pkcs8", format: "der" }).toString("base64"), userHandle: "AQID", signCount: 0 } });
      const fixture = await open(page);
      fixture.expire();
      await remove(page, HOSTS[0].name);
      await remove(page, HOSTS[1].name);
      await expect.poll(() => fixture.calls.filter((call) => call.startsWith("start:"))).toHaveLength(2);
      await expect(page.getByRole("button", { name: "Confirm with passkey", exact: true })).toBeVisible();
      // Give a wrongly separate second prompt time to appear before counting.
      await expect.poll(() => fixture.calls.filter((call) => call === "reauth:start").length).toBeGreaterThan(0);
      await page.screenshot({ animations: "disabled", path: tracerEvidencePath("parallel-removal", `${width}-one-prompt.png`) });
      await expect(page.getByRole("button", { name: "Confirm with passkey", exact: true })).toHaveCount(1);
      await page.getByRole("button", { name: "Confirm with passkey", exact: true }).click();
      for (const host of HOSTS) await expect(page.locator(".ui-toast").filter({ hasText: `${host.name} was removed.` })).toHaveCount(1);
      expect(fixture.calls.filter((call) => call === "reauth:start")).toHaveLength(1);
      await cdp.detach();
    });
  });
}
