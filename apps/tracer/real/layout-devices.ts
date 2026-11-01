/**
 * Shared two-device fixture for the layout presentation specs (#243): one real server, one desktop browser and one
 * phone browser signed in as the same account, so a layout drawn on one device is read on the other from the server.
 */
import { cache } from "./layout-observer";
export { cache } from "./layout-observer";
import { watchLayout } from "./layout-observer";
import { devices, expect, type Page, type BrowserContext, type Browser } from "playwright/test";
import { WebSocket } from "ws";
import { encodeMuxedFrame, WebSocketFrameDecoder } from "../../../packages/protocol/src/codec";
import { LAYOUT_SESSION_INCARNATION } from "../src/connection";
import { startRealServer, type RealServer } from "./server";
import type { CanvasDocument } from "../src/canvas/model/schema";

export const windows = (page: Page) => page.locator('.cl[data-view="console"] .ui-window');
export const settled = async (page: Page): Promise<void> => {
  await expect.poll(async () => (await cache(page)).initialized, { timeout: 30_000 }).toBe(true);
  await expect(page.getByText("Not saved — keep this tab open", { exact: true })).toBeHidden();
  await expect.poll(async () => (await cache(page))?.pending.length, { timeout: 15_000 }).toBe(0);
};
export async function enrol(page: Page, server: RealServer): Promise<void> {
  const cdp = await page.context().newCDPSession(page);
  await cdp.send("WebAuthn.enable");
  await cdp.send("WebAuthn.addVirtualAuthenticator", { options: { protocol: "ctap2", ctap2Version: "ctap2_1", transport: "internal", hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true, hasPrf: true } });
  await page.goto(server.origin + "/?theme=ink&bg=none");
  await page.locator("#setup-token").fill(server.token);
  await page.getByRole("button", { name: "Continue", exact: true }).click();
  await page.locator("#setup-username").fill("layout_phone");
  await page.locator("#setup-display-name").fill("Layout phone");
  await page.getByRole("button", { name: "Continue", exact: true }).click();
  await page.getByRole("button", { name: "Create passkey" }).click();
  await page.getByRole("heading", { name: "Save your recovery key" }).waitFor();
  await page.locator(".auth-check").click();
  await page.getByRole("button", { name: "Open infraternal" }).click();
  await expect(windows(page)).toHaveCount(1);
  await settled(page);
}
/** Bind valid test requests to the welcome while preserving intentionally invalid wire input. */
export function layoutRequestJson(input: unknown, incarnation: string | undefined): Buffer {
  let value: unknown = input;
  if (typeof value === "string") { try { value = JSON.parse(value); } catch { return Buffer.from(String(value)); } }
  return Buffer.from(JSON.stringify(value && typeof value === "object" && !Array.isArray(value) ? { ...value, session_incarnation: incarnation } : value));
}
/** Public actions use the same authenticated protocol; cookies and replies stay in memory. */
export async function request(server: RealServer, context: BrowserContext, action: string, input: unknown, snapshot = false): Promise<{ ok: boolean; value: Record<string, unknown> }> {
  const cookie = (await context.cookies()).map((c) => `${c.name}=${c.value}`).join("; ");
  const socket = new WebSocket(server.backend.replace("http:", "ws:") + "/v1/ws", { headers: { Origin: server.origin, Cookie: cookie } });
  const decoder = new WebSocketFrameDecoder();
  const send = (frame: Parameters<typeof encodeMuxedFrame>[1]): void => { socket.send(encodeMuxedFrame(0, frame)); };
  try {
    return await new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(Error("review protocol response absent")), 15_000);
      socket.on("error", () => { clearTimeout(timer); reject(Error("review protocol connection failed")); });
      socket.on("message", (bytes) => decoder.feed(new Uint8Array(Buffer.from(bytes as Buffer)), (_stream, frame) => {
        if (frame.type === "Hello") send({ type: "Hello", version: 1, caps: LAYOUT_SESSION_INCARNATION, clientInfo: "layout-review" });
        if (frame.type === "Ping") send({ ...frame, type: "Pong" });
        if (frame.type === "Welcome") {
          if (snapshot) send({ type: "Subscribe", subId: 1, filterJson: Buffer.from('{"topic":"canvas.layout"}') });
          else send({ type: "Call", callId: 1, actionId: action, inputJson: action.startsWith("canvas.layout.") ? layoutRequestJson(input, frame.sessionIncarnation) : Buffer.from(typeof input === "string" ? input : JSON.stringify(input)) });
        }
        if (frame.type === "Result" || snapshot && frame.type === "Event") {
          clearTimeout(timer);
          resolve({ ok: frame.type === "Event" || frame.ok, value: JSON.parse(new TextDecoder().decode(frame.type === "Event" ? frame.eventJson : frame.json)) });
        }
      }));
    });
  } finally { socket.terminate(); }
}

/** Every test owns its server and browser partitions, including failed-assertion cleanup. */
export async function pair(browser: Browser): Promise<{ server: RealServer; desktop: BrowserContext; phone: BrowserContext; page: Page; mobile: Page; dispose(): Promise<void> }> {
  const server = await startRealServer({ port: Number(process.env.TRACER_TEST_PORT ?? 4673) });
  const desktop = await browser.newContext({ viewport: { width: 1440, height: 900 }, ignoreHTTPSErrors: true });
  const phone = await browser.newContext({ ...devices["iPhone 15"], viewport: { width: 393, height: 852 }, ignoreHTTPSErrors: true });
  try {
    const page = watchLayout(await desktop.newPage()); await enrol(page, server);
    await phone.addCookies(await desktop.cookies());
    const mobile = watchLayout(await phone.newPage()); await mobile.goto(server.origin + "/?theme=ink&bg=none");
    await expect(windows(mobile)).toHaveCount(1); await settled(mobile);
    return { server, desktop, phone, page, mobile, async dispose() { await phone.close(); await desktop.close(); await server.dispose(); } };
  } catch (error) { await phone.close(); await desktop.close(); await server.dispose(); throw error; }
}
