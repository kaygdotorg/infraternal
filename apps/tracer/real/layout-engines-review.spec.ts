/** Production-engine controls for retries and all browser persistence surfaces (D312, #250). */
import { chromium, expect, test, type Page } from "playwright/test";
import { enrol, settled, windows } from "./layout-devices";
import { cache, watchLayout } from "./layout-observer";
import { startRealServer } from "./server";
import { WebSocketFrameDecoder } from "../../../packages/protocol/src/codec";

/** The real ceremony runs in its supported harness; target engines receive only the live cookie. */
test("production engine keeps two-device retries in RAM and stores only public shell assets", async ({ browser }) => {
  const server = await startRealServer({ port: Number(process.env.TRACER_TEST_PORT ?? 4457) });
  const bootstrap = await chromium.launch({ args: ["--ignore-certificate-errors"] });
  const auth = await bootstrap.newContext({ ignoreHTTPSErrors: true });
  const aContext = await browser.newContext({ viewport: { width: 1440, height: 900 }, ignoreHTTPSErrors: true });
  const bContext = await browser.newContext({ viewport: { width: 393, height: 852 }, ignoreHTTPSErrors: true });
  try {
    const owner = watchLayout(await auth.newPage()); await enrol(owner, server);
    const session = await (await auth.request.post(server.origin + "/auth/session", { data: {}, headers: { Origin: server.origin } })).json();
    const cookies = await auth.cookies(); await aContext.addCookies(cookies); await bContext.addCookies(cookies);
    const a = watchLayout(await aContext.newPage()), b = watchLayout(await bContext.newPage());
    let holding = false, disconnect = (): void => {};
    // Explicit delivery control works even when an engine's offline emulation
    // leaves established WebSockets alive. Dropped calls remain owned by the tab.
    await a.routeWebSocket("**/v1/ws", (route) => {
      const upstream = route.connectToServer();
      disconnect = () => route.close({ code: 1001, reason: "review reconnect" });
      route.onMessage((message) => {
        let layout = false;
        if (typeof message !== "string") new WebSocketFrameDecoder().feed(new Uint8Array(message), (_stream, frame) => { if (frame.type === "Call" && frame.actionId === "canvas.layout.apply") layout = true; });
        if (!holding || !layout) upstream.send(message);
      });
    });
    await a.goto(server.origin); await b.goto(server.origin); await expect(windows(a)).toHaveCount(1); await expect(windows(b)).toHaveCount(1); await settled(a); await settled(b);
    async function storage(page: Page): Promise<void> {
      const state = await page.evaluate(async (identity) => {
        const local = Object.entries(localStorage), tab = Object.entries(sessionStorage);
        const databases = typeof indexedDB.databases === "function" ? await indexedDB.databases() : [];
        const cached: Array<{ url: string; private: boolean }> = [];
        if (typeof caches !== "undefined") for (const name of await caches.keys()) {
          const cache = await caches.open(name);
          for (const request of await cache.keys()) {
            const response = await cache.match(request);
            cached.push({ url: request.url, private: Boolean(response && (await response.text()).includes(identity)) });
          }
        }
        const files: string[] = [];
        if (typeof navigator.storage?.getDirectory === "function") {
          const root = await navigator.storage.getDirectory();
          for await (const name of (root as unknown as { keys(): AsyncIterable<string> }).keys()) files.push(name);
        }
        return { local, tab, databases, cached, files };
      }, session.user_id);
      expect.soft(state.local.filter(([key, value]) => key!.includes(session.user_id) || value!.includes(session.user_id) || /canvas|drawing|tracer\.session/.test(key!))).toEqual([]);
      expect.soft(state.tab.filter(([key, value]) => key!.includes(session.user_id) || value!.includes(session.user_id) || /canvas|drawing|tracer\.session/.test(key!))).toEqual([]);
      expect(state.databases).toEqual([]); expect(state.files).toEqual([]);
      expect(state.cached.every((row) => !row.private && (new URL(row.url).pathname === "/" || /\.(js|css|woff2|wasm)$/.test(new URL(row.url).pathname)))).toBe(true);
    }
    await storage(a); await storage(b);
    holding = true;
    await windows(a).first().locator('[data-action="close"]').evaluate((el) => (el as HTMLElement).click());
    await expect(windows(a)).toHaveCount(0); await expect(a.getByText("Not saved — keep this tab open", { exact: true })).toBeVisible();
    await storage(a);
    await windows(b).first().locator('[data-action="close"]').evaluate((el) => (el as HTMLElement).click());
    await expect(windows(b)).toHaveCount(0); await settled(b); await storage(b);
    holding = false; disconnect(); await a.evaluate(() => window.dispatchEvent(new Event("online")));
    await settled(a); await expect.poll(async () => (await cache(a)).canonical).toEqual((await cache(b)).canonical);
    await storage(a); await storage(b);
    await a.reload(); await expect(windows(a)).toHaveCount(0); await settled(a); await storage(a);
    const result = await aContext.request.post(server.origin + "/auth/logout", { data: {}, headers: { Origin: server.origin } }); expect(result.ok()).toBe(true);
    await a.evaluate(() => window.dispatchEvent(new Event("online"))); await b.evaluate(() => window.dispatchEvent(new Event("online")));
    await expect(a.locator("#login-passkey")).toBeVisible(); await expect(b.locator("#login-passkey")).toBeVisible();
    await storage(a); await storage(b);
  } finally { await aContext.close(); await bContext.close(); await auth.close(); await bootstrap.close(); await server.dispose(); }
});
