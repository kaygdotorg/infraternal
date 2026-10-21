/** Shared mock-browser setup for the #243 canvas settlement break-it cases. */
import { expect, type BrowserContext, type Page } from "playwright/test";

export type ReviewApi = {
  revisions(): { server: number; client: number };
  currentView(): string;
  viewIds(): string[];
  removeConsole(): number;
  skipRevision(): number;
};
type ReviewWindow = Window & { __tracerLayoutReviewDouble?: ReviewApi; __setReviewCoarse?: (coarse: boolean) => void };
const port = Number(process.env.TRACER_TEST_PORT ?? "4621");
const backendPort = Number(process.env.TRACER_BACKEND_PORT ?? String(port + 1));
const backend = `http://localhost:${backendPort}`;

export async function openReviewProduct(page: Page, wide = false): Promise<void> {
  const request = page.context().request;
  expect((await request.post(`${backend}/__mock/reset`)).ok()).toBe(true);
  expect((await request.post(`${backend}/__mock/open-terminal`)).ok()).toBe(true);
  const session = await (await request.get(`${backend}/__mock/state`)).json() as { session_id: string };
  await page.goto(`http://localhost:${port}/?mock=1&proto=product&theme=ink&bg=none&reviewLayout=1&reviewWide=${wide ? "1" : "0"}&reviewSession=${encodeURIComponent(session.session_id)}`);
  await expect(page.locator('.cl[data-view="console"] .ui-window').first()).toBeVisible({ timeout: 30_000 });
  await expect.poll(() => page.evaluate(() => (window as ReviewWindow).__tracerLayoutReviewDouble !== undefined), { timeout: 10_000 }).toBe(true);
  await expect.poll(() => page.evaluate(() => {
    const revision = (window as ReviewWindow).__tracerLayoutReviewDouble!.revisions();
    return revision.client === revision.server;
  }), { timeout: 10_000 }).toBe(true);
}

export async function openReviewSettings(page: Page): Promise<void> {
  const toggle = page.locator("#sidebar-toggle");
  if (await toggle.getAttribute("aria-expanded") !== "true") await toggle.click();
  await page.locator(".ui-sidebar-foot .ui-sidebar-settings").click();
  await expect.poll(() => page.evaluate(() => (window as ReviewWindow).__tracerLayoutReviewDouble!.currentView())).toBe("settings");
}

export async function enableReviewCoarsePointer(context: BrowserContext): Promise<void> {
  await context.addInitScript(() => {
    const native = window.matchMedia.bind(window);
    let coarse = false;
    const listeners = new EventTarget();
    Object.defineProperty(window, "matchMedia", { configurable: true, value: (query: string) => {
      if (query !== "(pointer: coarse)") return native(query);
      return {
        media: query,
        get matches() { return coarse; },
        onchange: null,
        addEventListener: listeners.addEventListener.bind(listeners),
        removeEventListener: listeners.removeEventListener.bind(listeners),
        addListener: (listener: EventListener) => listeners.addEventListener("change", listener),
        removeListener: (listener: EventListener) => listeners.removeEventListener("change", listener),
        dispatchEvent: listeners.dispatchEvent.bind(listeners),
      };
    } });
    (window as ReviewWindow).__setReviewCoarse = (next) => {
      coarse = next;
      const event = Object.assign(new Event("change"), { matches: coarse, media: "(pointer: coarse)" });
      listeners.dispatchEvent(event);
    };
  });
}
