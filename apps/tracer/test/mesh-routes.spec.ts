/**
 * Subnet routes in the Mesh view (D197 M3, #580; approved mockup J1172) on a production build: the product's Mesh adapter
 * (`mesh/api.ts`) against the fake Mesh server, which holds routes as the server does (`?mock=1&proto=clusters&scene=6&routes=1`
 * plays the reviewed scenes on it). An approved network is a one-way target with its arrows; an advertisement waits with
 * Approve and Decline; a decline is remembered; the Settings › Mesh › Networks window (keep the source address, the overlap
 * refusal, the revoke question that names the network and its arrows); arrows drawn to a network and moved onto one reach the
 * server as `{ "Network": id }`; a refused or lost change puts everything back; a person who is not the owner sees none of it.
 *
 * Captures: with `ROUTES_CAPTURES=1`, each state is written at 1440x900 (DPR 2) and 393x852 (DPR 3) in ink and paper under the
 * external evidence directory. The assertions prove each state was reached and measure alignment (±0.5 px, the owner's rule);
 * nobody judges the pictures here.
 */
import { resolve } from "node:path";
import { expect, test, type BrowserContext, type Locator, type Page } from "playwright/test";
import { tracerEvidencePath } from "./evidence-path";

/** Where the captures are written (outside the checkout). */
const OUT = tracerEvidencePath("mesh-routes");
/** Whether this run writes the review captures. */
const CAPTURE = process.env.ROUTES_CAPTURES === "1";
/** The two screen sizes of the review: desktop at DPR 2 and phone at DPR 3. */
const SIZES = [
  ["desktop", { width: 1440, height: 900 }, 2],
  ["phone", { width: 393, height: 852 }, 3],
] as const;
/** The Networks window's selector. */
const WINDOW = '[data-window-id="s-mesh-networks"]';

/** What the preview build lends a spec: flying to a view and the camera. */
type Probe = {
  flyView(id: string): void; camera(): { cx: number; cy: number; z: number }; setCamera(cx: number, cy: number, z: number): void;
  mesh: { server(): FakeServer };
};
/** The parts of the fake Mesh server the specs use. */
type FakeServer = {
  calls: Array<{ action: string; input: Record<string, unknown> }>;
  routeList(): Array<{ id: number; network: string; approved: boolean; declined: boolean; advertised: boolean; masquerade: boolean }>;
  grantList(): Array<{ id: string; from: string; to: string }>;
  advertise(node: string, networks: string[]): void;
  failNext(action: string, error?: "refuse" | "network"): void;
};
/** Runs `fn` in the page against the fake Mesh server and returns what it returns. */
const server = <T>(page: Page, fn: (s: FakeServer) => T): Promise<T> =>
  page.evaluate((source) => (new Function("s", `return (${source})(s)`) as (s: unknown) => T)((window as unknown as { __tracerClusters: Probe }).__tracerClusters.mesh.server()), fn.toString());
/** Runs `fn` in the page against the preview probe and returns what it returns. */
const probe = <T>(page: Page, fn: (p: Probe) => T): Promise<T> =>
  page.evaluate((source) => (new Function("p", `return (${source})(p)`) as (p: unknown) => T)((window as unknown as { __tracerClusters: unknown }).__tracerClusters), fn.toString());

/** The card of a network in the Mesh view, found by the address it shows (its id is the server's route number). */
const card = (page: Page, cidr: string): Locator =>
  page.locator('.ui-window[data-kind="node"][data-route]').filter({ has: page.locator(".ui-window-host", { hasText: new RegExp(`^${cidr.replace(/\./g, "\\.")}$`) }) });

/** Opens the build on the fake server in `theme`, on the Mesh view, with the route scenes (`extra` adds URL switches). */
async function open(context: BrowserContext, theme: string, extra = "&routes=1"): Promise<Page> {
  const page = await context.newPage();
  await page.goto(`/?mock=1&proto=clusters&scene=6${extra}&bg=none&theme=${theme}`);
  await expect(page.locator(".cl-mockup")).toBeVisible({ timeout: 20_000 });
  await expect.poll(() => probe(page, (p) => p.camera().z)).toBeGreaterThan(0);
  // sleep: the preview's opening animation has no event to wait for; the capture must not catch it half way.
  await page.waitForTimeout(900);
  await mesh(page);
  return page;
}

/** Flies to the Mesh view and waits for its cards. */
async function mesh(page: Page): Promise<void> {
  await probe(page, (p) => p.flyView("mesh"));
  await expect(page.locator('.ui-window[data-window-id="n-build-01"]')).toBeVisible({ timeout: 15_000 });
  // sleep: the camera's fly-in has no event; the capture waits for it to rest.
  await page.waitForTimeout(1200);
}

/** Brings a card to the middle of the screen by moving the camera (a phone shows one column of the Mesh at a time). */
async function bringIntoView(page: Page, target: Locator): Promise<void> {
  const at = (await target.boundingBox())!;
  const vp = page.viewportSize()!;
  await page.evaluate(([dx, dy]) => {
    const p = (window as unknown as { __tracerClusters: Probe }).__tracerClusters;
    const { cx, cy, z } = p.camera();
    p.setCamera(cx + dx! / z, cy + dy! / z, z);
  }, [at.x + at.width / 2 - vp.width / 2, at.y + at.height / 2 - vp.height / 2]);
  // sleep: the camera glide has no event; waits for it to rest.
  await page.waitForTimeout(700);
}

/** Puts the fake server in a scene, as the palette row does. */
async function scenario(page: Page, id: string): Promise<void> {
  await page.evaluate((action) => window.dispatchEvent(new CustomEvent("tracer:canvas-action", { detail: { action, source: "keyboard" } })), `proto:routes:${id}`);
  // sleep: the scenario's cards and arrows fade in; there is no event for the end of it.
  await page.waitForTimeout(900);
}

/** The left edge of `l` on the page, for the alignment checks. */
const left = async (l: Locator): Promise<number> => (await l.boundingBox())!.x;
/** A capture, when the run asks for them. */
const shoot = async (page: Page, name: string): Promise<void> => { if (CAPTURE) await page.screenshot({ path: resolve(OUT, `${name}.png`) }); };

/** The Networks window after a scenario that opens it. */
async function windowOf(page: Page): Promise<Locator> {
  const win = page.locator(WINDOW);
  await expect(win.locator(".cl-nets")).toBeVisible({ timeout: 15_000 });
  // sleep: the window's fly-in has no event; the capture waits for it to finish.
  await page.waitForTimeout(1000);
  return win;
}

for (const [name, viewport, scale] of SIZES) {
  for (const theme of ["ink", "paper"]) {
    test.describe(`${name} ${theme}`, () => {
      test.skip(!CAPTURE, "captures only run with ROUTES_CAPTURES=1");
      test.setTimeout(300_000);
      test("every state of subnet routes, in the Mesh view and in Settings", async ({ browser }) => {
        const context = await browser.newContext({ viewport, deviceScaleFactor: scale, ...(name === "phone" ? { hasTouch: true, isMobile: true } : {}) });
        const page = await open(context, theme);
        const tag = `${name}-${theme}`;
        // The Mesh view: an approved network with its arrows, a waiting advertisement beside it.
        await scenario(page, "approved");
        await mesh(page);
        if (name === "phone") await bringIntoView(page, card(page, "192.168.10.0/24"));
        await shoot(page, `routes-approved-${tag}`);
        if (name === "phone") await bringIntoView(page, card(page, "10.20.0.0/16"));
        await shoot(page, `routes-waiting-card-${tag}`);
        await scenario(page, "waiting");
        await mesh(page);
        await shoot(page, `routes-waiting-${tag}`);
        // The overlap refusal on the card, then in the window.
        await scenario(page, "overlap");
        await windowOf(page);
        await shoot(page, `routes-overlap-window-${tag}`);
        await mesh(page);
        if (name === "phone") await bringIntoView(page, card(page, "192.168.0.0/16"));
        await shoot(page, `routes-overlap-card-${tag}`);
        // The window: an approved network with the switch, and the revoke question.
        await scenario(page, "window");
        const win = await windowOf(page);
        await shoot(page, `routes-window-${tag}`);
        await scenario(page, "keep-source");
        await windowOf(page);
        await shoot(page, `routes-keep-source-${tag}`);
        await scenario(page, "revoke");
        const w3 = await windowOf(page);
        await w3.getByRole("button", { name: "Revoke" }).click();
        await expect(page.locator(".ui-confirm-tip").filter({ hasText: "Stop routing 192.168.10.0/24?" })).toBeVisible();
        // sleep: the question grows out of its button; the capture waits for it to settle.
        await page.waitForTimeout(500);
        await shoot(page, `routes-revoke-${tag}`);
        void win;
        await scenario(page, "none");
        await windowOf(page);
        await shoot(page, `routes-none-${tag}`);
        await context.close();
      });
    });
  }
}

test.describe("behaviour", () => {
  test("an approved network is a one-way target with arrows, and a waiting one is a dashed card with two buttons", async ({ browser }) => {
    const context = await browser.newContext({ viewport: { width: 1440, height: 900 } });
    const page = await open(context, "ink");
    const approved = card(page, "192.168.10.0/24"), waiting = card(page, "10.20.0.0/16");
    await expect(approved).toHaveAttribute("data-route", "approved");
    await expect(waiting).toHaveAttribute("data-route", "pending");
    await expect(approved.locator(".cl-node-actions")).toBeHidden();
    await expect(waiting.getByRole("button", { name: "Approve" })).toBeVisible();
    await expect(waiting.getByRole("button", { name: "Decline" })).toBeVisible();
    // Two arrows end on the approved network and none on the waiting one; its connector is not drawn (it can only be reached).
    await expect(page.locator('.cl-arrow[data-tip$="can reach 192.168.10.0/24"]')).toHaveCount(2);
    await expect(page.locator('.cl-arrow[data-tip$="can reach 10.20.0.0/16"]')).toHaveCount(0);
    await expect(approved.locator(".cl-port")).toBeHidden();
    await expect(waiting.locator(".cl-port")).toBeHidden();
    await expect(page.locator('.ui-window[data-window-id="n-build-01"] .cl-port')).toBeVisible();
    // Card text starts where the pill's name starts (alignment, ±0.5 px).
    const edges = await Promise.all([left(waiting.locator(".ui-window-host")), left(waiting.locator(".cl-node-detail")), left(waiting.locator(".cl-node-sub")), left(waiting.getByRole("button", { name: "Approve" }))]);
    expect(Math.abs(edges[1]! - edges[2]!)).toBeLessThanOrEqual(0.5);
    expect(Math.abs(edges[2]! - edges[3]!)).toBeLessThanOrEqual(0.5);
    // The buttons stay inside the card.
    const box = (await waiting.boundingBox())!, decline = (await waiting.getByRole("button", { name: "Decline" }).boundingBox())!;
    expect(decline.y + decline.height).toBeLessThanOrEqual(box.y + box.height);
    expect(decline.x + decline.width).toBeLessThanOrEqual(box.x + box.width);
    await context.close();
  });

  test("Approve makes the network a target, Decline sends the advertisement away", async ({ browser }) => {
    const context = await browser.newContext({ viewport: { width: 1440, height: 900 } });
    const page = await open(context, "ink");
    await scenario(page, "waiting");
    await mesh(page);
    await bringIntoView(page, card(page, "10.20.0.0/16"));
    await card(page, "10.20.0.0/16").getByRole("button", { name: "Approve" }).click();
    await expect(card(page, "10.20.0.0/16")).toHaveAttribute("data-route", "approved");
    await expect(page.locator(".ui-toast").filter({ hasText: "10.20.0.0/16 is approved" })).toBeVisible();
    await card(page, "192.168.10.0/24").getByRole("button", { name: "Decline" }).click();
    await expect(card(page, "192.168.10.0/24")).toHaveCount(0);
    await expect.poll(() => server(page, (s) => s.routeList().find((r) => r.network === "192.168.10.0/24")?.declined)).toBe(true);
    // Remembered: the machine withdraws it and offers it again, and it does not come back to wait.
    await server(page, (s) => { s.advertise("build-01", []); s.advertise("build-01", ["192.168.10.0/24"]); });
    // sleep: the adapter lists again after the server's change event; nothing on screen marks the end of a list that changes nothing.
    await page.waitForTimeout(600);
    await expect(card(page, "192.168.10.0/24")).toHaveCount(0);
    // The window still lists it, declined, and the owner may change their mind.
    await page.evaluate(() => window.dispatchEvent(new CustomEvent("tracer:canvas-action", { detail: { action: "canvas:settings:mesh.networks", source: "keyboard" } })));
    const win = await windowOf(page);
    const declined = win.locator('.cl-net[data-state="declined"]');
    await expect(declined).toContainText("Declined");
    await declined.getByRole("button", { name: "Approve" }).click();
    await expect(win.locator('.cl-net[data-network="192.168.10.0/24"]')).toHaveAttribute("data-state", "approved");
    await context.close();
  });

  test("a change the server does not take is put back and said: approve, revoke, keep-source", async ({ browser }) => {
    const context = await browser.newContext({ viewport: { width: 1440, height: 900 } });
    const page = await open(context, "ink");
    await scenario(page, "window");
    const win = await windowOf(page);
    await server(page, (s) => s.failNext("mesh.route.approve", "network"));
    await win.locator('.cl-net[data-state="pending"]').getByRole("button", { name: "Approve" }).click();
    await expect(page.locator(".ui-toast").filter({ hasText: "Could not approve 10.20.0.0/16. Check your connection" })).toBeVisible();
    await expect(win.locator('.cl-net[data-network="10.20.0.0/16"]')).toHaveAttribute("data-state", "pending");
    await server(page, (s) => s.failNext("mesh.route.revoke", "refuse"));
    await win.getByRole("button", { name: "Revoke" }).click();
    await page.locator(".ui-confirm-tip").filter({ hasText: "Stop routing" }).last().getByRole("button", { name: "Revoke" }).click();
    await expect(page.locator(".ui-toast").filter({ hasText: "Could not stop routing 192.168.10.0/24" })).toBeVisible();
    await expect(win.locator('.cl-net[data-network="192.168.10.0/24"]')).toHaveAttribute("data-state", "approved");
    await mesh(page);
    // The arrows that were taken off the screen for the revoke are back.
    await expect(page.locator('.cl-arrow[data-tip$="can reach 192.168.10.0/24"]')).toHaveCount(2);
    expect(await server(page, (s) => s.routeList().find((r) => r.network === "192.168.10.0/24")?.approved)).toBe(true);
    await context.close();
  });

  test("an arrow drawn onto an approved network reaches the server as a network end; a tail never lands on a network", async ({ browser }) => {
    const context = await browser.newContext({ viewport: { width: 1440, height: 900 } });
    const page = await open(context, "ink");
    const target = card(page, "192.168.10.0/24");
    const route = await server(page, (s) => s.routeList().find((r) => r.network === "192.168.10.0/24")!.id);
    const from = page.locator('.ui-window[data-window-id="n-edge-arm"]');
    await from.locator(".ui-window-pill").hover();
    const port = (await from.locator(".cl-port").boundingBox())!;
    const t = (await target.boundingBox())!;
    await page.mouse.move(port.x + port.width / 2, port.y + port.height / 2);
    await page.mouse.down();
    await page.mouse.move(t.x + t.width / 2, t.y + t.height / 2, { steps: 12 });
    await expect(target).toHaveAttribute("data-drop", "");
    await page.mouse.up();
    await page.locator(".ui-confirm-tip").getByRole("button", { name: "Allow access" }).click();
    await expect.poll(() => server(page, (s) => s.calls.filter((c) => c.action === "mesh.grant.create").map((c) => c.input))).toEqual([{ name: `edge-arm-to-net-${route}`, from: { Node: 2 }, to: { Network: route }, both_ways: false }]);
    await expect(page.locator('.cl-arrow[data-tip="edge-arm can reach 192.168.10.0/24"]')).toHaveCount(1);
    // A waiting network is no target: the connector does not snap to it.
    const waiting = (await card(page, "10.20.0.0/16").boundingBox())!;
    await from.locator(".ui-window-pill").hover();
    await page.mouse.move(port.x + port.width / 2, port.y + port.height / 2);
    await page.mouse.down();
    await page.mouse.move(waiting.x + waiting.width / 2, waiting.y + waiting.height / 2, { steps: 12 });
    await expect(card(page, "10.20.0.0/16")).not.toHaveAttribute("data-drop", "");
    await page.mouse.up();
    await expect(page.locator(".ui-confirm-tip")).toHaveCount(0);
    await context.close();
  });

  test("an approval that overlaps one already approved is refused in a sentence, on the card and in the window", async ({ browser }) => {
    const context = await browser.newContext({ viewport: { width: 1440, height: 900 } });
    const page = await open(context, "ink");
    await scenario(page, "overlap");
    const win = await windowOf(page);
    const sentence = "192.168.0.0/16 overlaps 192.168.10.0/24, which is already approved. Revoke that one first, or have the machine advertise a network that does not overlap.";
    await expect(win.locator(".cl-up-refusal")).toHaveText(sentence);
    await mesh(page);
    await expect(card(page, "192.168.0.0/16").locator(".cl-node-sub")).toHaveText("Overlaps 192.168.10.0/24");
    await expect(card(page, "192.168.0.0/16")).toHaveAttribute("data-route", "pending");
    await context.close();
  });

  test("Revoke asks first, names the network and the arrows it deletes, and the network waits again with no arrows", async ({ browser }) => {
    const context = await browser.newContext({ viewport: { width: 1440, height: 900 } });
    const page = await open(context, "ink");
    await scenario(page, "revoke");
    const win = await windowOf(page);
    await win.getByRole("button", { name: "Revoke" }).click();
    const ask = page.locator(".ui-confirm-tip").filter({ hasText: "Stop routing 192.168.10.0/24?" });
    await expect(ask).toContainText("The 3 arrows that end on it are deleted");
    await ask.getByRole("button", { name: "Keep it" }).click();
    await expect(win.locator('.cl-net[data-state="approved"]')).toHaveCount(1);
    await win.getByRole("button", { name: "Revoke" }).click();
    await page.locator(".ui-confirm-tip").filter({ hasText: "Stop routing" }).last().getByRole("button", { name: "Revoke" }).click();
    await expect(win.locator('.cl-net[data-state="pending"]')).toHaveCount(1);
    await mesh(page);
    await expect(card(page, "192.168.10.0/24")).toHaveAttribute("data-route", "pending");
    await expect(page.locator('.cl-arrow[data-tip$="can reach 192.168.10.0/24"]')).toHaveCount(0);
    await context.close();
  });

  test("the Networks window is aligned and the switch keeps each machine's address", async ({ browser }) => {
    const context = await browser.newContext({ viewport: { width: 1440, height: 900 }, deviceScaleFactor: 2 });
    const page = await open(context, "ink");
    await scenario(page, "window");
    const win = await windowOf(page);
    const block = win.locator('.cl-net[data-state="approved"]');
    const edges = await Promise.all([left(block.locator(".ui-ts-title")), left(block.locator(".ui-kv-key").first()), left(block.locator(".ui-setting-title")), left(block.getByRole("button", { name: "Revoke" }))]);
    for (const e of edges) expect(Math.abs(e - edges[0]!)).toBeLessThanOrEqual(0.5);
    const pending = win.locator('.cl-net[data-state="pending"]');
    expect(Math.abs((await left(pending.getByRole("button", { name: "Approve" }))) - edges[0]!)).toBeLessThanOrEqual(0.5);
    // The status marks are as tall as the text beside them (TASTE).
    const mark = await block.locator(".ui-kv-mark").first().boundingBox();
    const text = await block.locator(".ui-kv-value").first().evaluate((n) => parseFloat(getComputedStyle(n).fontSize));
    expect(Math.abs(mark!.height - text)).toBeLessThanOrEqual(0.5);
    await expect(block.locator(".ui-setting-caption")).toHaveCount(0);
    await block.locator("[data-setting] [role=switch]").click();
    await expect(win.locator('.cl-net[data-state="approved"] [role=switch]')).toHaveAttribute("aria-checked", "true");
    await mesh(page);
    await expect(card(page, "192.168.10.0/24").locator(".cl-node-sub")).toHaveText("Keeps each machine's own address");
    await context.close();
  });

  test("on a phone the window header is a back button and a heading", async ({ browser }) => {
    const context = await browser.newContext({ viewport: { width: 393, height: 852 }, deviceScaleFactor: 3, hasTouch: true, isMobile: true });
    const page = await open(context, "ink");
    await scenario(page, "window");
    await windowOf(page);
    const crumbs = page.locator(".cl-crumbs");
    await expect(crumbs).toBeVisible();
    await expect(crumbs.locator(".cl-crumb[data-level=row] .cl-crumb-name")).toHaveText("Mesh");
    await expect(crumbs.locator(".cl-crumb[data-level=group] .cl-crumb-name")).toHaveText("Networks");
    await context.close();
  });

  test("a person who is not the owner sees no network: no card, no window", async ({ browser }) => {
    const context = await browser.newContext({ viewport: { width: 1440, height: 900 } });
    const page = await open(context, "ink", "&routes=1&meshowner=0");
    await expect(page.locator('.ui-window[data-window-id^="n-net:"]')).toHaveCount(0);
    // Every card carries the (hidden) buttons of a waiting network, since the pool may rebind it to one; none is shown.
    await expect(page.locator(".cl-node-actions:not([hidden])")).toHaveCount(0);
    await page.evaluate(() => window.dispatchEvent(new CustomEvent("tracer:canvas-action", { detail: { action: "canvas:settings:mesh.networks", source: "keyboard" } })));
    await expect(page.locator(WINDOW)).toHaveCount(0);
    await context.close();
  });
});
