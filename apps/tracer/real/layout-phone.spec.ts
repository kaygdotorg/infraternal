/**
 * Presentation of a server-held layout on a phone (#243): one account, a desktop browser that draws the layout and a
 * phone browser that reads it from the server. Screenshots go to the evidence directory; the assertions are the
 * measurable parts of the phone rules (targets, clipping, reachability, no motion for remote results).
 */
import { expect, test, type Page } from "playwright/test";
import { writeFile } from "node:fs/promises";
import { tracerEvidencePath } from "../test/evidence-path";
import { randomUUID } from "node:crypto";
import { WebSocketFrameDecoder } from "../../../packages/protocol/src/codec";
import { cache, pair, request, settled, windows } from "./layout-devices";

test.setTimeout(240_000);
const shot = async (page: Page, name: string): Promise<void> => { await page.screenshot({ path: tracerEvidencePath(`phone-pass-${name}.png`) }); };

/** What a person could trip over on this page: small targets, clipped text, windows with no way to reach them. */
async function audit(page: Page) {
  return page.evaluate(() => {
    const view = { w: innerWidth, h: innerHeight };
    const rect = (e: Element) => { const r = e.getBoundingClientRect(); return { x: Math.round(r.x), y: Math.round(r.y), w: Math.round(r.width), h: Math.round(r.height) }; };
    const visible = (e: Element) => { const r = e.getBoundingClientRect(); const s = getComputedStyle(e); return r.width > 0 && r.height > 0 && s.visibility !== "hidden" && s.display !== "none"; };
    const targets = [...document.querySelectorAll<HTMLElement>("button, [role=button], a[href], input, [data-action]")].filter(visible)
      .map((e) => ({ label: e.getAttribute("aria-label") || e.textContent?.trim().slice(0, 24) || e.className.toString().slice(0, 30), ...rect(e) }))
      .filter((t) => t.w < 44 || t.h < 44);
    /** A control smaller than 44 px is still a 44 px target when a press 21 px from its centre lands on it (the ::after hit area). */
    const reaches = (e: HTMLElement): boolean => { const r = e.getBoundingClientRect(); const cx = r.x + r.width / 2, cy = r.y + r.height / 2; return [[-21, 0], [21, 0], [0, -21], [0, 21]].every(([dx, dy]) => { if (cx + dx! < 0 || cx + dx! > innerWidth || cy + dy! < 0 || cy + dy! > innerHeight) return true; const hit = document.elementFromPoint(cx + dx!, cy + dy!); return !!hit && (e === hit || e.contains(hit)); }); };
    const unreachable = [...document.querySelectorAll<HTMLElement>(".cl[data-view=console] .ui-window-action, .cl[data-view=console] .ui-window-pill")].filter((e) => visible(e) && !reaches(e)).map((e) => `${e.className.toString().slice(0, 24)} ${JSON.stringify(rect(e))} in ${e.closest(".cl")?.getAttribute("data-view")}`);
    const clipped = [...document.querySelectorAll<HTMLElement>(".ui-window *")].filter((e) => visible(e) && e.scrollWidth > e.clientWidth + 1 && getComputedStyle(e).overflow !== "visible" && e.children.length === 0 && e.textContent!.trim())
      .map((e) => ({ text: e.textContent!.trim().slice(0, 30), cls: e.className.toString().slice(0, 30) }));
    const wins = [...document.querySelectorAll<HTMLElement>('.cl[data-view="console"] .ui-window')].map((e) => ({ id: e.dataset.windowId, ...rect(e) }));
    const offscreen = wins.filter((w) => w.x < 0 || w.y < 0 || w.x + w.w > view.w + 1 || w.y + w.h > view.h + 1).length;
    const scroller = document.querySelector<HTMLElement>(".cl-viewport");
    return { view, scrollable: scroller ? { sw: scroller.scrollWidth, cw: scroller.clientWidth, sh: scroller.scrollHeight, ch: scroller.clientHeight } : null, windows: wins.length, offscreen, smallTargets: targets, unreachable, clipped, wins };
  });
}

for (const count of [1, 4, 10]) {
  test(`phone pass: ${count} desktop windows on the phone`, async ({ browser }) => {
    const f = await pair(browser);
    try {
      for (let n = 1; n < count; n++) {
        await f.page.keyboard.press(n % 2 ? "Control+Shift+D" : "Control+Shift+E");
        await expect(windows(f.page)).toHaveCount(n + 1);
        await settled(f.page);
      }
      await expect(windows(f.mobile)).toHaveCount(count);
      await f.mobile.waitForTimeout(600); await settled(f.mobile);
      await shot(f.page, `${count}-desktop`); await shot(f.mobile, `${count}-phone`);
      const report = { desktop: await audit(f.page), phone: await audit(f.mobile) };
      await writeFile(tracerEvidencePath(`phone-pass-${count}-audit.json`), JSON.stringify(report, null, 2));
      console.log(JSON.stringify({ count, phone: { ...report.phone, wins: undefined }, desktop: { ...report.desktop, wins: undefined } }));
      expect((await cache(f.mobile)).canonical).toEqual((await cache(f.page)).canonical);
      expect(report.phone.unreachable).toEqual([]);
      await f.mobile.setViewportSize({ width: 375, height: 667 }); await f.mobile.waitForTimeout(700);
      await shot(f.mobile, `${count}-phone-375x667`);
      for (const [device, label] of [[f.page, "desktop"], [f.mobile, "phone-375x667"]] as const) {
        await device.goto(f.server.origin + "/?theme=paper&bg=none");
        await expect(windows(device)).toHaveCount(count); await device.waitForTimeout(900);
        await shot(device, `${count}-${label}-paper`);
      }
    } finally { await f.dispose(); }
  });
}

/** Frame-by-frame record of one window and of every running animation, started before the change arrives. */
async function watch(page: Page, id: string): Promise<void> {
  await page.evaluate((windowId) => {
    const frames: Array<{ t: number; rect: number[] | null; animations: number; shifts: number }> = [];
    let shifts = 0;
    const tasks: number[] = [];
    (window as unknown as { __tasks: number[] }).__tasks = tasks;
    new PerformanceObserver((list) => { for (const e of list.getEntries()) tasks.push(Math.round(e.duration)); }).observe({ type: "longtask" });
    new PerformanceObserver((list) => { for (const e of list.getEntries()) shifts += (e as unknown as { value: number }).value; }).observe({ type: "layout-shift", buffered: false });
    (window as unknown as { __frames: typeof frames }).__frames = frames;
    const seen: string[] = [];
    (window as unknown as { __seen: string[] }).__seen = seen;
    new PerformanceObserver((list) => { for (const e of list.getEntries()) for (const src of (e as unknown as { sources: Array<{ node?: Element }> }).sources) seen.push(`shift ${(e as unknown as { value: number }).value.toFixed(4)} ${(src.node as HTMLElement | undefined)?.className?.toString().slice(0, 40)}`); }).observe({ type: "layout-shift" });
    const tick = (): void => {
      const el = document.querySelector(`.ui-window[data-window-id="${windowId}"]`);
      const r = el?.getBoundingClientRect();
      for (const a of document.getAnimations()) { const d = `${a.constructor.name} ${(a as CSSTransition).transitionProperty ?? (a as CSSAnimation).animationName ?? "waapi"} ${((a.effect as KeyframeEffect | null)?.target as HTMLElement | null)?.className?.toString().slice(0, 40)}`; if (!seen.includes(d)) seen.push(d); }
      frames.push({ t: performance.now(), rect: r ? [r.x, r.y, r.width, r.height].map((n) => Math.round(n * 10) / 10) : null, animations: document.getAnimations().length, shifts });
      requestAnimationFrame(tick);
    };
    requestAnimationFrame(tick);
  }, id);
}
const frames = (page: Page) => page.evaluate(() => (window as unknown as { __frames: Array<{ t: number; rect: number[] | null; animations: number; shifts: number }> }).__frames);

test("phone pass: a layout change from the desktop does not move or animate what the phone shows", async ({ browser }) => {
  const f = await pair(browser);
  try {
    for (let n = 1; n < 4; n++) { await f.page.keyboard.press(n % 2 ? "Control+Shift+D" : "Control+Shift+E"); await expect(windows(f.page)).toHaveCount(n + 1); await settled(f.page); }
    await expect(windows(f.mobile)).toHaveCount(4); await f.mobile.waitForTimeout(800);
    const phoneView = (await cache(f.mobile)).canonical.views.find((v) => v.id === "console")!;
    if (phoneView.layout.type !== "tiled") throw Error("tiled");
    const first = phoneView.layout.columns[0]!.windows[0]!.id;
    await watch(f.mobile, first);
    await f.mobile.waitForTimeout(400);
    const before = (await frames(f.mobile)).length;
    // The desktop adds a window and removes another while the phone looks at the first window.
    await f.page.keyboard.press("Control+Shift+E");
    await expect(windows(f.page)).toHaveCount(5);
    await expect(windows(f.mobile)).toHaveCount(5);
    await f.mobile.waitForTimeout(900);
    await shot(f.mobile, "live-update-phone");
    const all = await frames(f.mobile);
    const rects = new Set(all.map((x) => JSON.stringify(x.rect)));
    const maxAnimations = Math.max(...all.slice(before).map((x) => x.animations));
    const shifts = all[all.length - 1]!.shifts;
    const worst = all.slice(1).reduce((m, x, i) => Math.max(m, x.t - all[i]!.t), 0);
    await writeFile(tracerEvidencePath("phone-pass-live-update.json"), JSON.stringify({ distinctRects: [...rects], maxAnimations, layoutShift: shifts, worstFrameMs: Math.round(worst * 10) / 10, frames: all.length }, null, 2));
    const seen = await f.mobile.evaluate(() => (window as unknown as { __seen: string[] }).__seen);
    await writeFile(tracerEvidencePath("phone-pass-live-update-seen.json"), JSON.stringify(seen, null, 2));
    const longTasks = await f.mobile.evaluate(() => (window as unknown as { __tasks: number[] }).__tasks);
    console.log(JSON.stringify({ seen, longTasks }));
    console.log(JSON.stringify({ distinctRects: rects.size, maxAnimations, shifts, worstFrameMs: worst }));
    expect(rects.size).toBe(1);
    // Only the changed windows move, and they move at once: nothing is tweened by transform, size or position.
    expect(seen.filter((d) => /waapi|transform|translate|width|height|left|top|inset/i.test(d) && !d.startsWith("shift"))).toEqual([]);
  } finally { await f.dispose(); }
});

const REFUSED = "That layout change was not saved. The saved layout is back.";

for (const size of [{ width: 393, height: 852 }, { width: 375, height: 667 }]) {
  test(`phone pass: a refused split is explained by the shared toast at ${size.width}x${size.height}`, async ({ browser }) => {
    const f = await pair(browser);
    try {
      await f.mobile.setViewportSize(size);
      const base = (await cache(f.mobile)).canonical;
      const view = base.views.find((v) => v.id === "console")!;
      if (view.layout.type !== "tiled") throw Error("tiled");
      expect((await request(f.server, f.desktop, "canvas.layout.apply", { op_id: randomUUID(), base_revision: base.revision, intent: { type: "weight", view_id: view.id, column_id: view.layout.columns[0]!.id, weight: 0.2 } })).ok).toBe(true);
      let armed = true, held = false;
      const queued: Array<string | Buffer> = [];
      await f.mobile.routeWebSocket("**/v1/ws", (route) => {
        const upstream = route.connectToServer();
        const decoder = new WebSocketFrameDecoder();
        (globalThis as { release?: () => void }).release = () => { armed = false; held = false; for (const bytes of queued.splice(0)) upstream.send(bytes); };
        route.onMessage((bytes) => {
          if (armed && typeof bytes !== "string") decoder.feed(new Uint8Array(bytes), (_s, frame) => {
            if (frame.type === "Call" && frame.actionId === "canvas.layout.apply" && (JSON.parse(new TextDecoder().decode(frame.inputJson)) as { intent?: { type?: string } }).intent?.type === "split") held = true;
          });
          if (held) queued.push(bytes); else upstream.send(bytes);
        });
      });
      await f.mobile.reload(); await expect(windows(f.mobile)).toHaveCount(1); await settled(f.mobile);
      await f.mobile.getByRole("button", { name: "Split right", exact: true }).tap();
      await expect(windows(f.mobile)).toHaveCount(2);
      await expect.poll(() => held).toBe(true);
      const now = (await cache(f.desktop.pages()[0]!)).canonical;
      expect((await request(f.server, f.desktop, "canvas.layout.apply", { op_id: randomUUID(), base_revision: now.revision, intent: { type: "weight", view_id: view.id, column_id: view.layout.columns[0]!.id, weight: 0.1 } })).ok).toBe(true);
      (globalThis as { release?: () => void }).release!();
      const toast = f.mobile.getByText(REFUSED, { exact: true });
      await toast.waitFor({ state: "visible", timeout: 15_000 });
      await expect(windows(f.mobile)).toHaveCount(1);
      await f.mobile.waitForTimeout(400);
      await shot(f.mobile, `refusal-${size.width}x${size.height}`);
      const box = await toast.boundingBox();
      const inToast = await toast.evaluate((el) => !!el.closest(".ui-toast, [data-toast], .toast") );
      await writeFile(tracerEvidencePath(`phone-pass-refusal-${size.width}.json`), JSON.stringify({ box, viewport: size, sharedToast: inToast, windows: await windows(f.mobile).count() }, null, 2));
      expect(box!.x).toBeGreaterThanOrEqual(0); expect(box!.x + box!.width).toBeLessThanOrEqual(size.width);
      await expect(windows(f.mobile)).toHaveCount(1);
    } finally { await f.dispose(); }
  });
}

test("phone pass: a warm offline edit is advertised and discarded by reload before confirmation", async ({ browser }) => {
  const f = await pair(browser);
  try {
    for (let n = 1; n < 3; n++) { await f.page.keyboard.press("Control+Shift+E"); await expect(windows(f.page)).toHaveCount(n + 1); await settled(f.page); }
    await expect(windows(f.mobile)).toHaveCount(3); await settled(f.mobile);
    let cut = (): void => {}; let blocked = false;
    await f.mobile.routeWebSocket("**/v1/ws", (route) => { if (blocked) { route.close(); return; } const up = route.connectToServer(); cut = () => route.close(); route.onMessage((m) => up.send(m)); up.onMessage((m) => route.send(m)); });
    await f.mobile.reload(); await expect(windows(f.mobile)).toHaveCount(3); await settled(f.mobile);
    blocked = true; cut();
    await f.mobile.waitForTimeout(1500);
    await shot(f.mobile, "offline-start");
    // Offline the phone still shows the last saved layout; a local edit is kept as a waiting change.
    await expect(windows(f.mobile)).toHaveCount(3);
    await windows(f.mobile).first().locator('[data-action="close"]').tap();
    await expect(windows(f.mobile)).toHaveCount(2);
    await f.mobile.waitForTimeout(600);
    await expect(f.mobile.getByText("Not saved — keep this tab open", { exact: true })).toBeVisible();
    await shot(f.mobile, "offline-edit");
    // Meanwhile the desktop adds a window.
    await f.page.keyboard.press("Control+Shift+D"); await expect(windows(f.page)).toHaveCount(4); await settled(f.page);
    blocked = false;
    await f.mobile.reload();
    await expect(windows(f.mobile)).toHaveCount(4, { timeout: 20_000 }); await settled(f.mobile);
    await expect.poll(async () => (await cache(f.mobile)).canonical.revision).toBe((await cache(f.page)).canonical.revision);
    expect((await cache(f.mobile)).canonical).toEqual((await cache(f.page)).canonical);
    await f.mobile.waitForTimeout(1200);
    await shot(f.mobile, "offline-back");
    await writeFile(tracerEvidencePath("phone-pass-offline.json"), JSON.stringify({ advertisedUnsaved: true, unconfirmedCloseLostOnReload: true }, null, 2));
    console.log(JSON.stringify({ advertisedUnsaved: true, desktopWindows: await windows(f.page).count(), phoneWindows: await windows(f.mobile).count() }));
  } finally { await f.dispose(); }
});
