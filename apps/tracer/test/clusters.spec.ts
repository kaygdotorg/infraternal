/**
 * Clusters concept mockup (`?proto=clusters`, issue #89): walks the six scenes and checks the
 * behaviours the owner's open questions are about. Everything runs against the test double.
 */
import { paletteOpen } from "./settings-palette";
import { expect, test, type Browser, type Page } from "playwright/test";

type Probe = {
  scene(): number;
  camera(): { cx: number; cy: number; z: number; lod: string; zoomBand: string; tx: number; ty: number };
  views(): Array<{ id: string; name: string; team: boolean; x: number; y: number; w: number; h: number; windows: string[] }>;
  grants(): Array<{ id: string; from: string; to: string }>;
  float(): { cols: number; rows: number; width: number; height: number } | undefined;
  canvasLock(): { on: boolean; index: number; stops: number; view: string };
  setScene(n: number): void;
  setSnap(on: boolean): void;
};
const probe = <T>(page: Page, fn: (p: Probe) => T): Promise<T> =>
  page.evaluate((source) => (new Function("p", `return (${source})(p)`) as (p: unknown) => T)((window as unknown as { __tracerClusters: unknown }).__tracerClusters), fn.toString());

/** Opens a named mock canvas scene for cluster geometry and gesture assertions. */
async function open(page: Page, scene: number, query = ""): Promise<void> {
  await page.setViewportSize({ width: 1440, height: 900 });
  // These specs check gestures, geometry and timing, not a look: they run on the Solid theme (`look=solid`). Under the default Tinted theme the windows' 6 px blur costs
  // enough frames in software rendering (17 ms a frame becomes 27 ms on a phone-sized page and 64 ms on a desktop one) that held fingers and wheel steps coalesce and a
  // gesture is sometimes lost. The cost of the blur is measured on its own, with the frame times, on #323.
  await page.goto(`/?mock=1&proto=clusters&scene=${scene}&theme=ink&bg=soft${query.includes("look=") ? "" : "&look=solid"}${query}`);
  await expect(page.locator(".cl-mockup")).toBeVisible({ timeout: 20_000 });
  await expect.poll(() => probe(page, (p) => p.views().length)).toBeGreaterThan(0);
  // Let the camera come to rest before measuring.
  await page.waitForTimeout(500);
}

const overlap = (a: { x: number; y: number; w: number; h: number }, b: { x: number; y: number; w: number; h: number }): boolean =>
  a.x < b.x + b.w && b.x < a.x + a.w && a.y < b.y + b.h && b.y < a.y + a.h;

test("the six scenes load from the palette and the mockup tag, without a page error", async ({ page }) => {
  const errors: string[] = [];
  page.on("pageerror", (e) => errors.push(e.message));
  await open(page, 1);
  await expect(page.locator(".cl-mockup")).toHaveText(/mockup/i);
  await page.keyboard.press("Control+Shift+K");
  await page.keyboard.type("mockup: scene");
  await expect(page.getByText("Mockup: scene 4 – open from a container")).toBeVisible();
  await page.keyboard.press("Escape");
  for (let scene = 1; scene <= 6; scene++) {
    await probe(page, (p) => p.setScene(0)).catch(() => undefined);
    await page.evaluate((n) => (window as unknown as { __tracerClusters: { setScene(n: number): void } }).__tracerClusters.setScene(n), scene);
    await expect.poll(() => probe(page, (p) => p.scene())).toBe(scene);
    await page.waitForTimeout(250);
  }
  expect(errors).toEqual([]);
});

test("overview: three views, thumbnails, a hover summary, and the views listed in the sidebar and the palette", async ({ page }) => {
  await open(page, 1);
  expect((await probe(page, (p) => p.views())).map((v) => v.id)).toEqual(["console", "containers", "mesh", "settings"]);
  const camera = await probe(page, (p) => p.camera());
  expect(camera.z).toBeLessThan(0.6);
  expect(camera.lod).toBe("thumb");
  await page.locator('.cl[data-view="console"] .cl-label').hover();
  // The card lists the view's five most recent windows by name (fewer when the view has fewer), and "All" only above five.
  const shown = (await probe(page, (p) => p.views())).find((v) => v.id === "console")!.windows.length;
  const summary = page.locator(".cl-summary[data-open='true']");
  await expect(summary.locator(".cl-summary-pick")).toHaveCount(Math.min(5, shown));
  await expect(summary.locator(".cl-summary-pick .cl-viewrow-name").first()).not.toHaveText("");
  if (shown > 5) await expect(summary.locator(".cl-summary-all")).toHaveText(/All \d+ windows/);
  else await expect(summary.locator(".cl-summary-all")).toHaveCount(0);
  await page.mouse.move(700, 880);
  await page.locator("#sidebar-toggle").click();
  await expect(page.locator("#tree .bm-sec")).toHaveCount(4);
  await page.locator("#sidebar-toggle").click();
  expect((await probe(page, (p) => p.canvasLock())).on).toBe(false);
  await page.keyboard.press("Control+Shift+K");
  await page.keyboard.type("go to");
  await expect(page.locator(".palette-result, [role='option']").filter({ hasText: "Go to Mesh" }).first()).toBeVisible();
  await page.keyboard.press("Control+a");
  await page.keyboard.type("canvas lock");
  await expect(page.getByText("Canvas lock on").first()).toBeVisible();
  await page.keyboard.press("Escape");
});

test("fly in: a view click springs the camera in and the windows go live above 60 percent", async ({ page }) => {
  await open(page, 1);
  await page.locator('.cl[data-view="console"] .cl-label').click();
  await expect.poll(async () => (await probe(page, (p) => p.camera())).lod, { timeout: 4000 }).toBe("live");
  await expect.poll(async () => (await probe(page, (p) => p.camera())).z, { timeout: 4000 }).toBeGreaterThan(0.9);
  // Flying in turns snap on.
  expect((await probe(page, (p) => p.canvasLock())).on).toBe(true);
  // Control+2 is the same camera spring to the second view.
  await page.keyboard.press("Control+Shift+Digit2");
  await expect.poll(async () => { const c = await probe(page, (p) => p.camera()); const v = (await probe(page, (p) => p.views())).find((x) => x.id === "containers")!; return Math.abs(c.cy - (v.y + v.h / 2)) < 300; }, { timeout: 4000 }).toBe(true);
});

test("D194: terminal windows draw no arrows and have no connector; arrows live only in the Mesh view", async ({ page }) => {
  await open(page, 3);
  const pill = page.locator('.ui-window[data-window-id="w-build-01"] .ui-window-pill');
  await pill.hover();
  await page.waitForTimeout(600);
  expect(await page.locator(".cl-reach .cl-arrow, .cl-edge, .ui-window[data-kind=\"terminal\"] .cl-port").count()).toBe(0);
  // The arrows that exist are in the Mesh view, and the connector is on its cards.
  expect(await page.locator('.cl[data-view="console"] .cl-arrow').count()).toBe(0);
  await page.keyboard.press("Control+Shift+Digit3");
  await page.waitForTimeout(1000);
  expect(await page.locator('.cl[data-view="mesh"] .cl-arrow').count()).toBeGreaterThan(0);
  expect(await page.locator('.cl[data-view="mesh"] .ui-window[data-kind="node"] .cl-port').count()).toBeGreaterThan(0);
});

test("a window kind decides its controls, and a terminal splits", async ({ page }) => {
  await open(page, 4);
  await expect(page.locator('.ui-window[data-window-id="w-containers"] [data-action^="split"]')).toHaveCount(0);
  await expect(page.locator('.ui-window[data-window-id="w-logs"] [data-action^="split"]')).toHaveCount(0);
  await page.locator('.cl-row[data-name="web-api"]').click();
  await expect(page.locator(".cl-float")).toBeVisible();
  await page.locator('.cl-float [data-action="close"]').click();
  await expect(page.locator(".cl-badge[data-open='true']")).toContainText("session in Console");
  await open(page, 3);
  const before = await page.locator('.cl[data-view="console"] .ui-window').count();
  await page.locator('.ui-window[data-window-id="w-studio-mac"] [data-action="split-down"]').evaluate((b) => (b as HTMLElement).click()); // off screen at the 1.1 default: three windows no longer fit side by side
  await expect(page.locator('.cl[data-view="console"] .ui-window')).toHaveCount(before + 1);
});

test("split right divides the window beside it, split down stacks below it, from the header, the shortcuts and the palette", async ({ page }) => {
  await open(page, 3);
  const id = "w-studio-mac";
  const rect = (sel: string) => page.locator(sel).first().evaluate((n) => { const r = n.getBoundingClientRect(); return { x: r.x, y: r.y, w: r.width, h: r.height }; });
  const count = () => page.locator('.cl[data-view="console"] .ui-window').count();
  const n0 = await count();
  // Two controls with names, and the right one is first.
  const actions = await page.locator(`.ui-window[data-window-id="${id}"] .ui-window-action`).evaluateAll((b) => b.map((x) => [(x as HTMLElement).dataset.action, (x as HTMLElement).dataset.tip]));
  // A terminal has no "?" (owner, 2026-11-06): the two split buttons are its first controls.
  expect(actions.slice(0, 2)).toEqual([["split-right", "Split right"], ["split-down", "Split down"]]);
  const a0 = await rect(`.ui-window[data-window-id="${id}"]`);
  await page.locator(`.ui-window[data-window-id="${id}"] [data-action="split-right"]`).evaluate((b) => (b as HTMLElement).click());
  await expect.poll(count).toBe(n0 + 1);
  await page.waitForTimeout(1200);
  const created = await page.locator('.cl[data-view="console"] .ui-window[data-window-id^="w-studio-mac-s"]').first().evaluate((n) => { const r = n.getBoundingClientRect(); return { id: (n as HTMLElement).dataset.windowId, x: r.x, y: r.y, w: r.width, h: r.height }; });
  const a1 = await rect(`.ui-window[data-window-id="${id}"]`);
  expect(created.x).toBeGreaterThan(a1.x + a1.w - 1); // beside it
  expect(Math.abs(created.y - a1.y)).toBeLessThan(2); // same top
  // D212: split right divides the window's own space, so the old window and the new one share its width (no new column).
  expect(Math.abs(a1.w - (a0.w - 12) / 2)).toBeLessThan(2);
  expect(Math.abs(created.w - a1.w)).toBeLessThan(2);
  // Split down from the shortcut (Ctrl+Alt+Shift+D here; the default is platform dependent).
  await page.keyboard.press("Control+Shift+E");
  await expect.poll(count).toBe(n0 + 2);
  await page.waitForTimeout(1200);
  // The newest window (highest serial) is the one the last split made; it sits below its parent, not at the top of a column.
  const below = await page.locator('.cl[data-view="console"] .ui-window[data-window-id^="w-studio-mac-s"]').evaluateAll((nodes) => {
    const newest = nodes.map((n) => ({ n, k: Number((n as HTMLElement).dataset.windowId!.replace(/\D+/g, "")) })).sort((p, q) => q.k - p.k)[0]!.n;
    const r = newest.getBoundingClientRect(); return { y: r.y, x: r.x };
  });
  expect(below.y).toBeGreaterThan(a1.y + 20);
  // Split right from the palette and the shortcut.
  await page.keyboard.press("Control+Shift+K");
  await page.keyboard.type("split right");
  await expect(page.locator(".palette .result", { hasText: "Split right" })).toBeVisible();
  await page.keyboard.press("Enter");
  await expect.poll(count).toBe(n0 + 3);
  await page.waitForTimeout(1200);
  await page.keyboard.press("Control+Shift+D");
  await expect.poll(count).toBe(n0 + 4);
});

test("canvas lock off frees pan and zoom in place; the overview is its own action", async ({ page }) => {
  await open(page, 3);
  const cam0 = await probe(page, (p) => p.camera());
  await page.keyboard.press("Control+Shift+G");
  await page.waitForTimeout(900);
  const cam1 = await probe(page, (p) => p.camera());
  expect(cam1.z).toBeCloseTo(cam0.z, 3);
  expect(cam1.cx).toBeCloseTo(cam0.cx, 1);
  expect(cam1.cy).toBeCloseTo(cam0.cy, 1);
  expect((await probe(page, (p) => p.canvasLock())).on).toBe(false);
  // Free: a ctrl+wheel zooms, a plain wheel pans.
  await page.mouse.move(720, 450);
  await page.keyboard.down("Control");
  await page.mouse.wheel(0, 240);
  await page.keyboard.up("Control");
  await page.waitForTimeout(300);
  expect((await probe(page, (p) => p.camera())).z).toBeLessThan(cam0.z);
  await page.keyboard.press("Escape");
  await expect.poll(async () => (await probe(page, (p) => p.camera())).z, { timeout: 4000 }).toBeLessThan(0.5);
});

test("a Ctrl+wheel that lands while the free-canvas code is still loading is kept and zooms once it arrives", async ({ page }) => {
  await open(page, 3);
  const cam0 = await probe(page, (p) => p.camera());
  // Every script requested from now on takes 1.5 s, so the free-canvas gestures (fetched when the lock turns off, D188) are still on their way
  // when the wheel turns.
  await page.route("**/*.js", async (route) => { await new Promise((done) => setTimeout(done, 1500)); await route.continue().catch(() => undefined); });
  await page.keyboard.press("Control+Shift+G");
  await expect.poll(async () => (await probe(page, (p) => p.canvasLock())).on, { timeout: 5000 }).toBe(false);
  await page.mouse.move(720, 450);
  await page.keyboard.down("Control");
  await page.mouse.wheel(0, 240);
  await page.keyboard.up("Control");
  // The gestures arrive about 1.5 s later and the held wheel is played then: the camera zooms out, it does not stay where it was.
  await expect.poll(async () => (await probe(page, (p) => p.camera())).z, { timeout: 8000 }).toBeLessThan(cam0.z);
});

test("the dots sit on the gradient: the gradient shows everywhere, the dot layers are plain tiles with no cover or mask", async ({ page }) => {
  // The one spec that needs a gradient: Tinted's own (the other looks are asked for with `look=`; see `open`).
  await open(page, 3, "&look=tinted");
  const info = await page.evaluate(() => {
    const fill = document.querySelector<HTMLElement>(".ui-canvas-backdrop-fill")!;
    const layers = [...document.querySelectorAll<HTMLElement>(".ui-canvas-backdrop-layer")];
    const shown = layers.find((l) => !l.hidden)!;
    const cs = getComputedStyle(shown);
    const stage = document.querySelector<HTMLElement>("#terminal-screen")!.getBoundingClientRect();
    const root = document.querySelector<HTMLElement>(".ui-canvas-backdrop")!.getBoundingClientRect();
    return {
      fillOpacity: Number(getComputedStyle(fill).opacity), fillImage: /-gradient\(/.test(getComputedStyle(fill).backgroundImage),
      layerImage: cs.backgroundImage.startsWith("radial-gradient"), layerMask: cs.maskImage, layerBg: cs.backgroundColor,
      coversScreen: Math.abs(root.width - stage.width) < 1 && Math.abs(root.height - stage.height) < 1,
    };
  });
  expect(info.fillOpacity).toBeGreaterThan(0.2);
  expect(info.fillImage).toBe(true);
  expect(info.layerImage).toBe(true);
  expect(info.layerMask).toBe("none");
  expect(info.layerBg).toBe("rgba(0, 0, 0, 0)"); // no opaque cover over the gradient
  expect(info.coversScreen).toBe(true); // behind the chrome too, not only the canvas area
});

test("mesh: hover names a grant, dragging a head or tail unsnaps it, snaps to another node and asks before moving; dropping on empty canvas asks to remove", async ({ page }) => {
  await open(page, 6);
  await page.keyboard.press("Control+Shift+Digit3"); // fly into Mesh
  await page.waitForTimeout(900);
  const grantsOf = () => probe(page, (p) => p.grants());
  const centre = async (sel: string) => { const b = (await page.locator(sel).first().boundingBox())!; return { x: b.x + b.width / 2, y: b.y + b.height / 2 }; };
  // Hover: the arrow gets its handles and a warm tooltip with the grant's name.
  const arrow = page.locator('.cl[data-view="mesh"] .cl-arrow[data-grant="g3"]');
  const hit = await centre('.cl[data-view="mesh"] .cl-arrow[data-grant="g3"] .cl-arrow-hit');
  await page.mouse.move(hit.x, hit.y);
  await expect(arrow).toHaveAttribute("data-tip", "nix-cache can reach studio-mac");
  await expect.poll(() => arrow.locator(".cl-arrow-handle").first().evaluate((n) => getComputedStyle(n).opacity)).toBe("1");
  await expect(page.locator(".ui-tooltip, .tip-pos").first()).toContainText("nix-cache can reach studio-mac");
  // Head to another node: nix-cache -> studio-mac becomes nix-cache -> edge-arm, after a confirmation.
  const head = await centre('.cl-arrow[data-grant="g3"] .cl-arrow-handle[data-end="head"]');
  const edge = await centre('.ui-window[data-window-id="n-edge-arm"]');
  await page.mouse.move(head.x, head.y);
  await page.mouse.down();
  await page.mouse.move(head.x + 10, head.y + 110, { steps: 5 }); // well clear of its own node: the end unsnaps
  await expect(page.locator('.cl-arrow[data-live]:not([data-snapped])')).toHaveCount(1); // unsnapped, following the pointer
  await page.mouse.move(edge.x, edge.y, { steps: 12 });
  await expect(page.locator('.ui-window[data-window-id="n-edge-arm"][data-drop]')).toHaveCount(1);
  await expect(page.locator('.cl-arrow[data-live][data-snapped]')).toHaveCount(1); // snapped on the new node
  await page.mouse.up();
  await expect(page.locator(".ui-confirm-tip")).toContainText("Let nix-cache reach edge-arm instead of studio-mac?");
  await page.locator(".ui-confirm-yes").click();
  await expect.poll(async () => (await grantsOf()).find((g) => g.id === "g3")?.to).toBe("edge-arm");
  // Cancelling springs the arrow back and changes nothing: ci -> nix-cache, tail to studio-mac.
  const tailPt = await centre('.cl-arrow[data-grant="g7"] .cl-arrow-hit');
  await page.mouse.move(tailPt.x, tailPt.y);
  const tail = await centre('.cl-arrow[data-grant="g7"] .cl-arrow-handle[data-end="tail"]');
  const studio = await centre('.ui-window[data-window-id="n-studio-mac"]');
  await page.mouse.move(tail.x, tail.y);
  await page.mouse.down();
  await page.mouse.move(tail.x - 10, tail.y + 110, { steps: 5 });
  await page.mouse.move(studio.x, studio.y, { steps: 14 });
  await page.mouse.up();
  await expect(page.locator(".ui-confirm-tip")).toContainText("Let studio-mac reach nix-cache instead of tag:ci?");
  await page.locator(".ui-confirm-no").click();
  await page.waitForTimeout(500);
  expect((await grantsOf()).find((g) => g.id === "g7")).toMatchObject({ from: "tag:ci", to: "nix-cache" });
  await expect(page.locator(".cl-arrow[data-live]")).toHaveCount(0);
  // Dropped on empty canvas: offers to remove the grant.
  const n0 = (await grantsOf()).length;
  const mid = await centre('.cl-arrow[data-grant="g3"] .cl-arrow-hit');
  await page.mouse.move(mid.x, mid.y);
  const head2 = await centre('.cl-arrow[data-grant="g3"] .cl-arrow-handle[data-end="head"]');
  await page.mouse.move(head2.x, head2.y);
  await page.mouse.down();
  await page.mouse.move(head2.x + 160, head2.y - 40, { steps: 10 }); // open canvas, clear of every node's snap radius
  await page.mouse.up();
  await expect(page.locator(".ui-confirm-tip")).toContainText("Stop nix-cache reaching edge-arm?");
  await page.locator(".ui-confirm-yes").click();
  await expect.poll(async () => (await grantsOf()).length).toBe(n0 - 1);
  await expect(page.locator('.cl-arrow[data-grant="g3"]')).toHaveCount(0);
});

test("mesh: dragging an arrow's end shows the real arrow, snaps within the radius onto the node's edge, and lets go beyond it", async ({ page }) => {
  await open(page, 6);
  await page.keyboard.press("Control+Shift+Digit3");
  await page.waitForTimeout(900);
  const centre = async (sel: string) => { const b = (await page.locator(sel).first().boundingBox())!; return { x: b.x + b.width / 2, y: b.y + b.height / 2 }; };
  const mid = await centre('.cl[data-view="mesh"] .cl-arrow[data-grant="g3"] .cl-arrow-hit');
  await page.mouse.move(mid.x, mid.y);
  await page.waitForTimeout(300);
  const head = await centre('.cl-arrow[data-grant="g3"] .cl-arrow-handle[data-end="head"]');
  const edge = (await page.locator('.ui-window[data-window-id="n-edge-arm"]').boundingBox())!;
  const live = page.locator(".cl-arrow[data-live]");
  const path = (): Promise<string> => live.locator(".cl-arrow-line").getAttribute("d").then((d) => d ?? "");
  const lastPoint = (d: string): { x: number; y: number } => { const n = d.match(/-?[\d.]+/g)!.map(Number); return { x: n[n.length - 2]!, y: n[n.length - 1]! }; };
  await page.mouse.move(head.x, head.y);
  await page.mouse.down();
  // Free: far from every node, the arrow (line and head) follows the pointer from its other node.
  await page.mouse.move(head.x + 20, head.y + 130, { steps: 8 });
  await expect(live).toHaveCount(1);
  await expect(live).not.toHaveAttribute("data-snapped", "");
  await expect(live.locator(".cl-arrow-head")).toHaveCount(1);
  const free1 = lastPoint(await path());
  await page.mouse.move(head.x - 20, head.y + 150, { steps: 6 });
  const free2 = lastPoint(await path());
  expect(Math.hypot(free2.x - free1.x, free2.y - free1.y)).toBeGreaterThan(20); // the end moves with the pointer
  // Approaching edge-arm: outside the radius it stays free, inside it snaps and the node highlights.
  const zoom = (await page.evaluate(() => (window as unknown as { __tracerClusters: { camera(): { z: number } } }).__tracerClusters.camera().z));
  const outside = 32 / zoom + 24, inside = 32 / zoom - 14;
  const px = edge.x + edge.width / 2;
  await page.mouse.move(px, edge.y + edge.height + outside * zoom, { steps: 8 });
  await expect(live).not.toHaveAttribute("data-snapped", "");
  await page.mouse.move(px, edge.y + edge.height + inside * zoom, { steps: 8 });
  await expect(live).toHaveAttribute("data-snapped", "");
  await expect(page.locator('.ui-window[data-window-id="n-edge-arm"][data-drop]')).toHaveCount(1);
  await page.waitForTimeout(700);
  // Snapped, the arrow ends on the node's edge (its bottom side, the nearest), not at the pointer.
  const end = lastPoint(await path());
  const svgBox = (await page.locator('.cl[data-view="mesh"] .cl-graph-arrows').boundingBox())!;
  const endScreen = { x: svgBox.x + end.x * zoom, y: svgBox.y + end.y * zoom };
  expect(Math.abs(endScreen.y - (edge.y + edge.height))).toBeLessThan(14);
  // Moving away unsnaps.
  await page.mouse.move(edge.x + edge.width + 90, edge.y + edge.height / 2, { steps: 8 }); // open canvas to the right
  await expect(live).not.toHaveAttribute("data-snapped", "");
  await page.mouse.up();
  await page.locator(".ui-confirm-no, .ui-confirm-yes").first().waitFor({ timeout: 3000 }).catch(() => undefined);
});

test("scrolling past the ends of a view never leaves it, and the pill always names the view on screen", async ({ page }) => {
  test.setTimeout(120_000);
  await open(page, 3);
  const pillName = (): Promise<string> => page.evaluate(() => document.querySelector("#capsule-host")?.textContent ?? "");
  const state = (): Promise<{ view: string; name: string }> => page.evaluate(() => {
    const p = (window as unknown as { __tracerClusters: { canvasLock(): { view: string } } }).__tracerClusters;
    return { view: p.canvasLock().view, name: document.querySelector("#capsule-host")?.textContent ?? "" };
  });
  const NAMES: Record<string, string> = { console: "Console", containers: "Containers", mesh: "Mesh", settings: "Settings" };
  await page.mouse.move(640, 400);
  for (const key of ["Control+Shift+Digit1", "Control+Shift+Digit2", "Control+Shift+Digit3", "Control+Shift+Digit4"]) {
    await page.keyboard.press(key);
    await page.waitForTimeout(1300);
    const start = await state();
    for (const dir of [1, -1]) for (let i = 0; i < 10; i++) {
      await page.mouse.wheel(dir * 220, 0);
      await page.waitForTimeout(260);
      const s = await state();
      expect(s.view, `${key} wheel ${dir}`).toBe(start.view);
      expect(s.name, `pill after ${key}`).toBe(NAMES[s.view]);
    }
    await page.waitForTimeout(700);
    const end = await state();
    expect(end.view).toBe(start.view);
    expect(end.name).toBe(NAMES[end.view]);
  }
});

test("container shell: the camera stays, the pill morphs into a floating terminal that resizes with its aspect locked and expands into Console", async ({ page }) => {
  await open(page, 4);
  const cam0 = await probe(page, (p) => p.camera());
  await page.locator('.cl-row[data-name="web-api"]').click();
  await expect(page.locator(".cl-float")).toBeVisible();
  await page.waitForTimeout(700);
  // The session already exists in Console.
  expect((await probe(page, (p) => p.views())).find((v) => v.id === "console")!.windows).toContain("w-shell-web-api");
  expect(await probe(page, (p) => p.camera())).toMatchObject({ cx: cam0.cx, cy: cam0.cy });
  const box0 = (await page.locator(".cl-float").boundingBox())!;
  const aspect0 = box0.width / box0.height;
  // Drag the east edge: the width changes by twice the travel and the aspect holds.
  await page.mouse.move(box0.x + box0.width - 2, box0.y + 120);
  await page.mouse.down();
  await page.mouse.move(box0.x + box0.width + 40, box0.y + 120, { steps: 6 });
  await page.waitForTimeout(150);
  const mid = (await page.locator(".cl-float").boundingBox())!;
  expect(mid.width).toBeGreaterThan(box0.width + 60);
  expect(mid.width / mid.height).toBeCloseTo(aspect0, 1);
  // It stays centred on the pill.
  const pill = (await page.locator("#capsule").boundingBox())!;
  expect(Math.abs(mid.x + mid.width / 2 - (pill.x + pill.width / 2))).toBeLessThan(2);
  await page.mouse.up();
  await expect.poll(async () => (await probe(page, (p) => p.float()))!.cols, { timeout: 4000 }).toBeGreaterThan(48);
  await page.locator('.cl-float [data-action="expand"]').click();
  await expect(page.locator(".cl-float")).toHaveCount(0, { timeout: 4000 });
  await expect.poll(async () => (await probe(page, (p) => p.camera())).z, { timeout: 4000 }).toBeCloseTo(1, 1);
  await expect(page.locator('.ui-window[data-window-id="w-shell-web-api"]')).toBeVisible();
});

test("the palette opens a shell by name from anywhere: in Console the camera flies to it", async ({ page }) => {
  await open(page, 2);
  await expect.poll(async () => (await probe(page, (p) => p.camera())).z, { timeout: 5000 }).toBeGreaterThan(0.9);
  await page.keyboard.press("Control+Shift+K");
  await page.keyboard.type("build");
  await expect(page.getByText("Open shell on build-01")).toBeVisible();
  await expect(page.getByText("arrives later").first()).toBeVisible();
  await page.keyboard.press("Enter");
  await expect(page.locator('.ui-window[data-window-id="w-build-01"]')).toBeVisible({ timeout: 4000 });
  expect((await probe(page, (p) => p.views())).find((v) => v.id === "console")!.windows).toContain("w-build-01");
});

test("the capsule lists the views with their shortcuts", async ({ page }) => {
  await open(page, 3);
  await page.locator("#capsule").click();
  await expect(page.locator(".cl-viewlist")).toContainText("Mesh");
  await expect(page.locator(".cl-viewlist")).toContainText("Ctrl");
  await page.locator('.cl-viewrow[data-view="mesh"]').click();
  await expect.poll(async () => (await probe(page, (p) => p.camera())).cx, { timeout: 4000 }).toBeGreaterThan(1500);
});

test("access by grants: a viewer sees only Console with two hosts; an operator sees all three views", async ({ page }) => {
  await open(page, 5);
  expect((await probe(page, (p) => p.views())).map((v) => v.id)).toEqual(["console", "settings"]);
  expect((await probe(page, (p) => p.views())).find((v) => v.id === "console")!.windows).toHaveLength(2);
  await page.keyboard.press("Control+Shift+K");
  await page.keyboard.type("sign in as");
  await page.getByText("Mockup: sign in as a operator").click();
  await expect.poll(async () => (await probe(page, (p) => p.views())).length).toBe(4);
  await page.evaluate(() => (window as unknown as { __tracerClusters: { setRole(r: string): void } }).__tracerClusters.setRole("new"));
  await expect(page.locator(".cl-empty")).toContainText("No hosts yet");
});

test("structure: a dragged view snaps to the grid, pushes a neighbour aside and never overlaps", async ({ page }) => {
  await open(page, 6);
  const label = (await page.locator('.cl[data-view="containers"] .cl-label').boundingBox())!;
  await page.mouse.move(label.x + 40, label.y + 12);
  await page.mouse.down();
  await page.mouse.move(label.x + 60, label.y - 150, { steps: 6 });
  await page.mouse.move(label.x + 60, label.y - 330, { steps: 8 });
  await page.mouse.up();
  await page.waitForTimeout(1500);
  const views = await probe(page, (p) => p.views());
  for (const v of views) { expect(Math.abs(v.x / 120 - Math.round(v.x / 120))).toBeLessThan(0.02); expect(Math.abs(v.y / 120 - Math.round(v.y / 120))).toBeLessThan(0.02); }
  for (let i = 0; i < views.length; i++) for (let j = i + 1; j < views.length; j++) expect(overlap(views[i]!, views[j]!)).toBe(false);
});

test("structure: a window dragged by its pill lands in another column", async ({ page }) => {
  await open(page, 6);
  const pill = (await page.locator('.ui-window[data-window-id="w-edge-arm"] .ui-window-pill').boundingBox())!;
  const col1 = (await page.locator('.ui-window[data-window-id="w-build-01"]').boundingBox())!;
  await page.mouse.move(pill.x + 30, pill.y + 10);
  await page.mouse.down();
  await page.mouse.move(pill.x - 60, pill.y - 100, { steps: 6 });
  await page.mouse.move(col1.x + 150, col1.y + col1.height - 40, { steps: 8 });
  await expect(page.locator(".cl-slot")).toHaveCount(1);
  await page.mouse.up();
  await expect(page.locator(".cl-slot")).toHaveCount(0, { timeout: 4000 });
  const parent = await page.locator('.ui-window[data-window-id="w-edge-arm"]').evaluate((n) => n.parentElement?.querySelector('[data-window-id="w-build-01"]') !== null);
  expect(parent).toBe(true);
});

async function touchPage(browser: Browser, scene: number): Promise<{ page: Page; touch: (type: "touchStart" | "touchMove" | "touchEnd", pts: Array<{ x: number; y: number }>) => Promise<unknown>; close(): Promise<void> }> {
  const context = await browser.newContext({ baseURL: `http://localhost:${process.env.TRACER_TEST_PORT ?? "4621"}`, viewport: { width: 393, height: 852 }, deviceScaleFactor: 2, hasTouch: true, isMobile: true });
  // These specs test the geometry of the Comfortable phone width (a neighbour peeks in, a gap to tap: a tap at x=371 lands on the
  // slice of the next window, 10 px wide at the screen edge, and so leaves the focused terminal); full width, the
  // default (D191), has its own specs in real/phone.spec.ts.
  await context.addInitScript(() => { try { localStorage.setItem("tracer.window-size.phone", "comfortable"); } catch { /* storage blocked */ } });
  const page = await context.newPage();
  // Gestures, not a look: the Solid theme (see `open`).
  await page.goto(`/?mock=1&proto=clusters&scene=${scene}&theme=ink&bg=soft&look=solid`);
  await expect(page.locator(".cl-mockup")).toBeVisible({ timeout: 20_000 });
  await page.waitForTimeout(900);
  const cdp = await context.newCDPSession(page);
  const touch = (type: "touchStart" | "touchMove" | "touchEnd", pts: Array<{ x: number; y: number }>) =>
    cdp.send("Input.dispatchTouchEvent", { type, touchPoints: pts.map((p, i) => ({ ...p, id: i })) });
  return { page, touch, close: () => context.close() };
}
/** Two fingers (the canvas lock's gesture) travelling from `from` to `to`. */
const swipe2 = async (t: Awaited<ReturnType<typeof touchPage>>, from: { x: number; y: number }, to: { x: number; y: number }, steps = 8): Promise<void> => {
  const at = (k: number, d: number): Array<{ x: number; y: number }> => [{ x: from.x + ((to.x - from.x) * k) / steps - d, y: from.y + ((to.y - from.y) * k) / steps }, { x: from.x + ((to.x - from.x) * k) / steps + d, y: from.y + ((to.y - from.y) * k) / steps }];
  await t.touch("touchStart", at(0, 20));
  for (let i = 1; i <= steps; i++) await t.touch("touchMove", at(i, 20));
  await t.touch("touchEnd", []);
};
const swipe = async (t: Awaited<ReturnType<typeof touchPage>>, from: { x: number; y: number }, to: { x: number; y: number }, steps = 8): Promise<void> => {
  await t.touch("touchStart", [from]);
  for (let i = 1; i <= steps; i++) await t.touch("touchMove", [{ x: from.x + ((to.x - from.x) * i) / steps, y: from.y + ((to.y - from.y) * i) / steps }]);
  await t.touch("touchEnd", []);
};

test("canvas lock on a phone: two fingers move one column at a time, pinch does nothing, the toggle frees the canvas", async ({ browser }) => {
  const t = await touchPage(browser, 3);
  try {
    const { page } = t;
    expect(await probe(page, (p) => p.canvasLock())).toMatchObject({ on: true, index: 0, stops: 3 });
    // One finger never moves windows: it scrolls the terminal it is on.
    await swipe(t, { x: 300, y: 400 }, { x: 120, y: 400 });
    await page.waitForTimeout(400);
    expect((await probe(page, (p) => p.canvasLock())).index).toBe(0);
    await swipe2(t, { x: 210, y: 400 }, { x: 40, y: 400 });
    await expect.poll(async () => (await probe(page, (p) => p.canvasLock())).index).toBe(1);
    await page.waitForTimeout(1600);
    const rested = (await probe(page, (p) => p.camera())).tx;
    await page.waitForTimeout(300);
    expect(Math.abs((await probe(page, (p) => p.camera())).tx - rested)).toBeLessThan(1);
    await swipe2(t, { x: 100, y: 400 }, { x: 330, y: 400 });
    await expect.poll(async () => (await probe(page, (p) => p.canvasLock())).index).toBe(0);
    // The toolbar's previous and next move one window too.
    await page.evaluate(() => document.querySelector<HTMLElement>('[data-cv="next"]')!.click());
    await expect.poll(async () => (await probe(page, (p) => p.canvasLock())).index, { timeout: 4000 }).toBeGreaterThanOrEqual(0);
    // A pinch changes nothing while the canvas is locked.
    const z0 = (await probe(page, (p) => p.camera())).z;
    await t.touch("touchStart", [{ x: 150, y: 400 }, { x: 250, y: 400 }]);
    for (let i = 1; i <= 6; i++) await t.touch("touchMove", [{ x: 150 - i * 2, y: 400 }, { x: 250 + i * 2, y: 400 }]);
    await t.touch("touchEnd", []);
    await page.waitForTimeout(500);
    expect((await probe(page, (p) => p.camera())).z).toBe(z0);
    // The canvas lock toggle frees the canvas where it is (no zoom change), then locks it again.
    await page.evaluate(() => document.querySelector<HTMLElement>('[data-cv="canvas-lock"]')!.click());
    await expect.poll(async () => (await probe(page, (p) => p.canvasLock())).on).toBe(false);
    await page.waitForTimeout(700);
    expect((await probe(page, (p) => p.camera())).z).toBe(z0);
    // The overview is its own control and does zoom out.
    await page.evaluate(() => document.querySelector<HTMLElement>('[data-cv="overview"]')!.click());
    await expect.poll(async () => (await probe(page, (p) => p.camera())).z, { timeout: 4000 }).toBeLessThan(0.7);
    await page.evaluate(() => document.querySelector<HTMLElement>('[data-cv="canvas-lock"]')!.click());
    await expect.poll(async () => (await probe(page, (p) => p.camera())).z, { timeout: 4000 }).toBe(1);
  } finally { await t.close(); }
});

test("canvas lock on a phone: tapping a neighbour that peeks in moves there; two fingers step windows in a column", async ({ browser }) => {
  const t = await touchPage(browser, 3);
  try {
    const { page } = t;
    // The next column peeks in at the right edge.
    await page.touchscreen.tap(368, 500);
    await expect.poll(async () => (await probe(page, (p) => p.canvasLock())).index, { timeout: 4000 }).toBe(1);
    await page.waitForTimeout(800);
    const col = '.cl-col[data-id="c2"]';
    await swipe2(t, { x: 200, y: 600 }, { x: 200, y: 200 }, 10);
    await expect.poll(() => page.locator(col).evaluate((n) => n.scrollTop), { timeout: 3000 }).toBeGreaterThan(20);
    await page.waitForTimeout(900);
    const top = await page.locator(col).evaluate((n) => ({ s: n.scrollTop, starts: [...n.querySelectorAll<HTMLElement>(":scope > .ui-window")].map((w) => w.offsetTop - 14), max: n.scrollHeight - n.clientHeight }));
    expect(top.starts.concat(top.max).some((v) => Math.abs(Math.min(v, top.max) - top.s) < 2)).toBe(true);
  } finally { await t.close(); }
});

test("snap on desktop: wheel and trackpad move between windows and columns, ctrl-wheel does not zoom", async ({ page }) => {
  await page.setViewportSize({ width: 1000, height: 800 });
  await page.goto("/?mock=1&proto=clusters&scene=3&theme=ink&bg=soft");
  await expect(page.locator(".cl-mockup")).toBeVisible({ timeout: 20_000 });
  await page.waitForTimeout(900);
  expect(await probe(page, (p) => p.canvasLock())).toMatchObject({ on: true, index: 0 });
  expect((await probe(page, (p) => p.canvasLock())).stops).toBeGreaterThan(1);
  await page.keyboard.down("Control");
  await page.mouse.move(500, 400);
  await page.mouse.wheel(0, -300);
  await page.keyboard.up("Control");
  await page.waitForTimeout(300);
  expect((await probe(page, (p) => p.camera())).z).toBe(1);
  // Horizontal: one column per gesture.
  await page.mouse.wheel(160, 0);
  await expect.poll(async () => (await probe(page, (p) => p.canvasLock())).index).toBe(1);
  await page.waitForTimeout(500);
  await page.mouse.wheel(-160, 0);
  await expect.poll(async () => (await probe(page, (p) => p.canvasLock())).index).toBe(0);
  // Vertical: the second window of a column.
  await page.waitForTimeout(500);
  const second = page.locator('.cl-col[data-id="c2"]');
  const box = (await second.boundingBox())!;
  await page.mouse.move(box.x + 100, box.y + 200);
  await page.mouse.wheel(0, 120);
  await expect.poll(() => second.evaluate((n) => n.scrollTop), { timeout: 3000 }).toBeGreaterThan(50);
});

test("toolbar: the keyboard row follows terminal focus, the canvas row follows a tap on the canvas, swipes switch and scroll rows", async ({ browser }) => {
  const t = await touchPage(browser, 3);
  try {
    const { page } = t;
    const row = (): Promise<string | null> => page.evaluate(() => document.querySelector("#terminal-screen")!.getAttribute("data-row"));
    // The live terminal has focus: keyboard row, and the canvas row is one snap swipe away.
    await page.touchscreen.tap(200, 500);
    await expect.poll(row).toBe("keys");
    await expect(page.locator("#keytray")).toHaveAttribute("data-rows", "2");
    let tray = (await page.locator("#keytray").boundingBox())!;
    expect(tray.height).toBeGreaterThanOrEqual(44);
    await page.waitForTimeout(700);
    // A swipe down reveals the row above (the canvas row), a swipe up the row below (the key row) again.
    await swipe(t, { x: tray.x + 100, y: tray.y + 12 }, { x: tray.x + 100, y: tray.y + 44 }, 6);
    await expect.poll(row).toBe("canvas");
    await page.waitForTimeout(500);
    await t.touch("touchStart", [{ x: tray.x + 100, y: tray.y + 32 }]);
    for (let i = 1; i <= 7; i++) { await t.touch("touchMove", [{ x: tray.x + 100, y: tray.y + 32 - i * 6 }]); await page.waitForTimeout(40); }
    await t.touch("touchEnd", []);
    await expect.poll(row).toBe("keys");
    await page.waitForTimeout(500);
    await swipe(t, { x: tray.x + 100, y: tray.y + 12 }, { x: tray.x + 100, y: tray.y + 44 }, 6);
    await expect.poll(row).toBe("canvas");
    // Tap empty canvas: the key row goes away altogether.
    await page.touchscreen.tap(371, 400);
    await expect(page.locator("#keytray")).toHaveAttribute("data-rows", "1");
    await page.waitForTimeout(500);
    // Horizontal swipe scrolls the overflowing canvas row.
    await swipe(t, { x: tray.x + 300, y: tray.y + 22 }, { x: tray.x + 100, y: tray.y + 22 }, 8);
    await expect.poll(() => page.evaluate(() => document.querySelector("#keyrow-canvas")!.scrollLeft), { timeout: 3000 }).toBeGreaterThan(40);
  } finally { await t.close(); }
});

test("toolbar: Ctrl latches (tap arms, double tap holds), snap and lock work from the canvas row", async ({ browser }) => {
  const t = await touchPage(browser, 3);
  try {
    const { page } = t;
    await page.touchscreen.tap(200, 500);
    await expect(page.locator("#terminal-screen")).toHaveAttribute("data-row", "keys");
    await page.waitForTimeout(600); // the rows slide for about 240 ms; measure the key once it has stopped
    const ctrl = page.locator('[data-mod="ctrl"]');
    const state = (): Promise<string | null> => ctrl.getAttribute("data-mod-state");
    expect(await state()).toBe("off");
    const box = (await ctrl.boundingBox())!;
    expect(box.height).toBeGreaterThanOrEqual(44);
    await page.touchscreen.tap(box.x + box.width / 2, box.y + box.height / 2);
    await expect.poll(state).toBe("armed");
    await page.waitForTimeout(500);
    await page.touchscreen.tap(box.x + box.width / 2, box.y + box.height / 2);
    await expect.poll(state).toBe("off");
    await page.touchscreen.tap(box.x + box.width / 2, box.y + box.height / 2);
    await page.touchscreen.tap(box.x + box.width / 2, box.y + box.height / 2);
    await expect.poll(state).toBe("locked");
    // Canvas row: snap and lock.
    await page.touchscreen.tap(371, 400);
    await expect(page.locator("#terminal-screen")).toHaveAttribute("data-row", "canvas");
    await page.waitForTimeout(500);
    await page.evaluate(() => document.querySelector<HTMLElement>('[data-cv="input-lock"]')!.click());
    await expect(page.locator('.ui-window[data-active][data-locked]')).toHaveCount(1);
    await expect(page.locator('[data-cv="input-lock"]')).toHaveAttribute("aria-pressed", "true");
    // Locked, the canvas lock and the overview are off limits; unlocking brings them back.
    await page.evaluate(() => document.querySelector<HTMLElement>('[data-cv="overview"]')!.click());
    expect((await probe(page, (p) => p.canvasLock())).on).toBe(true);
    await page.evaluate(() => document.querySelector<HTMLElement>('[data-cv="input-lock"]')!.click());
    await expect(page.locator('.ui-window[data-locked]')).toHaveCount(0);
    await page.evaluate(() => document.querySelector<HTMLElement>('[data-cv="overview"]')!.click());
    await expect.poll(async () => (await probe(page, (p) => p.canvasLock())).on).toBe(false);
  } finally { await t.close(); }
});

test("toolbar: a long press edits it in place (hide with a badge, a tray brings it back, drag reorders), and the layout is the account's until this device overrides it", async ({ browser }) => {
  const t = await touchPage(browser, 3);
  try {
    const { page } = t;
    await page.touchscreen.tap(371, 400);
    await expect(page.locator("#terminal-screen")).toHaveAttribute("data-row", "canvas");
    await page.waitForTimeout(500);
    const tray = (await page.locator("#keytray").boundingBox())!;
    const pt = { x: tray.x + 60, y: tray.y + 22 };
    await t.touch("touchStart", [pt]);
    await page.waitForTimeout(800);
    await t.touch("touchEnd", []);
    await expect(page.locator("#terminal-screen")).toHaveAttribute("data-toolbar-edit", "");
    await expect(page.locator(".keyedit")).toBeVisible();
    // The hide badge removes a control into the tray.
    const count = await page.locator('#keyrow-canvas > button:not([hidden])').count();
    await page.evaluate(() => document.querySelector<HTMLElement>('#keyrow-canvas [data-cv="add"] .keyx')!.click());
    await expect(page.locator('#keyrow-canvas > button:not([hidden])')).toHaveCount(count - 1);
    await expect(page.locator('.keyedit-add')).toHaveCount(1);
    // It is saved as the account's layout, which the server keeps.
    const saved = await page.evaluate(() => fetch("/__mock/account/toolbar").then((r) => r.json()));
    expect(JSON.stringify(saved)).toContain("add");
    await page.locator(".keyedit-add").tap();
    await expect(page.locator('#keyrow-canvas > button:not([hidden])')).toHaveCount(count);
    // Drag the first control to the right: the order changes.
    const first = (await page.locator('#keyrow-canvas > button').first().boundingBox())!;
    const idsBefore = await page.locator('#keyrow-canvas > button').evaluateAll((b) => b.map((n) => (n as HTMLElement).dataset.cv));
    await t.touch("touchStart", [{ x: first.x + 24, y: first.y + 24 }]);
    for (let i = 1; i <= 10; i++) await t.touch("touchMove", [{ x: first.x + 24 + i * 22, y: first.y + 24 }]);
    await t.touch("touchEnd", []);
    await page.waitForTimeout(700);
    const idsAfter = await page.locator('#keyrow-canvas > button').evaluateAll((b) => b.map((n) => (n as HTMLElement).dataset.cv));

    expect(idsAfter[0]).not.toBe(idsBefore[0]);
    await page.locator(".keyedit-done").tap();
    await expect(page.locator("#terminal-screen")).not.toHaveAttribute("data-toolbar-edit", "");
    // Settings, Toolbar: the layout comes from the account until "Customise for this device".
    await paletteOpen(page, "Terminal › Typing", "terminal.typing");
    await expect(page.locator(".ui-ts-tag")).toHaveText("Account layout");
    await page.getByRole("button", { name: "Customise for this device" }).click();
    await expect(page.locator(".ui-ts-tag")).toHaveText("This device");
    await page.getByRole("button", { name: "Use account layout" }).click();
    await expect(page.locator(".ui-ts-tag")).toHaveText("Account layout");
  } finally { await t.close(); }
});

test("shortcuts: Settings lists the registry, a row rebinds with a conflict warning, and the new key works everywhere", async ({ page }) => {
  await open(page, 3);
  await paletteOpen(page, "Terminal › Typing", "terminal.typing");
  await expect(page.locator(".ui-ss-row")).not.toHaveCount(0);
  await page.waitForTimeout(1600);
  await expect(page.locator('.ui-ss-row[data-id="canvas-lock"]')).toContainText("G");
  // A key the terminal needs is refused.
  await page.locator('.ui-ss-row[data-id="canvas-lock"] .ui-ss-main').click();
  await page.keyboard.press("Control+c");
  await expect(page.locator(".ui-ss-warn")).toContainText("terminal needs");
  await page.getByRole("button", { name: "Cancel" }).click();
  // A key another action has can be swapped.
  await page.locator('.ui-ss-row[data-id="canvas-lock"] .ui-ss-main').click();
  await page.keyboard.press("Control+Shift+L");
  await expect(page.locator(".ui-ss-warn")).toContainText("Input lock");
  await page.getByRole("button", { name: "Swap" }).click();
  await expect(page.locator('.ui-ss-row[data-id="input-lock"]')).toContainText("G");
  // A free combination saves and the palette shows it.
  await page.locator('.ui-ss-row[data-id="canvas-lock"] .ui-ss-main').click();
  await page.keyboard.press("Control+Shift+J");
  await expect(page.locator('.ui-ss-row[data-id="canvas-lock"]')).toContainText("J");
  await page.keyboard.press("Escape");
  const before = (await probe(page, (p) => p.canvasLock())).on;
  await page.keyboard.press("Control+Shift+J");
  await expect.poll(async () => (await probe(page, (p) => p.canvasLock())).on).toBe(!before);
});

test("the top pill: a horizontal swipe steps to the next view and the canvas lock re-engages", async ({ browser }) => {
  const t = await touchPage(browser, 3);
  try {
    const { page } = t;
    const pill = (await page.locator("#capsule").boundingBox())!;
    await swipe(t, { x: pill.x + pill.width - 30, y: pill.y + 20 }, { x: pill.x + 40, y: pill.y + 20 }, 6);
    await expect.poll(async () => (await probe(page, (p) => p.canvasLock())).view, { timeout: 4000 }).toBe("containers");
    expect((await probe(page, (p) => p.canvasLock())).on).toBe(true);
    await expect(page.locator("#capsule-host")).toHaveText("Containers", { timeout: 3000 });
    // A short drag springs back.
    await swipe(t, { x: pill.x + 200, y: pill.y + 20 }, { x: pill.x + 180, y: pill.y + 20 }, 4);
    await page.waitForTimeout(700);
    expect((await probe(page, (p) => p.canvasLock())).view).toBe("containers");
  } finally { await t.close(); }
});

test("motion rule: the work of a view jump, a window step and a column step finishes inside one frame, and keys do not animate", async ({ page }) => {
  await open(page, 3);
  const costs = await page.evaluate(async () => {
    const api = (window as unknown as { __tracerClusters: { flyView(id: string): void; camera(): { z: number; cx: number } } }).__tracerClusters;
    const time = (run: () => void): number => { const t0 = performance.now(); run(); return performance.now() - t0; };
    const out: Record<string, number> = {};
    out.viewJump = time(() => api.flyView("containers"));
    await new Promise((r) => setTimeout(r, 1400));
    out.windowStep = time(() => document.querySelector<HTMLElement>('[data-cv="next"]')!.click());
    await new Promise((r) => setTimeout(r, 600));
    out.canvasLockToggle = time(() => document.querySelector<HTMLElement>('[data-cv="canvas-lock"]')!.click());
    await new Promise((r) => setTimeout(r, 1400));
    // A keyboard view jump uses the short flight: it has landed well inside 400 ms. The view chord is a physical digit key (D222):
    // ⌘3 on a Mac, Ctrl+Shift+3 elsewhere.
    const before = api.camera().cx;
    const mac = /mac|iphone|ipad/i.test(navigator.platform);
    window.dispatchEvent(new KeyboardEvent("keydown", { key: "3", code: "Digit3", metaKey: mac, ctrlKey: !mac, shiftKey: !mac, bubbles: true, cancelable: true }));
    await new Promise((r) => setTimeout(r, 450));
    out.keyJumpMoved = Math.abs(api.camera().cx - before);
    return out;
  });
  console.log(`MOTION_COST ${JSON.stringify(costs)}`);
  expect(costs.viewJump).toBeLessThan(16);
  expect(costs.windowStep).toBeLessThan(16);
  expect(costs.canvasLockToggle).toBeLessThan(16);
  expect(costs.keyJumpMoved).toBeGreaterThan(500);
});

test("canvas backdrop: the dots stay on world multiples, a layer is a bounded box (only the screen's tiles are rastered) at any zoom, and at most two exist while one fades into the next", async ({ page }) => {
  await open(page, 1);
  const api = "__tracerClusters";
  const setCam = (x: number, y: number, z: number): Promise<void> => page.evaluate(([name, a, b, c]) => (window as unknown as Record<string, { setCamera(x: number, y: number, z: number): void }>)[name as string]!.setCamera(a as number, b as number, c as number), [api, x, y, z] as const);
  const read = (): Promise<{ shown: Array<{ k: number; opacity: number; w: number; h: number; dotX: number; spacing: number }>; tx: number; z: number; vw: number; vh: number }> => page.evaluate(() => {
    const cam = (window as unknown as Record<string, { camera(): { tx: number; ty: number; z: number } }>).__tracerClusters!.camera();
    const stage = document.querySelector<HTMLElement>(".ui-canvas-backdrop")!.getBoundingClientRect();
    const shown = [...document.querySelectorAll<HTMLElement>(".ui-canvas-backdrop-layer")].filter((l) => !l.hidden).map((l) => {
      const spacing = Number.parseFloat(l.style.backgroundSize);
      const m = /translate3d\(([-\d.e]+)px/.exec(l.style.transform);
      return { k: Number(l.dataset.level), opacity: Number(l.style.opacity), w: l.offsetWidth, h: l.offsetHeight, dotX: (m ? Number(m[1]) : 0) + spacing / 2, spacing };
    });
    const origin = document.querySelector<HTMLElement>(".cl-viewport")!.getBoundingClientRect().left - stage.left; // the canvas area's offset inside the backdrop
    return { shown, tx: cam.tx + origin, z: cam.z, vw: stage.width, vh: stage.height };
  });
  for (const [x, z] of [[2000, 1], [2037, 1], [2000, 0.6], [2000, 0.25], [9000, 0.08]] as const) {
    await setCam(x, 1000, z);
    const r = await read();
    expect(r.shown.length, `layers at z=${z}`).toBeLessThanOrEqual(2);
    for (const l of r.shown) {
      // One screen scaled to cover it when the layer is shown at 0.6 of its painted zoom, plus a tile of margin on each side:
      // never the world, whatever the zoom.
      expect(l.w).toBeLessThanOrEqual(r.vw / 0.6 + 2 * l.spacing + 1);
      expect(l.h).toBeLessThanOrEqual(r.vh / 0.6 + 2 * l.spacing + 1);
      // A dot sits at a world multiple of this level's gap: (screen x - camera origin) / zoom is a multiple of gap * 2^k.
      const step = 22 * 2 ** l.k;
      const world = (l.dotX - r.tx) / r.z;
      const off = ((world / step) % 1 + 1) % 1;
      expect(Math.min(off, 1 - off) * step, `dot phase at z=${z} level ${l.k}`).toBeLessThan(0.05);
    }
  }
  await setCam(2000, 1000, 1);
  expect((await read()).shown.map((l) => l.k)).toEqual([0]);
  await setCam(2000, 1000, 0.25);
  const far = (await read()).shown;
  expect(far.map((l) => l.k).sort()).toEqual([1]); // only the sparser one: the denser has faded away and holds nothing
});

test("toolbar: the row stack follows the finger one to one (a swipe down moves it down and reveals the canvas row)", async ({ browser }) => {
  const t = await touchPage(browser, 3);
  try {
    const { page } = t;
    await page.touchscreen.tap(200, 500); // a terminal has focus: the key row shows, the canvas row is above it
    await expect(page.locator("#terminal-screen")).toHaveAttribute("data-row", "keys");
    await page.waitForTimeout(900);
    const tray = (await page.locator("#keytray").boundingBox())!;
    const offset = (): Promise<number> => page.evaluate(() => Number(/-?[\d.]+/.exec(document.querySelector<HTMLElement>("#keyrows")!.style.transform || "0")?.[0] ?? 0));
    const rowH = await page.evaluate(() => document.querySelector<HTMLElement>("#keyrow-keys")!.offsetHeight);
    await t.touch("touchStart", [{ x: tray.x + 100, y: tray.y + 12 }]);
    const seen: number[] = [];
    for (let i = 1; i <= 7; i++) { await t.touch("touchMove", [{ x: tray.x + 100, y: tray.y + 12 + i * 6 }]); await page.waitForTimeout(40); seen.push(await offset()); }
    // After the direction locks, the stack is below where it started (nearer the canvas row) and keeps moving with the finger.
    expect(seen[6]!).toBeGreaterThan(-rowH + 25);
    expect(seen[6]!).toBeGreaterThan(seen[3]!);
    await t.touch("touchEnd", []);
    await expect(page.locator("#terminal-screen")).toHaveAttribute("data-row", "canvas");
  } finally { await t.close(); }
});

test("a pointer split fades the new window in over 150 ms and draws no liquid layer; the other windows only snap or glide", async ({ page }) => {
  await open(page, 3);
  await page.evaluate(() => {
    const w = window as unknown as { __splitFade: number[]; __splitGoo: number };
    w.__splitFade = []; w.__splitGoo = 0;
    new MutationObserver(() => {
      if (document.querySelector(".cl-goo")) w.__splitGoo++;
      for (const a of document.getAnimations()) {
        const keys = (a.effect as KeyframeEffect | null)?.getKeyframes() ?? [];
        if (keys.length === 2 && "opacity" in keys[0]! && !w.__splitFade.includes(a.effect!.getTiming().duration as number)) w.__splitFade.push(a.effect!.getTiming().duration as number);
      }
    }).observe(document.body, { subtree: true, childList: true, attributes: true });
  });
  await page.locator('.ui-window[data-window-id="w-studio-mac"] [data-action="split-down"]').evaluate((b) => (b as HTMLElement).click()); // off screen at the 1.1 default: three windows no longer fit side by side
  await expect.poll(() => page.evaluate(() => (window as unknown as { __splitFade: number[] }).__splitFade), { timeout: 3000 }).toContain(150); // declared duration, not a measured one
  expect(await page.evaluate(() => (window as unknown as { __splitGoo: number }).__splitGoo)).toBe(0);
  await expect.poll(() => page.evaluate(() => document.getAnimations().filter((a) => a.playState === "running" && a.effect?.getComputedTiming().iterations !== Infinity).length), { timeout: 3000 }).toBe(0); // loops that run while a state lasts (a blinking caret) are not the split
  expect(await page.locator(".cl-goo").count()).toBe(0);
});

test("closing re-tiles: the remaining window of a column takes the whole column (bottom closed, then top closed)", async ({ page }) => {
  for (const [closeId, keepId] of [["w-edge-arm", "w-nix-cache"], ["w-nix-cache", "w-edge-arm"]] as const) {
    await open(page, 3);
    const colH = await page.locator(`.ui-window[data-window-id="${keepId}"]`).evaluate((n) => (n.parentElement as HTMLElement).clientHeight - 28);
    const half = await page.locator(`.ui-window[data-window-id="${keepId}"]`).evaluate((n) => n.getBoundingClientRect().height);
    expect(half).toBeLessThan(colH * 0.75); // the pair is stacked, one is not the whole column
    await page.locator(`.ui-window[data-window-id="${closeId}"] [data-action="close"]`).click();
    await expect(page.locator(`.ui-window[data-window-id="${closeId}"]`)).toHaveCount(0);
    await expect.poll(() => page.locator(`.ui-window[data-window-id="${keepId}"]`).evaluate((n) => Math.abs(n.getBoundingClientRect().height - ((n.parentElement as HTMLElement).clientHeight - 28))), { timeout: 4000 }).toBeLessThan(2);
    // No leftover inline height, and no transform left behind once it has settled.
    await expect.poll(() => page.locator(`.ui-window[data-window-id="${keepId}"]`).evaluate((n) => (n as HTMLElement).style.transform)).toBe("");
  }
});

test("closing the last window of a column removes the column, its neighbours close the gap, and the canvas lock re-snaps", async ({ page }) => {
  await open(page, 3);
  const stopsBefore = (await probe(page, (p) => p.canvasLock())).stops;
  const colCount = await page.locator('.cl[data-view="console"] .cl-col').count();
  const rightBefore = (await page.locator('.ui-window[data-window-id="w-nix-cache"]').boundingBox())!.x;
  await page.locator('.ui-window[data-window-id="w-build-01"] [data-action="close"]').click();
  await expect(page.locator('.cl[data-view="console"] .cl-col')).toHaveCount(colCount - 1);
  // The column to its right slides left into the gap, on the camera's re-snapped stop.
  await expect.poll(async () => (await page.locator('.ui-window[data-window-id="w-nix-cache"]').boundingBox())!.x, { timeout: 4000 }).toBeLessThan(rightBefore - 100);
  const after = await probe(page, (p) => p.canvasLock());
  expect(after.on).toBe(true);
  expect(after.stops).toBeLessThanOrEqual(stopsBefore);
  // A column with one window has it fill the column.
  const fills = await page.locator('.cl[data-view="console"] .cl-col').evaluateAll((cols) => cols.map((c) => { const wins = [...c.querySelectorAll<HTMLElement>(":scope > .ui-window")]; if (wins.length > 1) return 0; /* a stacked pair scrolls by design */ const used = wins.reduce((s, w) => s + w.getBoundingClientRect().height, 0) + (wins.length - 1) * 12; return Math.abs(used - ((c as HTMLElement).clientHeight - 28)); }));
  for (const f of fills) expect(f).toBeLessThan(2);
});

/** The windows of Settings in rows (#304), in order: one row per component, one window per group; the administrator rows come from the owner's map. */
const SETTINGS_WINDOWS = {
  appearance: ["s-appearance-themes", "s-appearance-layout"],
  terminal: ["s-terminal-typing", "s-terminal-hosts", "s-terminal-scrollback", "s-terminal-multiplexer"],
  you: ["s-you-profile", "s-you-passkeys", "s-you-recovery", "s-you-apps", "s-you-devices"],
  machines: ["s-machines-new-machines", "s-machines-updates"],
  mesh: ["s-mesh-keys", "s-mesh-names", "s-mesh-access", "s-mesh-connections"],
  sharing: ["s-sharing-published-services", "s-sharing-certificates"],
  about: ["s-about-version", "s-about-licences"],
};
const SETTINGS_OPERATOR = [...SETTINGS_WINDOWS.appearance, ...SETTINGS_WINDOWS.terminal, ...SETTINGS_WINDOWS.you, ...SETTINGS_WINDOWS.machines, ...SETTINGS_WINDOWS.mesh, ...SETTINGS_WINDOWS.sharing, ...SETTINGS_WINDOWS.about];
const SETTINGS_VIEWER = [...SETTINGS_WINDOWS.appearance, ...SETTINGS_WINDOWS.terminal, ...SETTINGS_WINDOWS.you, ...SETTINGS_WINDOWS.about];

test("settings is a view: a gear after a divider, a row of windows for each component, administrator rows only for operators, nothing modal", async ({ page }) => {
  await open(page, 1);
  const sections = async (): Promise<string[]> => (await probe(page, (p) => p.views())).find((v) => v.id === "settings")!.windows;
  // The windows come in the order of the table: components top to bottom, the groups of each from the left (the order the probe lists the columns in is the track order, so compare as sets).
  expect([...(await sections())].sort()).toEqual([...SETTINGS_OPERATOR].sort());
  // The sidebar lists it last, after a divider; the gear in the sidebar footer flies there.
  await page.locator("#sidebar-toggle").click();
  await expect(page.locator('#tree .bm-sec[data-id="view:settings"].cl-divided')).toHaveCount(1);
  await page.locator(".ui-sidebar-foot .ui-sidebar-settings").click();
  // The mockup opens on the Settings view, so the view name alone is true before the gear has done anything; the fly that the gear
  // starts turns the snap on a moment later (a probe sees on=false at the click and on=true 400 ms after). Wait for both together.
  await expect.poll(async () => { const lock = await probe(page, (p) => p.canvasLock()); return `${lock.view}:${lock.on}`; }, { timeout: 4000 }).toBe("settings:true");
  await expect(page.locator(".ui-settings")).toHaveCount(0); // the overlay shell is gone
  // The palette goes straight to a group's window.
  await paletteOpen(page, "You › Devices", "you.devices");
  await expect(page.locator('.ui-window[data-window-id="s-you-devices"][data-active]')).toHaveCount(1, { timeout: 4000 });
  // The sidebar is a layer over the canvas (it no longer docks), so it is closed before reaching under it.
  await page.locator("#sidebar-toggle").click();
  // Appearance applies live: choosing a theme repaints at once.
  await page.evaluate(() => (window as unknown as { __tracerClusters: { openSettings(s: string): void } }).__tracerClusters.openSettings("appearance"));
  await page.locator('.ui-window[data-window-id="s-appearance-themes"] .cl-colour-dot[data-id="ink"]').click();
  await expect(page.locator("html")).toHaveAttribute("data-theme", "ink");
  // Viewers get no administrator rows.
  await page.evaluate(() => (window as unknown as { __tracerClusters: { setRole(r: string): void } }).__tracerClusters.setRole("viewer"));
  await expect.poll(async () => [...(await sections())].sort(), { timeout: 4000 }).toEqual([...SETTINGS_VIEWER].sort());
});

test("devices: the name edits in place, a sign-out asks first, and a device switch offers to continue once", async ({ page }) => {
  await open(page, 1);
  await page.evaluate(() => (window as unknown as { __tracerClusters: { openSettings(s: string): void } }).__tracerClusters.openSettings("you.devices"));
  await page.waitForTimeout(1600);
  const row = page.locator('.ui-window[data-window-id="s-you-devices"] .ui-sp-device').nth(1);
  const name = row.locator(".ui-sp-name");
  await name.fill("Studio MacBook");
  await name.press("Enter");
  await expect(page.locator(".ui-toast", { hasText: "Renamed" })).toContainText("Renamed to Studio MacBook");
  await expect(row.locator(".ui-sp-kind svg")).toHaveCount(1);
  const before = await page.locator('.ui-window[data-window-id="s-you-devices"] .ui-sp-device').count();
  await row.locator('[aria-label="Sign out this device"]').click();
  // The confirmation says what happens in plain words, and its two buttons carry their names.
  const tip = page.locator(".ui-confirm-tip");
  await expect(tip.locator(".ui-confirm-tip-message")).toContainText(/^Sign out .+\?$/);
  await expect(tip.locator(".ui-confirm-tip-detail")).toHaveText("That device will be signed out and will need your passkey to sign in again.");
  await expect(tip.locator(".ui-confirm-yes")).toHaveText("Sign out device");
  await expect(tip.locator(".ui-confirm-no")).toHaveText("Keep signed in");
  await page.locator(".ui-confirm-yes").click();
  await expect(page.locator('.ui-window[data-window-id="s-you-devices"] .ui-sp-device')).toHaveCount(before - 1);
  await page.keyboard.press("Control+Shift+K");
  await page.keyboard.type("simulate device switch");
  await page.keyboard.press("Enter");
  await expect(page.locator(".cl-continue[data-open='true']")).toContainText("Continue from");
  await expect(page.locator(".cl-continue")).toHaveCount(0, { timeout: 12_000 }); // it fades on its own
});

async function sharedPair(browser: Browser, publish: boolean): Promise<{ kayg: Page; asha: Page; close(): Promise<void> }> {
  const context = await browser.newContext({ baseURL: `http://localhost:${process.env.TRACER_TEST_PORT ?? "4621"}`, viewport: { width: 1440, height: 900 } });
  await context.request.post("/__mock/reset").catch(() => undefined);
  const kayg = await context.newPage();
  await open(kayg, 7);
  // Share the Incident view with asha from the palette.
  await kayg.keyboard.press("Control+Shift+K");
  await kayg.keyboard.type("share layout");
  await kayg.keyboard.press("Enter");
  await expect(kayg.locator(".cl-share")).toBeVisible();
  await expect(kayg.locator('.cl-share-chip[data-view="incident"]')).toHaveAttribute("aria-pressed", "true");
  await expect(kayg.locator(".cl-share-send")).toBeDisabled();
  await kayg.locator(".cl-share .ui-chip-text").pressSequentially("asha"); // a name that matches becomes a chip as soon as it is unambiguous
  await expect(kayg.locator(".cl-share .ui-chip", { hasText: "asha" })).toHaveCount(1);
  await expect(kayg.locator(".cl-share-note")).toHaveText("They get their own copy. Windows connect with their access.");
  if (publish) await kayg.locator(".cl-share-publish").click();
  await kayg.locator(".cl-share-send").click();
  await expect(kayg.locator(".ui-toast", { hasText: "Shared Incident with asha" })).toHaveCount(1);
  const asha = await context.newPage();
  await open(asha, 5, "&role=asha");
  return { kayg, asha, close: () => context.close() };
}

test("sharing: the dialog sends a view; the recipient gets their own copy named after the sender, with no-access windows, and nothing is replaced", async ({ browser }) => {
  const pair = await sharedPair(browser, false);
  try {
    const { asha } = pair;
    await expect.poll(async () => (await probe(asha, (p) => p.views())).map((v) => v.id), { timeout: 6000 }).toContain("incident-from-kayg-sh1");
    const views = await probe(asha, (p) => p.views());
    expect(views.find((v) => v.id === "console")!.windows).toHaveLength(2); // her own view is untouched
    expect(views.find((v) => v.id === "incident-from-kayg-sh1")!.name).toBe("Incident (from kayg)");
    const ids = views.map((v) => v.id);
    expect(ids.indexOf("settings")).toBe(ids.length - 1); // Settings stays last
    await expect(asha.locator(".ui-toast", { hasText: "kayg shared Incident" })).toHaveCount(1);
    // At rest, not mid-glide: Settings slides to make room for the copy, and a snapshot taken while it moves overlaps.
    await expect.poll(async () => {
      const now = await probe(asha, (p) => p.views());
      return now.flatMap((a, i) => now.slice(i + 1).map((b) => overlap(a, b))).some(Boolean);
    }, { timeout: 4000 }).toBe(false);
    // The camera flew to it, locked on.
    await expect.poll(async () => (await probe(asha, (p) => p.canvasLock())).view, { timeout: 4000 }).toBe("incident-from-kayg-sh1");
    // edge-arm is outside her grants: a calm explanation, not an error.
    const blocked = asha.locator('.ui-window[data-window-id$=":i-edge-arm"]');
    await expect(blocked).toContainText("No access");
    await expect(blocked).toContainText("You do not have access to edge-arm");
    await expect(asha.locator('.ui-window[data-window-id$=":i-build-01"] .terminal-host, .ui-window[data-window-id$=":i-build-01"] .canvas-preview')).toHaveCount(1);
    // It is her copy: editable (close is there).
    await expect(asha.locator('.ui-window[data-window-id$=":i-build-01"] [data-action="close"]')).toHaveCount(1);
  } finally { await pair.close(); }
});

test("team layouts: followers see a marker and a read-only copy that follows the publisher live, until they unlink it", async ({ browser }) => {
  const pair = await sharedPair(browser, true);
  try {
    const { kayg, asha } = pair;
    const id = "incident-from-kayg-sh1";
    await expect.poll(async () => (await probe(asha, (p) => p.views())).map((v) => v.id), { timeout: 6000 }).toContain(id);
    await expect.poll(async () => (await probe(asha, (p) => p.canvasLock())).view, { timeout: 4000 }).toBe(id);
    await expect(asha.locator(".cl-unlink")).toBeVisible();
    await expect(asha.locator("#capsule")).toContainText("team");
    await expect(asha.locator(`.cl[data-view="${id}"] .cl-team`)).toHaveCount(1);
    await expect(asha.locator(`.cl[data-view="${id}"] [data-action="close"], .cl[data-view="${id}"] [data-action^="split"]`)).toHaveCount(0); // read-only
    const colOf = (page: Page, suffix: string): Promise<string | null> => page.locator(`.ui-window[data-window-id$="${suffix}"]`).evaluate((n) => n.parentElement?.dataset.id ?? null);
    expect(await colOf(asha, ":i-logs")).toBe("i2");
    // The publisher moves the log window into the first column; the follower's copy follows, on its own.
    await kayg.locator('.ui-window[data-window-id="i-logs"] .ui-window-pill').scrollIntoViewIfNeeded();
    const pill = (await kayg.locator('.ui-window[data-window-id="i-logs"] .ui-window-pill').boundingBox())!;
    const target = (await kayg.locator('.ui-window[data-window-id="i-build-01"]').boundingBox())!;
    await kayg.mouse.move(pill.x + 30, pill.y + 10);
    await kayg.mouse.down();
    await kayg.mouse.move(pill.x - 60, pill.y - 40, { steps: 6 });
    await kayg.mouse.move(target.x + 150, target.y + target.height - 40, { steps: 8 });
    await kayg.mouse.up();
    await expect.poll(() => colOf(asha, ":i-logs"), { timeout: 8000 }).toBe("i1");
    // She cannot edit it until she unlinks; then it is hers.
    await asha.locator(".cl-unlink").click();
    await expect(asha.locator(".cl-unlink")).toBeHidden();
    await expect(asha.locator(`.cl[data-view="${id}"] .cl-team`)).toHaveCount(0);
    await expect(asha.locator('.ui-window[data-window-id$=":i-build-01"] [data-action="close"]')).toHaveCount(1);
  } finally { await pair.close(); }
});

test("a restarted mock never strands an open preview tab: an unknown session cookie gets a fresh mock session", async ({ page, context }) => {
  await open(page, 1);
  await context.clearCookies(); // what a restart does to a tab: its cookie is no longer known
  const status = await page.evaluate(() => fetch("/auth/session", { method: "POST", headers: { "Content-Type": "application/json" }, body: "{}", credentials: "same-origin" }).then((r) => r.status));
  expect(status).toBe(200);
});

/**
 * Descenders: the font's full content area (ascent + descent, from the canvas text metrics of the element's own
 * computed font, so it holds for any face) must fit inside every box that clips the text, up to and including
 * the pill itself. A line box shorter than the content area clips the descender of g, j, p, q and y.
 * Covers the window pill, a Mesh node pill, the view label and the top pill.
 */
const GLYPHS = "gjpqy";
async function glyphFit(page: Page, selector: string): Promise<{ selector: string; slack: number; ancestor: string }> {
  return page.evaluate(({ selector: sel, text }) => {
    const target = document.querySelector<HTMLElement>(sel);
    if (!target) throw new Error(`no ${sel}`);
    target.textContent = text;
    const style = getComputedStyle(target);
    const ctx = document.createElement("canvas").getContext("2d")!;
    ctx.font = `${style.fontStyle} ${style.fontWeight} ${style.fontSize} ${style.fontFamily}`;
    const m = ctx.measureText(text);
    const need = m.fontBoundingBoxAscent + m.fontBoundingBoxDescent;
    let worst = Infinity, who = "";
    for (let n: HTMLElement | null = target; n; n = n.parentElement) {
      const s = getComputedStyle(n);
      const pill = n.classList.contains("ui-window-pill") || n.classList.contains("cl-label") || n.id === "capsule";
      if (pill || s.overflowY !== "visible") {
        const have = n.clientHeight - (pill ? parseFloat(s.paddingTop) + parseFloat(s.paddingBottom) : 0);
        if (have - need < worst) { worst = have - need; who = n.className.toString() || n.tagName; }
      }
      if (pill) break;
    }
    return { selector: sel, slack: worst, ancestor: who };
  }, { selector, text: GLYPHS });
}

test("descenders: g j p q y fit inside the window pill, a Mesh node pill, the view label and the top pill", async ({ page }) => {
  await open(page, 1);
  for (const sel of [".cl-label-name", "#capsule-host", ".ui-window-host"]) {
    const r = await glyphFit(page, sel);
    expect(r.slack, `${sel} clipped by ${r.ancestor}`).toBeGreaterThanOrEqual(0);
  }
  await open(page, 6);
  const node = await glyphFit(page, '.ui-window[aria-label$="node"] .ui-window-host');
  expect(node.slack, `node pill clipped by ${node.ancestor}`).toBeGreaterThanOrEqual(0);
});

test("the window lock sits at the exact centre of its window and the title pill yields", async ({ page }) => {
  await open(page, 1);
  // Mesh node cards share the window material but do not control terminal input.
  // Keep the strict lock geometry checks on the Console's terminal windows.
  const centreOff = (): Promise<number[]> => page.evaluate(() => [...document.querySelectorAll<HTMLElement>('.cl[data-view="console"] .ui-window')].map((w) => {
    const l = w.querySelector<HTMLElement>(".ui-window-lock")!.getBoundingClientRect(), r = w.getBoundingClientRect();
    return r.width === 0 || l.width === 0 ? 0 : Math.abs((l.left + l.width / 2) - (r.left + r.width / 2)) + (Math.abs(l.width - 44 * (parseFloat(getComputedStyle(document.documentElement).fontSize) / 16) * (r.width / w.offsetWidth)) > 1 ? 1000 : 0);
  }));
  const ok = async (label: string): Promise<void> => { for (const d of await centreOff()) expect(d, label).toBeLessThanOrEqual(0.5); };
  await ok("at rest");
  const win = page.locator(".ui-window").first();
  const box = (await win.boundingBox())!;
  await page.mouse.move(box.x + box.width / 2, box.y + 6);
  await page.waitForTimeout(250);
  await ok("hover near the top edge");
  await page.evaluate(() => { document.querySelector(".ui-window .ui-window-host")!.textContent = "an-extremely-long-host-name-that-wants-the-whole-header.example.internal"; });
  await page.waitForTimeout(100);
  await ok("long title");
  const geo = await page.evaluate(() => {
    const w = document.querySelector(".ui-window")!;
    return { pillRight: w.querySelector(".ui-window-pill")!.getBoundingClientRect().right, lockLeft: w.querySelector(".ui-window-lock")!.getBoundingClientRect().left + 11 };
  });
  expect(geo.pillRight).toBeLessThanOrEqual(geo.lockLeft + 11);
  await page.setViewportSize({ width: 900, height: 700 });
  await page.waitForTimeout(500);
  await ok("after resize");
  await page.keyboard.press("Control+Shift+G");
  await page.waitForTimeout(400);
  await ok("after the canvas lock changes");
});

test("toolbar rows snap: a short drag springs back, a longer one commits, and the stack never rests between rows", async ({ browser }) => {
  const t = await touchPage(browser, 3);
  try {
    const { page } = t;
    await page.touchscreen.tap(200, 500); // a terminal has focus: both rows exist, the key row shows
    await expect(page.locator("#keytray")).toHaveAttribute("data-rows", "2");
    await page.waitForTimeout(900);
    const offset = (): Promise<number> => page.evaluate(() => Number(/-?[\d.]+/.exec(document.querySelector<HTMLElement>("#keyrows")!.style.transform || "0")?.[0] ?? 0));
    const rowH = await page.evaluate(() => document.querySelector<HTMLElement>("#keyrow-keys")!.offsetHeight);
    const tray = (await page.locator("#keytray").boundingBox())!;
    const drag = async (dy: number): Promise<void> => {
      await t.touch("touchStart", [{ x: tray.x + 100, y: tray.y + 32 }]);
      for (let i = 1; i <= 6; i++) { await t.touch("touchMove", [{ x: tray.x + 100, y: tray.y + 32 + (dy * i) / 6 }]); await page.waitForTimeout(60); }
      await page.waitForTimeout(250); // the finger rests: no flick
      await t.touch("touchEnd", []);
      await page.waitForTimeout(900);
    };
    const atKeys = async (): Promise<boolean> => Math.abs((await offset()) + rowH) < 1;
    const atCanvas = async (): Promise<boolean> => Math.abs(await offset()) < 1;
    expect(await atKeys()).toBe(true);
    await drag(rowH * 0.25); // a short pull down springs back to the key row
    expect(await atKeys()).toBe(true);
    await drag(rowH * 0.8); // most of a row commits to the canvas row, and it rests exactly there
    expect(await atCanvas()).toBe(true);
    await drag(-rowH * 0.25);
    expect(await atCanvas()).toBe(true);
    await drag(-rowH * 0.8);
    expect(await atKeys()).toBe(true);
    // Never between rows: a mid-drag release always ends on one of the two.
    for (const dy of [0.4, 0.6, -0.45, -0.55]) { await drag(rowH * dy); expect((await atKeys()) || (await atCanvas()), `rest after a ${dy} row drag`).toBe(true); }
  } finally { await t.close(); }
});

test("window header actions are one pill: as tall as the title pill, on its line, with touch targets of 44 px", async ({ browser, page }) => {
  await page.setViewportSize({ width: 1280, height: 800 });
  await page.goto("/?mock=1&proto=clusters&scene=3&theme=ink&bg=soft");
  await expect(page.locator(".cl-mockup")).toBeVisible({ timeout: 20_000 });
  await page.waitForTimeout(1500);
  const geometry = (pg: Page, id: string) => pg.evaluate((windowId) => {
    const w = document.querySelector(`.ui-window[data-window-id="${windowId}"]`)!;
    const a = w.querySelector(".ui-window-actions")!.getBoundingClientRect(), t = w.querySelector(".ui-window-pill")!.getBoundingClientRect();
    const buttons = [...w.querySelectorAll<HTMLElement>(".ui-window-action:not(.ui-window-more)")].map((b) => b.dataset.action);
    const gaps = [...w.querySelectorAll(".ui-window-action:not(.ui-window-more)")].map((b) => b.getBoundingClientRect()).map((r, i, all) => (i ? r.left - all[i - 1]!.right : 0)).slice(1);
    return { aTop: a.top, aH: a.height, tTop: t.top, tH: t.height, buttons, gaps, tip: [...w.querySelectorAll<HTMLElement>(".ui-window-action:not(.ui-window-more)")].map((b) => b.dataset.tip) };
  }, id);
  const d = await geometry(page, "w-nix-cache");
  expect(d.buttons).toEqual(["split-right", "split-down", "sessions", "close"]);
  expect(d.tip).toEqual(["Split right", "Split down", "Sessions", "Close"]);
  expect(Math.abs(d.aH - d.tH)).toBeLessThan(0.5);
  expect(Math.abs(d.aTop - d.tTop)).toBeLessThan(0.5);
  expect(Math.max(...d.gaps) - Math.min(...d.gaps)).toBeLessThan(0.5); // equal spacing
  // On a phone the same pill, with 44 px hit areas around each button (the title truncates before the pill shrinks).
  const t = await touchPage(browser, 3);
  try {
    const p = t.page;
    const pd = await geometry(p, "w-build-01");
    // On a touch device a terminal's header holds Close alone: "?" (read about this window, #304) is not there, because with it the group folded into a "…"
    // whose 44 px target overlapped its neighbours (J211). "?" stays in ⌘K; the splits and the session manager are in the canvas row while a terminal is focused.
    expect(pd.buttons).toEqual(["close"]);
    // Header pills are one size (TASTE): on touch both are 36 px visible; the 44 px target is invisible padding (checked below).
    expect(Math.abs(pd.aH - pd.tH)).toBeLessThan(1);
    expect(pd.aH).toBeLessThanOrEqual(38);
    expect(Math.abs(pd.aTop - pd.tTop)).toBeLessThan(0.5);
    // The test double's "Mockup" tag sits over the top right of the first window; it is not the product's chrome.
    await p.addStyleTag({ content: ".cl-mockup { display: none !important; }" });
    const hits = await p.evaluate(() => {
      const w = document.querySelector('.ui-window[data-window-id="w-build-01"]')!;
      return [...w.querySelectorAll<HTMLElement>(".ui-window-action")].map((b) => {
        const r = b.getBoundingClientRect(), cx = r.left + r.width / 2, cy = r.top + r.height / 2;
        const at = (x: number, y: number): boolean => (document.elementFromPoint(x, y) as HTMLElement | null)?.closest(".ui-window-action") === b;
        // The point 21 px left, right, above and below the centre still lands on this button: a 44 px target.
        return at(cx - 21, cy) && at(cx + 21, cy) && at(cx, cy - 21) && at(cx, cy + 21);
      });
    });
    // Only Close is in the phone header, so one 44 px target.
    expect(hits).toEqual([true]);
  } finally { await t.close(); }
});

test("toolbar and keyboard: no terminal focused means one row and no dots, a toolbar tap never focuses an input, a focused terminal gets the key row and keeps its focus", async ({ browser }) => {
  const t = await touchPage(browser, 3);
  try {
    const { page } = t;
    // Count every focus that lands on something editable, from the start.
    await page.evaluate(() => {
      (window as unknown as { __focusIn: string[] }).__focusIn = [];
      document.addEventListener("focusin", (e) => { const n = e.target as HTMLElement; if (n.matches("input, textarea, [contenteditable]")) (window as unknown as { __focusIn: string[] }).__focusIn.push(n.className || n.tagName); }, true);
    });
    const state = () => page.evaluate(() => ({
      rows: document.querySelector("#keytray")!.getAttribute("data-rows"),
      keysHidden: (document.querySelector("#keyrow-keys") as HTMLElement).hidden,
      dots: getComputedStyle(document.querySelector(".keydots")!).display,
      editable: !!document.activeElement?.matches("input, textarea, [contenteditable]"),
      focusIn: (window as unknown as { __focusIn: string[] }).__focusIn.length,
    }));
    await page.touchscreen.tap(371, 400); // the canvas, not a terminal
    await page.waitForTimeout(900);
    let s = await state();
    expect(s).toMatchObject({ rows: "1", keysHidden: true, dots: "none", editable: false });
    // Every canvas-row control: no input takes focus, no keyboard.
    const ids = await page.evaluate(() => [...document.querySelectorAll<HTMLElement>("#keyrow-canvas > button")].map((b) => b.dataset.cv!));
    expect(ids.length).toBeGreaterThan(5);
    for (const id of ids) {
      if (id === "search") continue; // opens the palette, whose field is a real text input
      const box = await page.evaluate((cv) => { const r = document.querySelector(`#keyrow-canvas > [data-cv="${cv}"]`)!.getBoundingClientRect(); return { x: r.x + r.width / 2, y: r.y + r.height / 2, w: r.width }; }, id);
      if (box.w === 0) continue;
      await page.touchscreen.tap(box.x, box.y);
      await page.waitForTimeout(250);
      s = await state();
      expect(s.editable, `canvas row "${id}" focused an input`).toBe(false);
      expect(s.focusIn, `canvas row "${id}" fired a focus event on an input`).toBe(0);
      if (id === "input-lock") { await page.evaluate(() => document.querySelector<HTMLElement>('[data-cv="input-lock"]')!.click()); await page.waitForTimeout(500); } // the lock holds the key row; unlock it
      await page.keyboard.press("Escape").catch(() => undefined);
    }
    await page.waitForTimeout(600);
    expect(await state()).toMatchObject({ rows: "1", keysHidden: true });
    // A terminal takes focus: the key row appears, two rows, dots. (The controls above left the canvas free and zoomed out.)
    await page.evaluate(() => { const p = (window as unknown as { __tracerClusters: { setCanvasLock(on: boolean): void } }).__tracerClusters; p.setCanvasLock(true); });
    await page.evaluate(() => document.querySelector<HTMLElement>('[data-cv="views"]')!.click());
    await page.keyboard.press("Control+Shift+Digit1");
    await page.waitForTimeout(1200);
    await page.touchscreen.tap(200, 500);
    await expect.poll(async () => (await state()).rows).toBe("2");
    expect(await state()).toMatchObject({ keysHidden: false, dots: "flex" });
    // Key-row taps keep the terminal focused (D129).
    const focusedInTerminal = (): Promise<boolean> => page.evaluate(() => !!document.activeElement?.closest(".terminal-host"));
    expect(await focusedInTerminal()).toBe(true);
    await page.waitForTimeout(900); // the key row has slid into place
    const keys = await page.evaluate(() => [...document.querySelectorAll<HTMLElement>("#keyrow-keys > button:not([hidden])")].slice(0, 6).map((b) => { const r = b.getBoundingClientRect(); return { x: r.x + r.width / 2, y: r.y + r.height / 2 }; }));
    for (const [i, k] of keys.entries()) { await page.touchscreen.tap(k.x, k.y); await page.waitForTimeout(150); expect(await focusedInTerminal(), `key ${i}`).toBe(true); }
    // Focus leaves: back to one row.
    await page.evaluate(() => (document.activeElement as HTMLElement | null)?.blur());
    await expect.poll(async () => (await state()).rows, { timeout: 4000 }).toBe("1");
    expect(await state()).toMatchObject({ keysHidden: true, dots: "none" });
  } finally { await t.close(); }
});
