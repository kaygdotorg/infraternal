/**
 * D309 break-it checks for the phone presentation: read the persisted server document directly and exercise the pointer
 * media transition without changing the viewport. This spec belongs to the review branch and runs against phone-min-col.
 */
import { expect, test } from "playwright/test";
import { randomUUID } from "node:crypto";
import { spawnSync } from "node:child_process";
import { writeFile } from "node:fs/promises";
import type { CanvasDocument } from "../src/canvas/model/schema";
import { tracerEvidencePath } from "../test/evidence-path";
import { cache, pair, request, settled, windows } from "./layout-devices";
import type { RealServer } from "./server";

function stored(server: RealServer): CanvasDocument {
  const path = `${server.dataDir}/infraternal.sqlite`;
  const result = spawnSync("python3", ["-c", `import json,sqlite3,sys
with sqlite3.connect(sys.argv[1]) as db:
 row=db.execute("SELECT revision,document FROM canvas_heads ORDER BY rowid DESC LIMIT 1").fetchone()
 if row is None: raise SystemExit("missing canvas head")
 print(json.dumps({"revision":row[0],"document":json.loads(row[1])}))
`, path], { encoding: "utf8" });
  if (result.status !== 0) throw new Error(`direct server layout query failed (${result.status})`);
  const row = JSON.parse(result.stdout) as { revision: number; document: CanvasDocument };
  expect(row.document.revision).toBe(row.revision);
  return row.document;
}

async function installCoarseSwitch(context: import("playwright/test").BrowserContext): Promise<void> {
  await context.addInitScript(() => {
    const native = window.matchMedia.bind(window);
    let coarse = true;
    const listeners = new Set<(event: MediaQueryListEvent) => void>();
    const query = "(pointer: coarse)";
    const list = {
      media: query,
      get matches() { return coarse; },
      onchange: null as ((event: MediaQueryListEvent) => void) | null,
      addEventListener(type: string, listener: EventListenerOrEventListenerObject | null) {
        if (type === "change" && typeof listener === "function") listeners.add(listener as (event: MediaQueryListEvent) => void);
      },
      removeEventListener(type: string, listener: EventListenerOrEventListenerObject | null) {
        if (type === "change" && typeof listener === "function") listeners.delete(listener as (event: MediaQueryListEvent) => void);
      },
      addListener(listener: ((event: MediaQueryListEvent) => void) | null) { if (listener) listeners.add(listener); },
      removeListener(listener: ((event: MediaQueryListEvent) => void) | null) { if (listener) listeners.delete(listener); },
      dispatchEvent(event: Event) { for (const listener of listeners) listener(event as MediaQueryListEvent); return true; },
    } as MediaQueryList;
    window.matchMedia = ((media: string) => media === query ? list : native(media)) as typeof window.matchMedia;
    (window as Window & { __setReviewCoarse?: (value: boolean) => void }).__setReviewCoarse = (value) => {
      if (coarse === value) return;
      coarse = value;
      const event = new Event("change") as MediaQueryListEvent;
      listeners.forEach((listener) => listener(event));
      list.onchange?.(event);
    };
  });
}

const colWidths = (page: import("playwright/test").Page): Promise<number[]> => page.evaluate(() =>
  [...document.querySelectorAll<HTMLElement>('.cl[data-view="console"] .cl-col')].map((column) => Math.round(column.getBoundingClientRect().width)));

test("phone: 1 to 8 columns, rotation, pinch, reload, and desktop edits preserve server truth", async ({ browser }) => {
  const f = await pair(browser);
  try {
    let serverDoc = stored(f.server);
    const startRevision = serverDoc.revision;
    for (let count = 2; count <= 8; count++) {
      await f.page.keyboard.press("Control+Shift+D");
      await expect(windows(f.page)).toHaveCount(count);
      await settled(f.page);
      await expect(windows(f.mobile)).toHaveCount(count);
      await settled(f.mobile);
      serverDoc = stored(f.server);
      const consoleView = serverDoc.views.find((entry) => entry.id === "console")!;
      expect(consoleView.layout.type === "tiled" ? consoleView.layout.columns.length : 0, `server columns at count ${count}`).toBe(count);
    }
    const consoleView = serverDoc.views.find((entry) => entry.id === "console")!;
    if (consoleView.layout.type !== "tiled") throw new Error("console layout is not tiled");
    const targetColumn = consoleView.layout.columns[1]!;
    expect((await request(f.server, f.desktop, "canvas.layout.apply", {
      op_id: randomUUID(), base_revision: serverDoc.revision,
      intent: { type: "weight", view_id: consoleView.id, column_id: targetColumn.id, weight: 0.1 },
    })).ok).toBe(true);
    await settled(f.page);
    await settled(f.mobile);
    serverDoc = stored(f.server);
    const phoneTruth = structuredClone(serverDoc);
    await expect.poll(async () => f.mobile.locator('.cl[data-view="console"] .cl-col').count()).toBe(8);
    expect(await colWidths(f.mobile)).toHaveLength(8);
    await f.mobile.screenshot({ path: tracerEvidencePath("phone-review-8-columns-portrait.png") });
    for (let step = 1; step < 8; step++) {
      await f.mobile.locator("[data-cv='next']").tap();
      await f.mobile.waitForTimeout(600);
      const center = await f.mobile.evaluate(() => innerWidth / 2);
      const closest = await f.mobile.evaluate((mid) => {
        const widths = [...document.querySelectorAll<HTMLElement>('.cl[data-view="console"] .cl-col')].map((node) => {
          const rect = node.getBoundingClientRect();
          return { id: node.dataset.id, distance: Math.abs((rect.left + rect.right) / 2 - mid) };
        });
        return widths.reduce((a, b) => a.distance <= b.distance ? a : b).id;
      }, center);
      expect(closest, `column reachable after ${step} next actions`).toBe(consoleView.layout.columns[step]!.id);
    }
    await f.mobile.setViewportSize({ width: 852, height: 393 });
    await f.mobile.waitForTimeout(500);
    await f.mobile.screenshot({ path: tracerEvidencePath("phone-review-8-columns-landscape.png") });
    expect(stored(f.server)).toEqual(phoneTruth);

    await f.mobile.getByRole("button", { name: /Canvas lock on/ }).click();
    await expect(f.mobile.getByRole("button", { name: /Canvas lock off/ })).toBeVisible();
    const cdp = await f.mobile.context().newCDPSession(f.mobile);
    const zoom = async () => f.mobile.evaluate(() => {
      const transform = document.querySelector<HTMLElement>(".cl-world")!.style.transform;
      return Number(/scale\(([^)]+)\)/.exec(transform)?.[1] ?? 1);
    });
    const beforePinch = await zoom();
    await cdp.send("Input.dispatchTouchEvent", { type: "touchStart", touchPoints: [{ x: 380, y: 190, id: 1 }, { x: 460, y: 190, id: 2 }] });
    for (let step = 1; step <= 6; step++) await cdp.send("Input.dispatchTouchEvent", { type: "touchMove", touchPoints: [{ x: 380 - step * 3, y: 190, id: 1 }, { x: 460 + step * 3, y: 190, id: 2 }] });
    await cdp.send("Input.dispatchTouchEvent", { type: "touchEnd", touchPoints: [] });
    await cdp.detach();
    await expect.poll(zoom, { timeout: 5_000 }).toBeGreaterThan(beforePinch + 0.2);
    const afterPinch = await zoom();
    await f.mobile.screenshot({ path: tracerEvidencePath("phone-review-after-pinch.png") });
    await writeFile(tracerEvidencePath("phone-review-pinch.json"), JSON.stringify({ beforeZoom: beforePinch, afterZoom: afterPinch, serverRevision: phoneTruth.revision }, null, 2));
    expect(stored(f.server)).toEqual(phoneTruth);

    await f.mobile.reload();
    await expect(windows(f.mobile)).toHaveCount(8);
    await settled(f.mobile);
    expect(stored(f.server)).toEqual(phoneTruth);
    expect((await cache(f.mobile)).canonical).toEqual(phoneTruth);

    const latestView = phoneTruth.views.find((entry) => entry.id === "console")!;
    if (latestView.layout.type !== "tiled") throw new Error("console layout is not tiled");
    expect((await request(f.server, f.desktop, "canvas.layout.apply", {
      op_id: randomUUID(), base_revision: phoneTruth.revision,
      intent: { type: "weight", view_id: latestView.id, column_id: latestView.layout.columns[0]!.id, weight: 0.2 },
    })).ok).toBe(true);
    await settled(f.page);
    await settled(f.mobile);
    const desktopEdit = stored(f.server);
    expect(desktopEdit.revision).toBe(phoneTruth.revision + 1);
    await expect.poll(async () => (await cache(f.mobile)).canonical.revision).toBe(desktopEdit.revision);
    await expect.poll(async () => (await cache(f.page)).canonical.revision).toBe(desktopEdit.revision);
    expect((await cache(f.mobile)).canonical).toEqual(desktopEdit);
    expect((await cache(f.page)).canonical).toEqual(desktopEdit);
    const editedView = desktopEdit.views.find((entry) => entry.id === "console")!;
    if (editedView.layout.type !== "tiled") throw new Error("console layout is not tiled");
    const closedWindow = editedView.layout.columns[0]!.windows[0]!;
    expect((await request(f.server, f.desktop, "canvas.layout.apply", {
      op_id: randomUUID(), base_revision: desktopEdit.revision,
      intent: { type: "close", window_id: closedWindow.id },
    })).ok).toBe(true);
    const desktopClose = stored(f.server);
    expect(desktopClose.revision).toBe(desktopEdit.revision + 1);
    await expect(windows(f.page)).toHaveCount(7);
    await expect(windows(f.mobile)).toHaveCount(7);
    await expect.poll(async () => (await cache(f.mobile)).canonical.revision).toBe(desktopClose.revision);
    await expect.poll(async () => (await cache(f.page)).canonical.revision).toBe(desktopClose.revision);
    expect(stored(f.server)).toEqual(desktopClose);

    expect((await request(f.server, f.desktop, "canvas.layout.apply", {
      op_id: randomUUID(), base_revision: desktopClose.revision,
      intent: { type: "view.update", view_id: "console", cell: { x: 3, y: 2 } },
    })).ok).toBe(true);
    const desktopMove = stored(f.server);
    expect(desktopMove.revision).toBe(desktopClose.revision + 1);
    await expect.poll(async () => (await cache(f.mobile)).canonical.revision).toBe(desktopMove.revision);
    await expect.poll(async () => (await cache(f.page)).canonical.revision).toBe(desktopMove.revision);
    expect(desktopMove.views.find((entry) => entry.id === "console")!.cell).toEqual({ x: 3, y: 2 });
    expect((await cache(f.mobile)).canonical).toEqual(desktopMove);
    expect(stored(f.server)).toEqual(desktopMove);
    await writeFile(tracerEvidencePath("phone-review-layout-revisions.json"), JSON.stringify({
      initial: { revision: startRevision, columns: 1 },
      phonePresentation: { revision: phoneTruth.revision, weights: (phoneTruth.views.find((entry) => entry.id === "console")!.layout as { columns: Array<{ weight: number }> }).columns.map((column) => column.weight) },
      desktopEdit: { revision: desktopEdit.revision, weights: (desktopEdit.views.find((entry) => entry.id === "console")!.layout as { columns: Array<{ weight: number }> }).columns.map((column) => column.weight) },
      desktopClose: { revision: desktopClose.revision, remainingWindows: 7 },
      desktopMove: { revision: desktopMove.revision, cell: desktopMove.views.find((entry) => entry.id === "console")!.cell },
    }, null, 2));
  } finally { await f.dispose(); }
});

test("phone: a view drag followed by a desktop edit converges on the durable server layout", async ({ browser }) => {
  const f = await pair(browser);
  try {
    const initial = stored(f.server);
    await f.mobile.getByRole("button", { name: /Canvas lock on/ }).click();
    await expect(f.mobile.locator(".cl-world")).not.toHaveAttribute("data-snap", "");
    const touch = await f.mobile.context().newCDPSession(f.mobile);
    // Free mode pans by a two-finger drag; move the label below the top controls so a one-finger drag can grab it.
    await touch.send("Input.dispatchTouchEvent", { type: "touchStart", touchPoints: [{ x: 120, y: 350, id: 1 }, { x: 260, y: 350, id: 2 }] });
    await touch.send("Input.dispatchTouchEvent", { type: "touchMove", touchPoints: [{ x: 120, y: 470, id: 1 }, { x: 260, y: 470, id: 2 }] });
    await touch.send("Input.dispatchTouchEvent", { type: "touchEnd", touchPoints: [] });
    const findStart = () => f.mobile.evaluate(() => {
      const node = document.querySelector<HTMLElement>('.cl[data-view="console"] .cl-label');
      if (!node) return undefined;
      const box = node.getBoundingClientRect();
      for (const y of [box.top + box.height / 2, box.top + 4, box.bottom - 4]) {
        for (let x = box.right - 4; x >= box.left + 4; x -= 4) {
          const hit = document.elementFromPoint(x, y);
          if (hit?.closest(".cl-label") === node) return { x, y };
        }
      }
      return undefined;
    });
    await expect.poll(async () => (await findStart()) !== undefined, { timeout: 5_000 }).toBe(true);
    const start = await findStart();
    if (!start) throw new Error("phone view label has no unobscured touch point");
    await touch.send("Input.dispatchTouchEvent", { type: "touchStart", touchPoints: [{ ...start, id: 1 }] });
    for (let step = 1; step <= 6; step++) {
      await touch.send("Input.dispatchTouchEvent", { type: "touchMove", touchPoints: [{ x: start.x + step * 40, y: start.y + step, id: 1 }] });
    }
    await expect(f.mobile.locator('.cl[data-view="console"][data-lifted]')).toHaveCount(1);
    await touch.send("Input.dispatchTouchEvent", { type: "touchEnd", touchPoints: [] });
    await touch.detach();
    await f.mobile.screenshot({ path: tracerEvidencePath("phone-review-after-drag.png") });
    await expect.poll(() => stored(f.server).revision).toBeGreaterThan(initial.revision);
    const afterPhone = stored(f.server);
    const moved = afterPhone.views.find((entry) => entry.id === "console")!;
    expect(moved.cell).not.toEqual(initial.views.find((entry) => entry.id === "console")!.cell);
    expect((await cache(f.mobile)).canonical).toEqual(afterPhone);
    await writeFile(tracerEvidencePath("phone-review-drag-revisions.json"), JSON.stringify({ before: initial.revision, afterPhone: afterPhone.revision, phoneCell: moved.cell }, null, 2));

    const consoleView = afterPhone.views.find((entry) => entry.id === "console")!;
    if (consoleView.layout.type !== "tiled") throw new Error("console layout is not tiled");
    expect((await request(f.server, f.desktop, "canvas.layout.apply", {
      op_id: randomUUID(), base_revision: afterPhone.revision,
      intent: { type: "weight", view_id: consoleView.id, column_id: consoleView.layout.columns[0]!.id, weight: 0.6 },
    })).ok).toBe(true);
    await settled(f.page);
    await settled(f.mobile);
    const finalDoc = stored(f.server);
    expect(finalDoc.revision).toBe(afterPhone.revision + 1);
    expect(finalDoc.views.find((entry) => entry.id === "console")!.cell).toEqual(moved.cell);
    await expect.poll(async () => (await cache(f.page)).canonical.revision).toBe(finalDoc.revision);
    await expect.poll(async () => (await cache(f.mobile)).canonical.revision).toBe(finalDoc.revision);
    expect((await cache(f.page)).canonical).toEqual(finalDoc);
    expect((await cache(f.mobile)).canonical).toEqual(finalDoc);
    await writeFile(tracerEvidencePath("phone-review-drag-desktop-final.json"), JSON.stringify({ afterDesktop: finalDoc.revision, phoneCell: moved.cell, finalCell: finalDoc.views.find((entry) => entry.id === "console")!.cell }, null, 2));
  } finally { await f.dispose(); }
});

test("phone: an incoming shared view is pushed for display while its saved cell remains on the server", async ({ browser }) => {
  const f = await pair(browser);
  try {
    for (let count = 2; count <= 8; count++) {
      await f.page.keyboard.press("Control+Shift+D");
      await expect(windows(f.page)).toHaveCount(count);
      await settled(f.page);
      await expect(windows(f.mobile)).toHaveCount(count);
      await settled(f.mobile);
    }
    const before = stored(f.server);
    const consoleView = before.views.find((entry) => entry.id === "console")!;
    const savedCell = structuredClone(consoleView.cell);
    expect((await request(f.server, f.desktop, "canvas.layout.apply", {
      op_id: randomUUID(), base_revision: before.revision,
      intent: { type: "view.add", view: { id: "peer", kind: "console", name: "Peer", cell: savedCell, layout: { type: "tiled", columns: [] } } },
    })).ok).toBe(true);
    const incoming = stored(f.server);
    expect(incoming.revision).toBe(before.revision + 1);
    expect(incoming.views.find((entry) => entry.id === "peer")!.cell).toEqual(savedCell);
    await expect.poll(async () => (await cache(f.mobile)).canonical.revision).toBe(incoming.revision);
    await expect.poll(async () => f.mobile.locator('.cl[data-view="peer"]').count()).toBe(1);
    const displayBoxes = () => f.mobile.evaluate(() => {
      const view = (id: string) => {
        const node = document.querySelector<HTMLElement>(`.cl[data-view="${id}"]`)!;
        const match = /translate\(([-\d.]+)px,\s*([-\d.]+)px\)/.exec(node.style.transform);
        return { x: Number(match?.[1]), y: Number(match?.[2]), w: node.offsetWidth, h: node.offsetHeight };
      };
      return { console: view("console"), peer: view("peer") };
    });
    const displayed = await displayBoxes();
    const pushedX = displayed.peer.x;
    expect(Number.isFinite(displayed.console.x) && Number.isFinite(displayed.peer.x)).toBe(true);
    expect(pushedX !== savedCell.x * 120 || displayed.peer.y !== savedCell.y * 120).toBe(true);
    expect(displayed.console.x < displayed.peer.x + displayed.peer.w
      && displayed.peer.x < displayed.console.x + displayed.console.w
      && displayed.console.y < displayed.peer.y + displayed.peer.h
      && displayed.peer.y < displayed.console.y + displayed.console.h).toBe(false);
    await f.mobile.screenshot({ path: tracerEvidencePath("phone-review-incoming-pushed-view.png") });
    expect(stored(f.server)).toEqual(incoming);
    expect((await cache(f.mobile)).canonical).toEqual(incoming);
    await writeFile(tracerEvidencePath("phone-review-incoming-layout.json"), JSON.stringify({ beforeRevision: before.revision, afterRevision: incoming.revision, serverCell: savedCell, displayPosition: { x: pushedX, y: displayed.peer.y }, noOverlap: true }, null, 2));

    expect((await request(f.server, f.desktop, "canvas.layout.apply", {
      op_id: randomUUID(), base_revision: incoming.revision,
      intent: { type: "view.update", view_id: "peer", cell: { x: savedCell.x + 1, y: savedCell.y + 1 } },
    })).ok).toBe(true);
    const desktopMoved = stored(f.server);
    expect(desktopMoved.revision).toBe(incoming.revision + 1);
    expect(desktopMoved.views.find((entry) => entry.id === "peer")!.cell).toEqual({ x: savedCell.x + 1, y: savedCell.y + 1 });
    await expect.poll(async () => (await cache(f.mobile)).canonical.revision).toBe(desktopMoved.revision);
    expect((await cache(f.mobile)).canonical).toEqual(desktopMoved);
    expect(stored(f.server)).toEqual(desktopMoved);
    const movedDisplay = await displayBoxes();
    expect(Number.isFinite(movedDisplay.console.x) && Number.isFinite(movedDisplay.peer.x)).toBe(true);
    expect(movedDisplay.peer.x !== (savedCell.x + 1) * 120 || movedDisplay.peer.y !== (savedCell.y + 1) * 120).toBe(true);
    expect(movedDisplay.console.x < movedDisplay.peer.x + movedDisplay.peer.w
      && movedDisplay.peer.x < movedDisplay.console.x + movedDisplay.console.w
      && movedDisplay.console.y < movedDisplay.peer.y + movedDisplay.peer.h
      && movedDisplay.peer.y < movedDisplay.console.y + movedDisplay.console.h).toBe(false);
    await writeFile(tracerEvidencePath("phone-review-incoming-desktop-move.json"), JSON.stringify({
      serverRevision: desktopMoved.revision, savedCell: { x: savedCell.x + 1, y: savedCell.y + 1 },
      displayPosition: { x: movedDisplay.peer.x, y: movedDisplay.peer.y }, noOverlap: true,
    }, null, 2));

    await f.mobile.reload();
    await expect.poll(async () => f.mobile.locator('.cl[data-view="peer"]').count()).toBe(1);
    await expect.poll(async () => (await cache(f.mobile)).canonical.revision).toBe(desktopMoved.revision);
    expect(stored(f.server)).toEqual(desktopMoved);
  } finally { await f.dispose(); }
});

test("phone: a fine-pointer transition drops the touch width floor without a viewport resize", async ({ browser }) => {
  const f = await pair(browser);
  try {
    await installCoarseSwitch(f.phone);
    await f.mobile.reload();
    await expect(windows(f.mobile)).toHaveCount(1);
    await settled(f.mobile);
    await f.page.keyboard.press("Control+Shift+D");
    await expect(windows(f.page)).toHaveCount(2);
    await expect(windows(f.mobile)).toHaveCount(2);
    await settled(f.page);
    await settled(f.mobile);

    let serverDoc = stored(f.server);
    let view = serverDoc.views.find((entry) => entry.id === "console")!;
    if (view.layout.type !== "tiled") throw new Error("console layout is not tiled");
    expect(view.layout.columns).toHaveLength(2);
    const narrow = view.layout.columns[1]!;
    expect((await request(f.server, f.desktop, "canvas.layout.apply", {
      op_id: randomUUID(), base_revision: serverDoc.revision,
      intent: { type: "weight", view_id: view.id, column_id: narrow.id, weight: 0.1 },
    })).ok).toBe(true);
    await settled(f.page);
    await settled(f.mobile);
    serverDoc = stored(f.server);
    expect(serverDoc.views.find((entry) => entry.id === "console")!.layout).toMatchObject({
      type: "tiled", columns: [{ weight: expect.any(Number) }, { id: narrow.id, weight: 0.1 }],
    });
    const touchWidths = await colWidths(f.mobile);
    await f.mobile.screenshot({ path: tracerEvidencePath("phone-review-coarse-pointer.png") });
    expect(touchWidths).toHaveLength(2);
    expect(touchWidths[1]).toBeGreaterThan(250);
    expect(stored(f.server)).toEqual(serverDoc);

    await f.mobile.evaluate(() => (window as Window & { __setReviewCoarse?: (value: boolean) => void }).__setReviewCoarse?.(false));
    await expect.poll(() => f.mobile.evaluate(() => matchMedia("(pointer: coarse)").matches)).toBe(false);
    await f.mobile.waitForTimeout(500);
    const fineWidths = await colWidths(f.mobile);
    await f.mobile.screenshot({ path: tracerEvidencePath("phone-review-fine-pointer-stale-width.png") });
    const afterSwitch = stored(f.server);
    await writeFile(tracerEvidencePath("phone-review-pointer-switch.json"), JSON.stringify({
      beforeRevision: serverDoc.revision, afterRevision: afterSwitch.revision,
      savedWeight: 0.1, coarseColumnWidth: touchWidths[1], fineColumnWidth: fineWidths[1],
    }, null, 2));
    expect(fineWidths[1], `saved 0.1-weight column should become narrow after pointer switch; was ${JSON.stringify(fineWidths)}`).toBeLessThan(100);
    expect(afterSwitch).toEqual(serverDoc);
    expect((await cache(f.mobile)).canonical).toEqual(serverDoc);
  } finally { await f.dispose(); }
});
