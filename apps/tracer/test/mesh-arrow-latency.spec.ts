/**
 * How fast the Mesh view's arrows answer the hand (owner, 2026-11-25: "make sure to make the arrows really flexible and
 * snappy"; TASTE "Arrows are flexible and snappy"; #580). The goal is a 120 Hz frame: 8 ms from input to paint.
 *
 * A production build, the fake Mesh server with 50 hosts and 10 subnet routes (half approved, with arrows), at 1440 x 900
 * with a mouse and at 393 x 852 with touch. Three gestures, each done many times:
 * - **drag**: a new arrow is pulled from a card's connector across the canvas, snapping onto cards and off them;
 * - **retarget**: an arrow's head is grabbed and moved onto another card, the move is confirmed, and the arrow is redrawn;
 * - **delete**: an arrow's head is dropped on empty canvas and "Stop access" is confirmed; the arrow goes.
 *
 * The edit gestures need arrows on screen whose ends a hand can reach. A phone sees one or none of the generated mesh's, so
 * the run first adds arrows between the host cards in view, and takes the first arrow whose own line is on top at some point
 * (a tap or a hover there finds it; the point is not under a card or a label). A finger taps an arrow to select it before it
 * takes an end. The report counts the gestures completed and why any round was lost (`gestures.skipped`).
 *
 * Input-to-paint is measured inside the page: a capturing listener takes each input event's own timestamp, and in the
 * frame that event lands in, a message posted from `requestAnimationFrame` runs once that frame's style, layout and paint
 * are done. The difference is the time to the frame that shows the input (the compositor's last step after it is a
 * fraction of a millisecond in Chromium and is not counted). For each gesture this is reported for the moves and for
 * the press that commits (release, confirm click), as p50, p99 and the largest. The main thread's work per frame (a CDP
 * trace, as in mesh-perf.spec.ts) and how often a frame read layout inside an input handler (a forced layout) are reported
 * too, since those are what make a frame miss.
 *
 * Tagged `@perf`: timings only mean something on the quiet perf VM (PROCESS §1). On a build host it still runs every
 * gesture end to end and prints its numbers, which is how the functional parts (snap, confirm, server answer) are proved.
 * Results: `MESH-ARROW-LATENCY <viewport> {...}` lines and `mesh-arrow-latency-<viewport>.json` in the evidence folder.
 */
import { writeFileSync, mkdirSync } from "node:fs";
import { cpus, loadavg } from "node:os";
import { expect, test, type CDPSession, type Page } from "playwright/test";
import { tracerEvidencePath } from "./evidence-path";

/** One Chromium trace event, with only the fields read here. */
type Ev = { name: string; ph: string; ts: number; dur?: number; tdur?: number; tid: number; pid: number; args?: { name?: string; data?: { type?: string } } };
/** A distribution in milliseconds: how many samples, p50, p99, the largest, and how many missed a 120 Hz frame (8.33 ms). */
type Summary = { n: number; p50: number; p99: number; max: number; over8: number };
/** The `q` quantile of `a` (nearest rank), to two decimals. */
const pct = (a: number[], q: number): number => { const s = [...a].sort((x, y) => x - y); return s.length ? +s[Math.min(s.length - 1, Math.ceil(s.length * q) - 1)]!.toFixed(2) : 0; };
/** The distribution of `a`. */
const summary = (a: number[]): Summary => ({ n: a.length, p50: pct(a, 0.5), p99: pct(a, 0.99), max: pct(a, 1), over8: a.filter((v) => v > 8.33).length });

/** Installs the in-page meter: input timestamp to the end of the frame that shows it, by label. */
const METER = `(() => {
  const w = window;
  w.__lat = { moves: [], commits: [], frames: [], cancels: 0, downs: {} };
  addEventListener("pointercancel", () => { if (w.__latLabel !== "idle") w.__lat.cancels += 1; }, { capture: true });
  addEventListener("pointerdown", (e) => { const k = (e.target && e.target.getAttribute && e.target.getAttribute("class")) || "?"; w.__lat.downs[k] = (w.__lat.downs[k] || 0) + 1; }, { capture: true });
  w.__latLabel = "idle";
  const mark = (kind) => (e) => {
    if (w.__latLabel === "idle") return;
    // t0: when the input happened; t1: when the page got to handle it (the wait for the frame is t1 - t0).
    const t0 = e.timeStamp, t1 = performance.now(), label = w.__latLabel;
    requestAnimationFrame(() => {
      const ch = new MessageChannel();
      ch.port1.onmessage = () => { const t2 = performance.now(); w.__lat[kind].push({ label, ms: t2 - t0, handled: t2 - t1 }); };
      ch.port2.postMessage(0);
    });
  };
  // The browser's own frame interval, so a latency can be read in frames (headless Chromium paints at 60 Hz).
  let last = 0;
  const tick = (now) => { if (last && w.__latLabel !== "idle") w.__lat.frames.push(now - last); last = now; requestAnimationFrame(tick); };
  requestAnimationFrame(tick);
  for (const t of ["pointermove"]) addEventListener(t, mark("moves"), { capture: true });
  for (const t of ["pointerup", "click"]) addEventListener(t, mark("commits"), { capture: true });
})()`;

/** One frame: the next animation frame and the task after it. */
const frame = (page: Page): Promise<unknown> => page.evaluate("new Promise(r => requestAnimationFrame(() => setTimeout(r, 0)))");

/** Main-thread work per frame and forced layouts while `run` runs (see mesh-perf.spec.ts for the method). */
async function traced(page: Page, run: () => Promise<void>): Promise<{ work: number[]; forced: Record<string, number>; frames: number; clicks: number[]; clickToPaint: number[] }> {
  const cdp = await page.context().newCDPSession(page);
  const events: Ev[] = [];
  cdp.on("Tracing.dataCollected", (e) => events.push(...(e.value as unknown as Ev[])));
  await cdp.send("Tracing.start", { categories: "devtools.timeline,disabled-by-default-devtools.timeline,cc,toplevel", transferMode: "ReportEvents" });
  await run();
  const done = new Promise<void>((r) => cdp.once("Tracing.tracingComplete", () => r()));
  await cdp.send("Tracing.end");
  await done;
  await cdp.detach();
  const main = new Map<string, string>();
  for (const e of events) if (e.ph === "M" && e.name === "thread_name") main.set(`${e.pid}:${e.tid}`, e.args?.name ?? "");
  const mainEvents = events.filter((e) => e.ph === "X" && e.dur !== undefined && main.get(`${e.pid}:${e.tid}`) === "CrRendererMain");
  const cpu = (e: Ev): number => e.tdur ?? e.dur!;
  const frames = mainEvents.filter((e) => e.name === "ProxyMain::BeginMainFrame");
  const waits = mainEvents.filter((e) => e.name === "LayerTreeHost::WaitForCommitCompletion");
  const work = frames.map((f) => Math.max(0, cpu(f) - waits.filter((w) => w.ts >= f.ts && w.ts <= f.ts + f.dur!).reduce((s, w) => s + cpu(w), 0)) / 1000);
  // A layout inside an input event's dispatch is one the handler forced by reading geometry: the move path must have none.
  const dispatches = mainEvents.filter((e) => e.name === "EventDispatch" && /^pointer/.test(e.args?.data?.type ?? ""));
  const layouts = mainEvents.filter((e) => e.name === "Layout" || e.name === "UpdateLayoutTree");
  const forced: Record<string, number> = {};
  for (const d of dispatches) { const k = layouts.filter((l) => l.ts >= d.ts && l.ts <= d.ts + d.dur!).length; if (k) forced[d.args!.data!.type!] = (forced[d.args!.data!.type!] ?? 0) + k; }
  // The work of a click (the confirm that commits a change): it runs as a task of its own, outside the frames above.
  // A click that did no work (a press on a handle, which has no click handler) is not a confirm and is left out: 0.5 ms.
  const clicks = mainEvents.filter((e) => e.name === "EventDispatch" && e.args?.data?.type === "click" && cpu(e) > 500).map((e) => cpu(e) / 1000);
  // The whole of a confirm on the main thread: the click's task and the work of the first frame that follows it (style, layout,
  // paint), which is what stands between the press and the pixels. The click alone can look cheap when work is moved to the frame.
  const clickToPaint = mainEvents.filter((e) => e.name === "EventDispatch" && e.args?.data?.type === "click" && cpu(e) > 500).map((c) => {
    const next = frames.find((f) => f.ts >= c.ts);
    return (cpu(c) + (next ? Math.max(0, cpu(next) - waits.filter((w) => w.ts >= next.ts && w.ts <= next.ts + next.dur!).reduce((t, w) => t + cpu(w), 0)) : 0)) / 1000;
  });
  return { work, forced, frames: frames.length, clicks, clickToPaint };
}

/** Pointer input that works for a mouse and for a finger (CDP touch events, so pointer capture and coarse hit areas are real). */
interface Hand { down(x: number, y: number): Promise<void>; move(x: number, y: number): Promise<void>; up(x: number, y: number): Promise<void>; tap(x: number, y: number): Promise<void>; hover(x: number, y: number): Promise<void> }
/** A mouse: hover exists, presses are clicks. */
function mouseHand(page: Page): Hand {
  return {
    down: async (x, y) => { await page.mouse.move(x, y); await page.mouse.down(); },
    move: (x, y) => page.mouse.move(x, y),
    up: async (x, y) => { await page.mouse.move(x, y); await page.mouse.up(); },
    tap: (x, y) => page.mouse.click(x, y),
    hover: (x, y) => page.mouse.move(x, y),
  };
}
/** A finger through CDP touch events: no hover, and a tap is a touch start and end. */
function touchHand(cdp: CDPSession): Hand {
  const send = (type: "touchStart" | "touchMove" | "touchEnd", x: number, y: number): Promise<unknown> =>
    cdp.send("Input.dispatchTouchEvent", { type, touchPoints: type === "touchEnd" ? [] : [{ x, y, id: 1, radiusX: 8, radiusY: 8, force: 1 }] });
  return {
    down: async (x, y) => { await send("touchStart", x, y); },
    move: async (x, y) => { await send("touchMove", x, y); },
    up: async (x, y) => { await send("touchEnd", x, y); },
    tap: async (x, y) => { await send("touchStart", x, y); await send("touchEnd", x, y); },
    hover: async () => undefined,
  };
}

/** Runs `f` (source text) against the preview probe `window.__tracerClusters` and returns its result. */
const P = <T>(page: Page, f: string): Promise<T> => page.evaluate(`(${f})(window.__tracerClusters)`) as Promise<T>;
/** The screen box of the first element matching `sel` now, or nothing (no waiting: a missing element is an answer). */
const box = (page: Page, sel: string): Promise<{ x: number; y: number; w: number; h: number } | undefined> =>
  page.evaluate((q) => { const el = document.querySelector(q); if (!el) return undefined; const r = el.getBoundingClientRect(); return r.width || r.height ? { x: r.left, y: r.top, w: r.width, h: r.height } : undefined; }, sel);
/** Cards wholly on screen, by node id, with their centres. */
const visibleCards = (page: Page): Promise<Array<{ id: string; x: number; y: number; w: number; h: number; network: boolean }>> =>
  page.locator('.ui-window[data-kind="node"]').evaluateAll((ns) => ns.flatMap((n) => {
    const r = n.getBoundingClientRect(), el = n as HTMLElement;
    if (r.left < 8 || r.top < 60 || r.right > innerWidth - 8 || r.bottom > innerHeight - 8 || r.width === 0) return [];
    return [{ id: el.dataset.windowId!.slice(2), x: r.left + r.width / 2, y: r.top + r.height / 2, w: r.width, h: r.height, network: el.dataset.route !== undefined }];
  }));

/** Runs the three gestures `reps` times and returns their latencies. */
async function measure(page: Page, hand: Hand, label: string, touch: boolean): Promise<Record<string, unknown>> {
  await page.evaluate(METER);
  const setLabel = (l: string): Promise<unknown> => page.evaluate(`window.__latLabel = ${JSON.stringify(l)}`);
  const cards = await visibleCards(page);
  const hosts = cards.filter((c) => !c.network);
  expect(hosts.length, "host cards on screen").toBeGreaterThanOrEqual(4);
  const errors: string[] = [];
  page.on("pageerror", (e) => errors.push(e.message));

  // ---- drag: a new arrow from a connector, swept across the canvas over cards and gaps (snap on, snap off) -------
  const dragOnce = async (from: (typeof hosts)[number], i: number): Promise<void> => {
    const port = `.ui-window[data-window-id="n-${from.id}"] .cl-port`;
    if (!touch) await hand.hover(from.x, from.y - from.h / 2 + 12);
    const b = await box(page, port);
    if (!b) return;
    await hand.down(b.x + b.w / 2, b.y + b.h / 2);
    const steps = 40;
    for (let s = 1; s <= steps; s++) {
      const t = s / steps, other = hosts[(i + 1 + Math.floor(t * (hosts.length - 1))) % hosts.length]!;
      // Half the path goes straight at another card (it snaps), half wanders between cards.
      const x = s % 10 < 5 ? other.x : b.x + Math.sin(s / 3) * 180, y = s % 10 < 5 ? other.y : b.y + 120 + Math.cos(s / 4) * 90;
      await hand.move(x, y);
      await frame(page);
    }
    await setLabel("idle");
    await hand.up(b.x + 300, b.y + 400); // a release on nothing: the live arrow goes, nothing is asked
    // Escape cancels a question on a desktop; on a phone it flies the camera out to the overview, which is not what a finger did.
    if (!touch) await page.keyboard.press("Escape");
  };
  const dragTrace = await traced(page, async () => {
    await setLabel("drag");
    for (let i = 0; i < 4; i++) {
      await setLabel("drag");
      await dragOnce(hosts[i % hosts.length]!, i);
      // sleep: the released live arrow fades out (320 ms, no event); the next drag starts on a quiet canvas.
      await page.waitForTimeout(350);
    }
  });
  await setLabel("idle");

  // ---- retarget: grab a head, move it onto another card, confirm; and delete: drop on empty canvas, confirm -------------
  const grabHead = async (grant: string): Promise<{ x: number; y: number } | undefined> => {
    const hit = `.cl-arrow[data-grant="${grant}"] .cl-arrow-hit`;
    // A point of the arrow near its head that is on screen and on the arrow's own hit line (not under a card or a label):
    // from 80 % along back toward the middle, the first point whose topmost element is this arrow's hit line.
    const mid = await page.evaluate(({ q, g }) => {
      const path = document.querySelector(q) as SVGPathElement | null;
      if (!path) return undefined;
      const m = path.getScreenCTM()!, total = path.getTotalLength();
      for (let t = 0.8; t >= 0.3; t -= 0.05) {
        const pt = path.getPointAtLength(total * t), x = pt.x * m.a + pt.y * m.c + m.e, y = pt.x * m.b + pt.y * m.d + m.f;
        if (x < 4 || y < 4 || x > innerWidth - 4 || y > innerHeight - 4) continue;
        const top = document.elementFromPoint(x, y);
        if (top?.closest(".cl-arrow")?.getAttribute("data-grant") === g) return { x, y };
      }
      return undefined;
    }, { q: hit, g: grant });
    if (!mid) return undefined;
    // A mouse shows the handles on hover; a finger taps the arrow to select it first.
    if (touch) await hand.tap(mid.x, mid.y); else await hand.hover(mid.x, mid.y);
    await frame(page);
    return box(page, `.cl-arrow[data-grant="${grant}"] .cl-arrow-handle[data-end="head"]`).then((b) => (b ? { x: b.x + b.w / 2, y: b.y + b.h / 2 } : undefined));
  };
  /** Arrows drawn with their head on a card that is on screen (the tail may be anywhere): those a hand can grab by the head. */
  const onScreenGrants = async (): Promise<Array<{ id: string; from: string; to: string }>> => {
    const ids = new Set((await visibleCards(page)).map((c) => c.id));
    const grants = await P<Array<{ id: string; from: string; to: string }>>(page, "p => p.mesh.source().grants().map(g => ({ id: g.id, from: g.from, to: g.to }))");
    const drawn = new Set(await page.locator(".cl[data-view=\"mesh\"] .cl-arrow[data-grant]").evaluateAll((gs) => gs.map((g) => (g as SVGElement).dataset.grant!)));
    return grants.filter((g) => ids.has(g.to) && drawn.has(g.id));
  };
  const confirm = async (name: RegExp): Promise<boolean> => {
    // The question's confirm is an icon button named by its label (TASTE: confirm and cancel are icons with warm tooltips).
    const button = page.locator(".ui-confirm-tip").getByRole("button", { name }).first();
    if (!(await button.isVisible().catch(() => false))) return false;
    const b = (await button.boundingBox())!;
    await setLabel("commit");
    await hand.tap(b.x + b.width / 2, b.y + b.height / 2);
    await frame(page); await frame(page);
    await setLabel("idle");
    return true;
  };
  /** A point of empty canvas near `from`, well clear of every card (the snap radius is 32 px, 48 px on touch). */
  const emptySpot = async (from: { x: number; y: number }): Promise<{ x: number; y: number } | undefined> => {
    const cards = await page.locator('.ui-window[data-kind="node"]').evaluateAll((ns) => ns.map((n) => { const r = n.getBoundingClientRect(); return { l: r.left, t: r.top, r: r.right, b: r.bottom }; }));
    const vp = page.viewportSize()!;
    let best: { x: number; y: number; d: number } | undefined;
    for (let y = 90; y < vp.height - 30; y += 20) for (let x = 30; x < vp.width - 30; x += 20) {
      if (cards.some((c) => x > c.l - 70 && x < c.r + 70 && y > c.t - 70 && y < c.b + 70)) continue;
      const d = Math.hypot(x - from.x, y - from.y);
      if (!best || d < best.d) best = { x, y, d };
    }
    return best;
  };
  /**
   * Makes sure at least `n` arrows end on a card that is on screen, adding arrows between visible hosts where there are
   * fewer. Which arrows the generated mesh puts in view depends on the viewport (a phone sees one or none), and a gesture
   * that finds no arrow measures nothing, so the edit steps would silently not run (the J1203 phone report had none).
   */
  const ensureArrows = async (n: number): Promise<void> => {
    for (let tries = 0; tries < 12 && (await onScreenGrants()).length < n; tries++) {
      const hostsNow = (await visibleCards(page)).filter((c) => !c.network);
      const all = await P<Array<{ from: string; to: string }>>(page, "p => p.mesh.source().grants().map(g => ({ from: g.from, to: g.to }))");
      let pair: [string, string] | undefined;
      for (const a of hostsNow) for (const b of hostsNow) if (!pair && a.id !== b.id && !all.some((o) => o.from === a.id && o.to === b.id)) pair = [a.id, b.id];
      if (!pair) return;
      await P(page, `p => p.mesh.source().addGrant(${JSON.stringify(pair[0])}, ${JSON.stringify(pair[1])})`);
      await frame(page); await frame(page);
    }
  };
  // Enough arrows for every delete of the run (one in three gestures), added before the trace starts so their own work is not in it.
  await ensureArrows(10);
  // sleep: the new arrows' landing cue plays out (no event) before the first is grabbed
  await page.waitForTimeout(400);
  let retargets = 0, deletes = 0;
  /** Why a round of the edit loop did not complete, so a run that measured less than it should says where it lost the gesture. */
  const skipped = { noArrow: 0, noHandle: 0, noTarget: 0, noSpot: 0, noQuestion: 0 };
  const editTrace = await traced(page, async () => {
    for (let i = 0; i < 24; i++) {
      await ensureArrows(1);
      const grants = await onScreenGrants();
      if (!grants.length) { skipped.noArrow += 1; break; }
      const del = i % 3 === 2;
      const all = await P<Array<{ from: string; to: string }>>(page, "p => p.mesh.source().grants().map(g => ({ from: g.from, to: g.to }))");
      // The first arrow, from this round's turn on, that a hand can take now: its head can be reached (its curve is clear
      // of cards and labels at some point, so a finger or a hover finds it), and, for a retarget, a host card is free to take it.
      let g: (typeof grants)[number] | undefined, head: { x: number; y: number } | undefined, target: Awaited<ReturnType<typeof visibleCards>>[number] | undefined;
      for (let k = 0; k < grants.length && !head; k++) {
        const cand = grants[(i + k) % grants.length]!;
        // The head goes to a host card (a network takes only heads, and some already have this tail).
        const free = (await visibleCards(page)).find((c) => !c.network && c.id !== cand.from && c.id !== cand.to && !all.some((o) => o.from === cand.from && o.to === c.id));
        if (!del && !free) { skipped.noTarget += 1; continue; }
        const taken = await grabHead(cand.id);
        if (!taken) { skipped.noHandle += 1; continue; }
        g = cand; head = taken; target = free;
      }
      if (!g || !head) continue;
      const to = del ? await emptySpot(head) : { x: target!.x, y: target!.y };
      if (!to) { skipped.noSpot += 1; continue; }
      await setLabel(del ? "delete" : "retarget");
      await hand.down(head.x, head.y);
      const steps = 20;
      for (let s = 1; s <= steps; s++) { await hand.move(head.x + ((to.x - head.x) * s) / steps, head.y + ((to.y - head.y) * s) / steps); await frame(page); }
      await setLabel("release");
      await hand.up(to.x, to.y);
      await frame(page); await frame(page);
      await setLabel("idle");
      if (await confirm(del ? /Stop access/ : /Change access/)) { if (del) deletes += 1; else retargets += 1; }
      else { skipped.noQuestion += 1; if (!touch) await page.keyboard.press("Escape"); }
      // sleep: the confirmation and the toast settle (about 260 ms, no event) before the next arrow is grabbed.
      await page.waitForTimeout(300);
    }
  });
  type Sample = { label: string; ms: number; handled: number };
  const raw = await page.evaluate("window.__lat") as { moves: Sample[]; commits: Sample[]; frames: number[]; cancels: number; downs: Record<string, number> };
  const of = (list: Sample[], l: string): number[] => list.filter((r) => r.label === l).map((r) => r.ms);
  const handled = (list: Sample[], l: string): number[] => list.filter((r) => r.label === l).map((r) => r.handled);
  const result = {
    viewport: label,
    gestures: { retargets, deletes, skipped },
    inputToPaint: {
      drag: summary(of(raw.moves, "drag")),
      retarget: summary(of(raw.moves, "retarget")),
      delete: summary(of(raw.moves, "delete")),
      release: summary(of(raw.commits, "release")),
      confirm: summary(of(raw.commits, "commit")),
    },
    // From the moment the page handles the input to the end of the frame that shows it: the page's own share.
    handledToPaint: {
      drag: summary(handled(raw.moves, "drag")), retarget: summary(handled(raw.moves, "retarget")), delete: summary(handled(raw.moves, "delete")),
      release: summary(handled(raw.commits, "release")), confirm: summary(handled(raw.commits, "commit")),
    },
    frameInterval: summary(raw.frames),
    mainThreadWork: { drag: summary(dragTrace.work), edit: summary(editTrace.work) },
    forcedLayoutsInPointerHandlers: { drag: dragTrace.forced, edit: editTrace.forced },
    confirmClickWork: summary(editTrace.clicks),
    confirmClickAndFrameWork: summary(editTrace.clickToPaint),
    // The display's own rate as the page saw it (headless Chromium paints at 60 Hz unless its vsync is off).
    displayHz: Math.round(1000 / (summary(raw.frames).p50 || 16.7)),
    pointerCancels: raw.cancels,
    pressedOn: raw.downs,
    load: +(loadavg()[0]! / cpus().length).toFixed(2),
    errors,
  };
  console.log(`MESH-ARROW-LATENCY ${label} ${JSON.stringify(result)}`);
  const dir = tracerEvidencePath("mesh-arrow-latency");
  mkdirSync(dir, { recursive: true });
  writeFileSync(`${dir}/mesh-arrow-latency-${label}.json`, JSON.stringify(result, null, 2));
  return result;
}

/**
 * Opens the Mesh view of the latency mesh and frames a part of it with cards and arrows: zoom 1 on a desktop, 0.75 on a
 * phone (still cards, above the clusters level), so several cards and the arrows between them are on screen.
 */
async function openMesh(page: Page, z: number): Promise<void> {
  await page.goto("/?mock=1&proto=clusters&scene=6&theme=ink&bg=none&mesh=50&meshnets=10");
  await expect(page.locator(".cl-mockup")).toBeVisible({ timeout: 20_000 });
  await P(page, "p => p.flyView('mesh')");
  // The source lists the routes after the mesh: all ten networks are in the graph (most of them below the screen).
  await expect.poll(() => P<number>(page, "p => p.mesh.source().data().networks?.length ?? 0"), { timeout: 20_000 }).toBe(10);
  // sleep: the fly-in has no event; the camera is set once it rests.
  await page.waitForTimeout(1200);
  const c = await P<{ cx: number; cy: number }>(page, "p => p.camera()");
  await P(page, `p => p.setCamera(${c.cx}, ${c.cy}, ${z})`);
  await expect.poll(async () => (await visibleCards(page)).filter((v) => !v.network).length, { timeout: 20_000 }).toBeGreaterThanOrEqual(4);
  // sleep: cards that came on screen fade in; the first measured frame must not be one of theirs.
  await page.waitForTimeout(800);
}

test.describe("Mesh arrows: input to paint (#580)", { tag: "@perf" }, () => {
  test("desktop 1440 x 900, a mouse", async ({ page }) => {
    test.setTimeout(240_000);
    await page.setViewportSize({ width: 1440, height: 900 });
    await openMesh(page, 1);
    const r = await measure(page, mouseHand(page), "desktop", false) as { gestures: { retargets: number; deletes: number }; errors: string[]; inputToPaint: Record<string, Summary> };
    expect(r.errors).toEqual([]);
    // The run adds arrows between the cards on screen, so the gestures do not depend on which arrows the generated mesh
    // puts in view: a run that completes fewer than these has lost its grab (the counts and why are in the report).
    expect(r.gestures.retargets).toBeGreaterThanOrEqual(5);
    expect(r.gestures.deletes).toBeGreaterThanOrEqual(3);
    expect(r.inputToPaint.drag!.n).toBeGreaterThan(80);
  });

  test("phone 393 x 852, a finger", async ({ browser }) => {
    test.setTimeout(240_000);
    const context = await browser.newContext({ viewport: { width: 393, height: 852 }, deviceScaleFactor: 3, isMobile: true, hasTouch: true });
    const page = await context.newPage();
    await openMesh(page, 0.75);
    const cdp = await context.newCDPSession(page);
    const r = await measure(page, touchHand(cdp), "phone", true) as { gestures: { retargets: number; deletes: number }; errors: string[]; inputToPaint: Record<string, Summary> };
    expect(r.errors).toEqual([]);
    // A finger first taps the arrow to select it (its ends then show), then takes an end: the tap goes where the arrow's own
    // line is on top, not under a card or a label. Every edit gesture runs on the phone too.
    expect(r.inputToPaint.drag!.n).toBeGreaterThan(10);
    expect(r.gestures.retargets).toBeGreaterThanOrEqual(5);
    expect(r.gestures.deletes).toBeGreaterThanOrEqual(3);
    await context.close();
  });
});
