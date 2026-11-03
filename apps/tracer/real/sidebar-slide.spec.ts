/**
 * The sidebar's slide cost (#114): variants of its material while it moves, measured one against the other on the
 * same page and the same load (the variants alternate round after round, so load hits all of them equally).
 * Prints p50/p95/max of the frame times of the 300 ms after each toggle, with the machine's load average, and
 * counts layouts and paints inside the slide with the trace.
 *
 *   control   the shipped material: translucent tint with a live backdrop blur on the element
 *   opaque    blur and tint on two layers; while it slides the layer is opaque and has no blur, at rest the blur fades in
 *   contained opaque, plus will-change only while sliding and contain: strict
 */
import { tracerEvidencePath } from "../test/evidence-path";
import { expect, test, type Page } from "playwright/test";
import { loadavg } from "node:os";
import { personName, startRealServer, type RealServer } from "./server";

test.describe.configure({ mode: "serial" });

const LAYERS = `
.sidebar { background: transparent !important; backdrop-filter: none !important; -webkit-backdrop-filter: none !important; }
.sidebar::before, .sidebar::after { content: ""; position: absolute; inset: -1px; border-radius: inherit; pointer-events: none; z-index: -1; transition: opacity 120ms ease-out; }
.sidebar::before { background: var(--ui-overlay-background, var(--overlay)); backdrop-filter: blur(var(--ui-overlay-blur)) saturate(var(--ui-overlay-saturation)); -webkit-backdrop-filter: blur(var(--ui-overlay-blur)) saturate(var(--ui-overlay-saturation)); opacity: 1; }
.sidebar::after { background: linear-gradient(var(--overlay), var(--overlay)), var(--bg); opacity: 0; }
.sidebar[data-slide]::before { opacity: 0; transition: none; }
.sidebar[data-slide]::after { opacity: 1; transition: none; }
`;
const VARIANTS: Record<string, string> = {
  control: "",
  opaque: LAYERS,
  contained: LAYERS + `.sidebar[data-slide] { will-change: transform, opacity; contain: strict; }`,
};
let server: RealServer;
let page: Page;
test.beforeAll(async ({ browser }) => {
  server = await startRealServer();
  const context = await browser.newContext({ ignoreHTTPSErrors: true, viewport: { width: 1440, height: 900 } });
  page = await context.newPage();
  const cdp = await context.newCDPSession(page);
  await cdp.send("WebAuthn.enable");
  await cdp.send("WebAuthn.addVirtualAuthenticator", { options: { protocol: "ctap2", ctap2Version: "ctap2_1", transport: "internal", hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true, hasPrf: true } });
  await page.goto(server.origin + "/?theme=ink&bg=none");
  await page.locator("#setup-token").fill(server.token);
  await page.getByRole("button", { name: "Continue", exact: true }).click();
  await page.locator("#setup-username").fill(personName("slide_real"));
  await page.locator("#setup-display-name").fill("Slide real");
  await page.getByRole("button", { name: "Continue", exact: true }).click();
  await page.getByRole("button", { name: "Create passkey" }).click();
  await page.getByRole("heading", { name: "Save your recovery key" }).waitFor();
  await page.locator(".auth-check").click();
  await page.getByRole("button", { name: "Open infraternal" }).click();
  await page.locator(".cl-viewport").waitFor();
  for (let i = 0; i < 2; i++) { await page.locator(".tab-add").click(); await page.waitForTimeout(700); }
  // The camera's flight springs have a long, nearly invisible tail (about two seconds); the slide is measured after it.
  await page.waitForTimeout(4000);
});
test.afterAll(async () => { await page?.context().close(); await server?.dispose(); });

/** The product does not mark the slide (no variant won); the variants key on `data-slide`, so the harness sets it for 300 ms. */
const markSlide = (): Promise<void> => page.evaluate(() => { const sb = document.querySelector<HTMLElement>("#sidebar")!; sb.dataset.slide = ""; setTimeout(() => { delete sb.dataset.slide; }, 300); });

async function setVariant(name: string): Promise<void> {
  await page.evaluate((css) => {
    document.getElementById("variant")?.remove();
    if (css) { const s = document.createElement("style"); s.id = "variant"; s.textContent = css; document.head.append(s); }
  }, VARIANTS[name]!);
  await page.waitForTimeout(300);
}

/** Five open and five close slides; returns the frame times of the 300 ms after each click. */
async function slides(): Promise<number[]> {
  await page.evaluate(() => { const w = window as unknown as { __f: number[]; __rec: number; __stop: boolean }; w.__f = []; w.__rec = 0; w.__stop = false; let last = performance.now(); const tick = (t: number): void => { if (t < w.__rec) w.__f.push(t - last); last = t; if (!w.__stop) requestAnimationFrame(tick); }; requestAnimationFrame(tick); });
  for (let i = 0; i < 10; i++) {
    await page.evaluate(() => { (window as unknown as { __rec: number }).__rec = performance.now() + 300; });
    await markSlide();
    await page.locator("#sidebar-toggle").click();
    await page.waitForTimeout(500);
  }
  return page.evaluate(() => { const w = window as unknown as { __f: number[]; __stop: boolean }; w.__stop = true; return w.__f.slice(1); });
}
const pct = (xs: number[], q: number): number => [...xs].sort((a, b) => a - b)[Math.min(xs.length - 1, Math.floor(xs.length * q))]!;

test("slide frame times per variant, alternating on the same load", async () => {
  test.setTimeout(240_000);
  const all: Record<string, number[]> = Object.fromEntries(Object.keys(VARIANTS).map((k) => [k, []]));
  const load: Record<string, number[]> = Object.fromEntries(Object.keys(VARIANTS).map((k) => [k, []]));
  const names = Object.keys(VARIANTS);
  for (let round = 0; round < 6; round++) {
    // The order rotates, so the first position in a round (and the load trend) falls on each variant in turn.
    for (const name of [...names.slice(round % names.length), ...names.slice(0, round % names.length)]) {
      await setVariant(name);
      load[name]!.push(loadavg()[0]!);
      all[name]!.push(...await slides());
    }
  }
  for (const name of Object.keys(VARIANTS)) {
    const f = all[name]!;
    console.log(`SLIDE ${name.padEnd(9)} n=${f.length} p50=${pct(f, 0.5).toFixed(1)} p95=${pct(f, 0.95).toFixed(1)} max=${Math.max(...f).toFixed(1)} ms, load1 at the start of each round ${load[name]!.map((x) => x.toFixed(1)).join(" ")}`);
  }
});

test("during the slide, layout and paint work stops after the first frame", async () => {
  const cdp = await page.context().newCDPSession(page);
  const winner = process.env.SLIDE_VARIANT ?? "control";
  await setVariant(winner);
  const events: Array<{ name: string; ts: number; ph: string; args?: { data?: { name?: string } } }> = [];
  cdp.on("Tracing.dataCollected", (e: { value: typeof events }) => { events.push(...e.value); });
  await cdp.send("Tracing.start", { categories: process.env.SLIDE_DETAIL ? "devtools.timeline,blink.user_timing,disabled-by-default-devtools.timeline.invalidationTracking" : "devtools.timeline,blink.user_timing", transferMode: "ReportEvents" });
  for (const open of [true, false]) {
    await page.evaluate(() => performance.mark("slide-start"));
    await markSlide();
    await page.locator("#sidebar-toggle").click();
    await page.evaluate(() => new Promise<void>((r) => setTimeout(() => { performance.mark("slide-first-frames"); r(); }, 60)));
    await page.evaluate(() => new Promise<void>((r) => setTimeout(() => { performance.mark("slide-end"); r(); }, 240)));
    await page.waitForTimeout(400);
    void open;
  }
  const done = new Promise<void>((resolve) => cdp.once("Tracing.tracingComplete", () => resolve()));
  await cdp.send("Tracing.end");
  await done;
  const mark = (name: string): number[] => events.filter((e) => e.name === name).map((e) => e.ts).sort((a, b) => a - b);
  const firsts = mark("slide-first-frames"), ends = mark("slide-end");
  expect(firsts.length).toBe(2);
  const watched = ["Layout", "UpdateLayoutTree", "Paint", "PrePaint", "Layerize", "RecalculateStyles", "CompositeLayers"];
  const inFirst: Record<string, number> = {}, after: Record<string, number> = {};
  const starts = mark("slide-start");
  for (const e of events) {
    if (!watched.includes(e.name) || e.ph !== "X") continue;
    for (let i = 0; i < 2; i++) {
      if (e.ts >= starts[i]! && e.ts < firsts[i]!) inFirst[e.name] = (inFirst[e.name] ?? 0) + 1;
      else if (e.ts >= firsts[i]! && e.ts < ends[i]!) after[e.name] = (after[e.name] ?? 0) + 1;
    }
  }
  if (process.env.SLIDE_DETAIL) for (const e of events) {
    if (e.name === "Animation" && e.ph === "b") console.log("ANIM", JSON.stringify(e.args?.data).slice(0, 300));
    if (e.name === "StyleRecalcInvalidationTracking" || e.name === "StyleInvalidatorInvalidationTracking") {
      for (let i = 0; i < 2; i++) if (e.ts >= starts[i]! && e.ts < ends[i]!) { const d = e.args?.data as { nodeName?: string; stackTrace?: Array<{ functionName: string; lineNumber: number; columnNumber: number }> } | undefined; if (d?.stackTrace) console.log("INVAL", (e.ts - starts[i]!) / 1000 | 0, d.nodeName?.slice(0, 40), JSON.stringify(d.stackTrace?.map((f) => `${f.functionName || "?"}@${f.lineNumber}:${f.columnNumber}`))); }
    }
    if (!["Layout", "UpdateLayoutTree", "Paint"].includes(e.name) || e.ph !== "X") continue;
    for (let i = 0; i < 2; i++) if (e.ts >= firsts[i]! && e.ts < ends[i]!) console.log("DETAIL", e.name, (e.ts - firsts[i]!) / 1000 | 0, JSON.stringify(e.args).slice(0, 260));
  }
  console.log(`TRACE ${winner}: first 60 ms ${JSON.stringify(inFirst)}; the remaining 240 ms of the slide ${JSON.stringify(after)}`);
});

test("captures: the sidebar mid-slide and at rest, with the winning material", async () => {
  const out = process.env.SLIDE_CAPTURES ?? tracerEvidencePath("sidebar-slide");
  await setVariant(process.env.SLIDE_VARIANT ?? "contained");
  await page.evaluate(() => { document.documentElement.style.setProperty("--ui-overlay-saturation", "100%"); });
  await markSlide();
  await page.locator("#sidebar-toggle").click();
  await page.waitForTimeout(110);
  await page.screenshot({ path: `${out}/slide-mid.png`, clip: { x: 0, y: 0, width: 520, height: 900 } });
  await page.waitForTimeout(700);
  await page.screenshot({ path: `${out}/slide-rest.png`, clip: { x: 0, y: 0, width: 520, height: 900 } });
  await page.locator("#sidebar-toggle").click();
  await page.waitForTimeout(600);
});
