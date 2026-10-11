/**
 * Profiles one user operation of the preview (not a spec: run it by hand).
 *
 *   THROTTLE=4 bun test/work-trace.ts sidebar-open
 *   operations: sidebar-open sidebar-close theme activate palette-open font-cold tab popover-open
 *
 * Records a Chrome trace of the renderer main thread for the operation (animations off), then prints
 * the top self-time functions from the sampling profiler, the style recalculations (how many elements each
 * touched), the layouts (how many objects were dirty of how many), and the forced ones (style or layout
 * that script asked for in the middle of a task: reads after writes). Needs the mock server serving the
 * production build at TRACER_PREVIEW (default http://localhost:4796).
 */
import { chromium } from "playwright";

const op = process.argv[2] ?? "sidebar-open";
const THROTTLE = Number(process.env.THROTTLE ?? "4");
const origin = process.env.TRACER_PREVIEW ?? "http://localhost:4796";
const browser = await chromium.launch({ args: ["--disable-renderer-backgrounding"] });
const context = await browser.newContext({ viewport: { width: 1440, height: 900 }, reducedMotion: "reduce" });
const page = await context.newPage();
await page.goto(`${origin}/?mock=1&proto=windows&theme=ink&bg=none&fixture=none`);
await page.waitForTimeout(3500);
let aim = { x: 0, y: 0 };
const aimAt = async (selector: string, offset?: { x: number; y: number }): Promise<void> => {
  const box = (await page.locator(selector).first().boundingBox())!;
  aim = offset ? { x: box.x + offset.x, y: box.y + offset.y } : { x: box.x + box.width / 2, y: box.y + box.height / 2 };
};
const closeAll = async (): Promise<void> => { await page.keyboard.press("Escape"); await page.keyboard.press("Escape"); };

// Warm up and put the page in the state the operation starts from.
const prepare: Record<string, () => Promise<void>> = {
  "sidebar-open": async () => { await page.locator("#sidebar-toggle").click(); await page.waitForTimeout(300); await page.locator("#sidebar-toggle").click(); await page.waitForTimeout(300); await aimAt("#sidebar-toggle"); },
  "sidebar-close": async () => { await page.locator("#sidebar-toggle").click(); await page.waitForTimeout(400); await aimAt("#sidebar-toggle"); },
  "theme": async () => { await page.keyboard.press("Control+Shift+K"); await page.locator("#palette-input").fill("theme paper"); await page.waitForTimeout(200); },
  "activate": async () => { await aimAt(".ui-window:nth-child(2) .ui-window-body", { x: 100, y: 200 }); },
  "palette-open": async () => { await page.keyboard.press("Control+Shift+K"); await page.waitForTimeout(300); await closeAll(); await page.waitForTimeout(300); },
  "font-cold": async () => { await page.keyboard.press("Control+Shift+K"); await page.locator("#palette-input").fill("jetbrains"); await page.waitForTimeout(300); },
  "tab": async () => { await page.locator(".ui-window-pill").nth(1).click(); await page.waitForTimeout(400); await aimAt(".canvas-popover .ui-tab[data-tab='connection']"); },
  "popover-open": async () => { await page.locator(".ui-window-pill").nth(1).click(); await page.waitForTimeout(300); await closeAll(); await page.waitForTimeout(300); await aimAt(".ui-window:nth-child(2) .ui-window-pill"); },
};
const act: Record<string, () => Promise<void>> = {
  "sidebar-open": () => page.mouse.click(aim.x, aim.y),
  "sidebar-close": () => page.mouse.click(aim.x, aim.y),
  "theme": () => page.keyboard.press("Enter"),
  "activate": () => page.mouse.click(aim.x, aim.y),
  "palette-open": () => page.keyboard.press("Control+Shift+K"),
  "font-cold": () => page.keyboard.press("ArrowDown"),
  "tab": () => page.mouse.click(aim.x, aim.y),
  "popover-open": () => page.mouse.click(aim.x, aim.y),
};
if (!prepare[op] || !act[op]) throw new Error(`unknown operation ${op}`);
await prepare[op]!();

const session = await browser.newBrowserCDPSession();
const events: Array<Record<string, any>> = [];
session.on("Tracing.dataCollected", (data: { value: Array<Record<string, any>> }) => events.push(...data.value));
const complete = new Promise<void>((resolve) => session.on("Tracing.tracingComplete", () => resolve()));
const cdp = await context.newCDPSession(page);
await cdp.send("Emulation.setCPUThrottlingRate", { rate: THROTTLE });
await session.send("Tracing.start", {
  categories: "devtools.timeline,disabled-by-default-devtools.timeline,disabled-by-default-v8.cpu_profiler,v8,blink",
  transferMode: "ReportEvents",
} as never);
await act[op]!();
await page.waitForTimeout(400);
await session.send("Tracing.end");
await complete;
await cdp.send("Emulation.setCPUThrottlingRate", { rate: 1 });

const main = events.find((event) => event.name === "thread_name" && event.args?.name === "CrRendererMain");
const mainEvents = events.filter((event) => event.pid === main?.pid && event.tid === main?.tid);
const ms = (microseconds: number): string => (microseconds / 1000).toFixed(1);

// Style and layout.
const styles = mainEvents.filter((event) => event.name === "UpdateLayoutTree" && event.ph === "X");
const layouts = mainEvents.filter((event) => event.name === "Layout" && event.ph === "X");
const forced = mainEvents.filter((event) => event.name === "Document::UpdateStyleAndLayout" || event.name === "Blink.ForcedStyleAndLayout.UpdateTime");
console.log(`\n== ${op} at ${THROTTLE}x CPU ==`);
console.log(`style recalcs: ${styles.length}, ${ms(styles.reduce((sum, event) => sum + event.dur, 0))} ms; elements (ms each): ${styles.map((event) => `${event.args?.elementCount ?? "?"} (${ms(event.dur)})`).join(", ")}`);
console.log(`layouts: ${layouts.length}, ${ms(layouts.reduce((sum, event) => sum + event.dur, 0))} ms; dirty/total objects: ${layouts.map((event) => `${event.args?.beginData?.dirtyObjects ?? "?"}/${event.args?.beginData?.totalObjects ?? "?"}`).join(", ")}`);
console.log(`forced style+layout from script: ${forced.length}, ${ms(forced.reduce((sum, event) => sum + (event.dur ?? 0), 0))} ms`);

// Sampling profiler: self time by function.
const nodes = new Map<number, { name: string; url: string; line: number }>();
const self = new Map<string, number>();
for (const chunk of events.filter((event) => event.name === "ProfileChunk")) {
  const profile = chunk.args?.data?.cpuProfile;
  for (const node of profile?.nodes ?? []) nodes.set(node.id, { name: node.callFrame.functionName || "(anonymous)", url: String(node.callFrame.url).split("/").pop() ?? "", line: node.callFrame.lineNumber });
  const samples: number[] = profile?.samples ?? [];
  const deltas: number[] = chunk.args?.data?.timeDeltas ?? [];
  samples.forEach((id, index) => {
    const node = nodes.get(id);
    if (!node) return;
    const key = `${node.name} ${node.url}:${node.line}`;
    self.set(key, (self.get(key) ?? 0) + (deltas[index] ?? 0));
  });
}
const forcedBy = new Map<string, number>();
for (const event of mainEvents.filter((e) => e.name === "Document::UpdateStyleAndLayout" || e.name === "Blink.ForcedStyleAndLayout.UpdateTime")) { /* counted above */ void event; }
const top = [...self.entries()].filter(([key]) => !key.startsWith("(idle)") && !key.startsWith("(program)")).sort((a, b) => b[1] - a[1]).slice(0, 12);
console.log("top self time (sampling profiler):");
for (const [key, time] of top) console.log(`  ${ms(time).padStart(6)} ms  ${key}`);
await browser.close();
