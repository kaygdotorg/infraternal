/**
 * Frame time with glass over a busy terminal, on a desktop and a phone-sized viewport (D365, #448).
 *
 * Bundles `glass-frame-bench.ts` (the real glass code over a stand-in terminal that repaints and notifies the glass every frame)
 * with the shared stylesheet into a static page in the evidence directory (`frame-bench/index.html`), runs it at 1440 x 900 and
 * 393 x 852, and writes `frame-bench/report-<size>.json`. The same page is what the iPhone Simulator opens (see the issue for the
 * command), so the numbers are comparable. The spec asserts only that every phase produced frames and that the tracked phase updated
 * the glass: frame time is software-rendered here and is for people to read, not a pass line.
 */
import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { expect, test } from "playwright/test";
import { tracerEvidencePath } from "./evidence-path";

/** The shared UI package, whose stylesheet and glass code the page uses. */
const ui = resolve(import.meta.dirname, "../../../packages/ui");

/** Bundles the bench and writes `index.html` (bench script and stylesheet inlined); returns its directory. */
function buildPage(): string {
  const out = tracerEvidencePath("frame-bench", "index.html");
  const dir = mkdtempSync(join(tmpdir(), "glass-bench-"));
  const entry = join(dir, "entry.ts");
  writeFileSync(entry, `import { runBench } from ${JSON.stringify(resolve(import.meta.dirname, "glass-frame-bench.ts"))};\nvoid runBench().then((r) => { (document.getElementById("out") as HTMLElement).textContent = JSON.stringify(r); fetch("/report", { method: "POST", body: JSON.stringify(r) }).catch(() => {}); });\n`);
  const js = join(dir, "bench.js");
  execFileSync("bun", ["build", entry, "--target=browser", "--format=iife", `--outfile=${js}`], { stdio: "pipe" });
  const css = readFileSync(join(ui, "styles.css"), "utf8");
  mkdirSync(resolve(out, ".."), { recursive: true });
  writeFileSync(out, `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><style>${css}</style></head><body style="margin:0"><pre id="out" style="position:fixed;bottom:0;left:0;right:0;z-index:99;color:#0f0;background:#000;font-size:9px;white-space:pre-wrap">running</pre><script>${readFileSync(js, "utf8")}</script></body></html>`);
  return out;
}

for (const size of [{ id: "1440x900", width: 1440, height: 900 }, { id: "393x852", width: 393, height: 852 }]) {
  test(`frame time over a busy terminal at ${size.id}`, async ({ browser }) => {
    test.setTimeout(60_000);
    const page = await (await browser.newContext({ viewport: size, deviceScaleFactor: 2 })).newPage();
    await page.route("http://bench.test/**", (route) => route.fulfill({ contentType: "text/html", body: readFileSync(buildPage(), "utf8") }));
    await page.goto("http://bench.test/");
    await page.waitForFunction(() => (globalThis as { __benchReport?: unknown }).__benchReport !== undefined, undefined, { timeout: 40_000 });
    const report = await page.evaluate(() => (globalThis as { __benchReport?: unknown }).__benchReport) as { phases: Array<{ frames: number; glass?: { updates: number } }> };
    writeFileSync(tracerEvidencePath("frame-bench", `report-${size.id}.json`), JSON.stringify(report, null, 1));
    console.log(`FRAMEBENCH ${size.id} ${JSON.stringify(report)}`);
    for (const p of report.phases) expect(p.frames).toBeGreaterThan(30);
    expect(report.phases[2]!.glass!.updates, "the glass updated while the screen streamed").toBeGreaterThan(10);
  });
}
