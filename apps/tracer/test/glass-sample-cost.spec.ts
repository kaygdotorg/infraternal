/**
 * What sampling the picture behind a glass card costs (D365, `packages/ui/src/glass-adapt.ts`).
 *
 * Adaptive glass density reads an 8x8 average of the part of a remote window's picture under a card, at most every 250 ms
 * while the card is open. Latency comes first (D375), so this measures the price before anyone wires it into a window:
 *  - the time of one sample (`readSample`: one `drawImage` into an 8x8 canvas and one 256-byte read) from a live 1920x1080
 *    stream, from a decoded 1920x1080 VP8 video and from a 1920x1080 `<canvas>`, as the mean of 50 back-to-back samples, 20 times
 *    (the browser's clock moves in 0.1 ms steps, so a single call would read 0);
 *  - the page's frame intervals (`requestAnimationFrame` deltas) over a few seconds with the picture animating and no
 *    sampling, then with `watchBackdrop` running at its real 250 ms pace.
 *
 * Results are written to `glass-sample-cost/report.json` in the evidence directory and printed. The spec asserts only that
 * sampling returns sensible data: wall-clock speed is not a functional assertion (the numbers are for people to read, and a
 * headless run on a build VM uses software rendering, so they bound the CPU path and say nothing of a phone's GPU).
 */
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { expect, test } from "playwright/test";
import { tracerEvidencePath } from "./evidence-path";

/** The shared UI package's source, bundled into the page under test. */
const uiSrc = resolve(import.meta.dirname, "../../../packages/ui/src");

/** Bundles the module and the themes for the browser; the scratch directory is outside the checkout. */
function bundle(): string {
  const dir = mkdtempSync(join(tmpdir(), "glass-cost-"));
  const entry = join(dir, "entry.ts");
  writeFileSync(entry, `export * from ${JSON.stringify(join(uiSrc, "glass-adapt.ts"))};\nexport { THEMES } from ${JSON.stringify(join(uiSrc, "themes.ts"))};\n`);
  const out = join(dir, "glass.js");
  execFileSync("bun", ["build", entry, "--target=browser", "--format=esm", `--outfile=${out}`], { stdio: "pipe" });
  return readFileSync(out, "utf8");
}

/** Summary of a list of readings, in milliseconds. */
interface Stats { n: number; p50: number; p99: number; max: number; mean: number }
/** `msPerSample` is each timed batch's mean (the browser's clock is coarse, so single calls read 0); frames are the rAF intervals. */
interface Report { liveVideo: Stats; recordedVideo: Stats; canvas: Stats; framesIdle: Stats; framesSampling: Stats; samplesDuringRun: number }

test("sampling a 1080p picture: cost of one sample and its effect on frame intervals", async ({ page }) => {
  test.setTimeout(120_000);
  const code = bundle();
  await page.route("http://glass.test/**", (route) => {
    const url = route.request().url();
    if (url.endsWith("/glass.js")) return route.fulfill({ contentType: "text/javascript", body: code });
    return route.fulfill({ contentType: "text/html", body: "<!doctype html><meta charset=utf-8><body style=margin:0><div id=card data-glass-under></div>" });
  });
  await page.goto("http://glass.test/");
  const report: Report = await page.evaluate(async () => {
    const moduleUrl = "http://glass.test/glass.js";
    const GA = await import(moduleUrl) as typeof import("../../../packages/ui/src/glass-adapt") & { THEMES: Record<string, import("../../../packages/ui/src/themes").Theme> };
    const stats = (xs: number[]): Stats => {
      const s = [...xs].sort((a, b) => a - b);
      const at = (q: number): number => s[Math.min(s.length - 1, Math.floor(q * s.length))]!;
      return { n: s.length, p50: at(0.5), p99: at(0.99), max: s[s.length - 1]!, mean: s.reduce((a, b) => a + b, 0) / s.length };
    };
    // A 1920x1080 picture that changes every frame, as a stream would.
    const pic = document.createElement("canvas");
    pic.width = 1920; pic.height = 1080;
    const g = pic.getContext("2d")!;
    let t = 0;
    const paint = (): void => {
      t += 1;
      const grad = g.createLinearGradient(0, 0, 1920, 1080);
      grad.addColorStop(0, `hsl(${t % 360} 40% 90%)`); grad.addColorStop(1, `hsl(${(t * 2) % 360} 30% 70%)`);
      g.fillStyle = grad; g.fillRect(0, 0, 1920, 1080);
      g.fillStyle = "#222"; g.fillRect((t * 7) % 1700, 300, 200, 120);
    };
    paint();
    const painter = window.setInterval(paint, 1000 / 30);
    const video = document.createElement("video");
    video.muted = true; video.playsInline = true;
    video.srcObject = pic.captureStream(30);
    document.body.append(video);
    await video.play();
    await new Promise<void>((done) => { const check = (): void => (video.readyState >= 2 && video.videoWidth > 0 ? done() : void setTimeout(check, 20)); check(); });

    const region = { x: 600, y: 300, width: 320, height: 240 };
    /** 20 batches of 50 samples; the mean of each batch is one reading, which beats the browser's 0.1 ms clock steps. */
    const time = (source: HTMLVideoElement | HTMLCanvasElement): number[] => {
      const out: number[] = [];
      for (let rep = 0; rep < 20; rep++) {
        const a = performance.now();
        for (let i = 0; i < 50; i++) if (!GA.readSample(source, region)) throw new Error("no sample");
        out.push((performance.now() - a) / 50);
      }
      return out;
    };
    // A decoded video, not just a canvas stream: record two seconds of the picture as VP8 and play the file back.
    const recorder = new MediaRecorder(pic.captureStream(30), { mimeType: "video/webm;codecs=vp8", videoBitsPerSecond: 8_000_000 });
    const parts: Blob[] = [];
    recorder.ondataavailable = (e) => parts.push(e.data);
    const stopped = new Promise<void>((done) => { recorder.onstop = () => done(); });
    recorder.start();
    await new Promise((done) => setTimeout(done, 2500));
    recorder.stop();
    await stopped;
    const recorded = document.createElement("video");
    recorded.muted = true; recorded.playsInline = true; recorded.loop = true;
    recorded.src = URL.createObjectURL(new Blob(parts, { type: "video/webm" }));
    document.body.append(recorded);
    await recorded.play();
    await new Promise<void>((done) => { const check = (): void => (recorded.readyState >= 2 && recorded.videoWidth > 0 ? done() : void setTimeout(check, 20)); check(); });
    time(video); time(recorded); // warm each path once
    const liveCost = time(video);
    const recordedCost = time(recorded);
    const canvasCost = time(pic);

    const frames = (ms: number): Promise<number[]> => new Promise((done) => {
      const out: number[] = [];
      let last = performance.now();
      const stop = last + ms;
      const step = (now: number): void => { out.push(now - last); last = now; if (now < stop) requestAnimationFrame(step); else done(out.slice(5)); };
      requestAnimationFrame(step);
    });
    const framesIdle = await frames(4000);
    let samples = 0;
    const stopWatching = GA.watchBackdrop({
      marker: document.getElementById("card")!, source: video, region: () => { samples += 1; return region; },
      theme: () => GA.THEMES.ink!, level: () => 2,
    });
    const framesSampling = await frames(4000);
    stopWatching();
    window.clearInterval(painter);
    return { liveVideo: stats(liveCost), recordedVideo: stats(recordedCost), canvas: stats(canvasCost), framesIdle: stats(framesIdle), framesSampling: stats(framesSampling), samplesDuringRun: samples };
  });
  writeFileSync(tracerEvidencePath("glass-sample-cost", "report.json"), JSON.stringify(report, null, 2));
  console.log(JSON.stringify(report, null, 2));
  expect(report.liveVideo.n).toBe(20);
  expect(report.samplesDuringRun).toBeGreaterThan(5);
});
