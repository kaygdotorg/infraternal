/**
 * Paint-frame alignment probe (J1066, #569, D130, D375): which animation frame shows a byte that just arrived, and
 * which frame shows a key the person just pressed.
 *
 * It runs against the production build and the tracer test double, on the perf VM under `perf-run`. A script injected
 * before the app starts records, in the page itself:
 * - every animation frame (the first callback of each frame, so its start time is the frame start);
 * - every websocket message arrival (the capture-phase listener runs before the app's own);
 * - every canvas `fillText` with the text drawn, tagged as the terminal canvas or the prediction overlay canvas, and
 *   whether it ran inside an animation-frame callback or in an ordinary task.
 * A draw made inside a frame callback is shown by that frame; a draw made in a task is shown by the next frame.
 * "Extra frames" is the frame that shows a byte minus the first frame that could have: 0 is the best any code can do.
 *
 * `PA_MODE=chunks` (run with `INFRATERNAL_TEST_RTT=0`): output chunks arrive alone and in pairs `gap` ms apart, the shape
 * of an echo followed by a prompt redraw. `PA_MODE=keys` (default RTT, prediction on): real keystrokes, the predicted
 * letter and the host's echo. Results go to the console as `PAROW` lines and to `$PA_OUT` as JSON.
 */
import { expect, test } from "playwright/test";
import { firstFrameAfter, pct, presentingFrame, recording, RECORDER, signIn } from "../test/paint-frames";
import { writeFileSync } from "node:fs";

function summary(name: string, values: number[]): string {
  return `PAROW name=${name} n=${values.length} p50=${pct(values, 0.5).toFixed(2)} p99=${pct(values, 0.99).toFixed(2)} max=${Math.max(...values).toFixed(2)}`;
}

const mode = process.env.PA_MODE ?? "chunks";
/** `flood` is the 10 MB/s output + typing probe (needs the harness patch). */
const rounds = Number(process.env.PA_ROUNDS ?? "150");
const outFile = process.env.PA_OUT;

test(`paint alignment: ${mode}`, async ({ page }) => {
  test.setTimeout(600_000);
  await page.addInitScript(RECORDER);
  const backend = `http://localhost:${Number(process.env.TRACER_BACKEND_PORT ?? String(Number(process.env.TRACER_TEST_PORT ?? "4621") + 1))}`;
  await signIn(page, mode === "keys" || mode === "flood");
  const results: Record<string, number[]> = {};
  let floodWindow: [number, number] | undefined;
  const push = (name: string, value: number): void => { (results[name] ??= []).push(value); };
  const post = (text: string) => page.context().request.post(`${backend}/__mock/live-output`, { data: { text } });
  let nextId = 1000;
  /** The marker id of the first message of every pair round; the second has the next id. */
  const pairFirst = new Set<number>();

  if (mode === "flood") {
    // Needs the measurement-only harness (perf/paint-align-flood-harness.patch) in the build. 10 MB/s of output through the
    // real receive path while keys are typed; each key is echoed 20 ms later as its own message.
    const cdp = await page.context().newCDPSession(page);
    await cdp.send("Performance.enable");
    const metricOf = async (name: string): Promise<number> =>
      ((await cdp.send("Performance.getMetrics")).metrics.find((m) => m.name === name)?.value ?? Number.NaN);
    const durationMs = 4000;
    const startedFrames = (await recording(page)).frames.length;
    const taskBefore = await metricOf("TaskDuration");
    const scriptBefore = await metricOf("ScriptDuration");
    const windowStart = await page.evaluate(() => performance.now());
    const flood = page.evaluate((ms) => (window as unknown as { __tracerTestDouble?: { floodForTest: (o: { bytesPerSecond: number; durationMs: number }) => Promise<{ bytes: number; stalls: number; renderPasses: number; messages: number }> } }).__tracerTestDouble?.floodForTest({ bytesPerSecond: 10_000_000, durationMs: ms }), durationMs);
    const letters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    for (let index = 0; index < 24; index += 1) {
      await page.waitForTimeout(130 + Math.random() * 20);
      await page.keyboard.press(letters[index]!);
    }
    const outcome = await flood;
    floodWindow = [windowStart, await page.evaluate(() => performance.now())];
    const taskMs = ((await metricOf("TaskDuration")) - taskBefore) * 1000;
    const scriptMs = ((await metricOf("ScriptDuration")) - scriptBefore) * 1000;
    const framesDuring = (await recording(page)).frames.length - startedFrames;
    console.log(`PAROW name=flood_totals bytes=${outcome?.bytes} messages=${outcome?.messages} stalls=${outcome?.stalls} frames=${framesDuring} render_passes=${outcome?.renderPasses} passes_per_frame=${((outcome?.renderPasses ?? 0) / framesDuring).toFixed(2)} main_thread_task_ms=${taskMs.toFixed(0)} script_ms=${scriptMs.toFixed(0)} mb_per_s=${((outcome?.bytes ?? 0) / durationMs / 1000).toFixed(2)}`);
    push("flood_task_ms", taskMs);
    push("flood_passes_per_frame", (outcome?.renderPasses ?? 0) / framesDuring);
    push("flood_fps", framesDuring / (durationMs / 1000));
    push("flood_mbps", (outcome?.bytes ?? 0) / durationMs / 1000);
  } else if (mode === "chunks") {
    // One marker per message, written on its own row so a draw of it is easy to find.
    const gaps = (process.env.PA_GAPS ?? "0,2,4,6,8,12").split(",").map(Number);
    let expected = 0;
    for (let round = 0; round < rounds; round += 1) {
      // A random idle wait de-correlates the arrival from the frame phase.
      await page.waitForTimeout(40 + Math.random() * 30);
      const gap = gaps[round % gaps.length]!;
      const pair = round % 2 === 1;
      if (pair) pairFirst.add(nextId);
      void post(`\r\n@@${nextId++}@@`);
      expected += 1;
      if (pair) {
        await new Promise((resolve) => setTimeout(resolve, gap));
        void post(`@@${nextId++}@@`);
        expected += 1;
      }
      await expect.poll(async () => (await recording(page)).msgs.filter((m) => m.id !== undefined).length >= expected).toBe(true);
    }
  } else {
    const letters = "abcdefghijklmnopqrstuvwxyz";
    for (let round = 0; round < rounds; round += 1) {
      await page.waitForTimeout(450 + Math.random() * 40);
      await page.keyboard.press(letters[round % letters.length]!);
    }
    await page.waitForTimeout(800);
  }

  const rec = await recording(page);
  const frames = rec.frames;
  const intervals = frames.slice(1).map((t, i) => t - frames[i]!);
  console.log(summary("frame_interval_ms", intervals));
  console.log(`PAROW name=long_animation_frames n=${rec.longFrames.length} blocking_p99=${pct(rec.longFrames.map((f) => f.blocking), 0.99).toFixed(2)} max_duration=${Math.max(0, ...rec.longFrames.map((f) => f.duration)).toFixed(2)}`);

  if (mode === "chunks") {
    const marked = rec.msgs.filter((m) => m.id !== undefined);
    // Reconstruct, per marker, the time of the terminal-canvas draw that painted its digits.
    const mainDraws = rec.draws.filter((d) => !d.overlay);
    let joined = "";
    const owner: number[] = [];
    mainDraws.forEach((d, index) => { joined += d.text; for (let i = 0; i < d.text.length; i += 1) owner.push(index); });
    for (const msg of marked) {
      const at = joined.indexOf(`@@${msg.id}@@`) >= 0 ? joined.indexOf(`@@${msg.id}@@`) : joined.indexOf(String(msg.id));
      if (at < 0) { push("undrawn", 1); continue; }
      const draw = mainDraws[owner[at]!]!;
      const minFrame = firstFrameAfter(frames, msg.t);
      const shown = presentingFrame(frames, draw);
      if (minFrame < 0 || shown < 0) continue;
      const extra = shown - minFrame;
      push("extra_frames_all", extra);
      push("arrival_to_frame_start_ms", frames[shown]! - msg.t);
      push("arrival_to_draw_ms", draw.t - msg.t);
      push("queue_in_task_ms", msg.t - msg.created);
    }
    // Pair rounds: the second marker of a pair arrives `gap` ms after the first.
    for (let i = 0; i + 1 < marked.length; i += 1) {
      const a = marked[i]!;
      const b = marked[i + 1]!;
      if (!pairFirst.has(a.id!) || b.id !== a.id! + 1) continue;
      const gap = b.t - a.t;
      const bucket = gap < 2 ? "0-2" : gap < 4 ? "2-4" : gap < 6 ? "4-6" : gap < 9 ? "6-9" : gap < 13 ? "9-13" : "13+";
      const at = joined.indexOf(String(b.id));
      if (at < 0) continue;
      const draw = mainDraws[owner[at]!]!;
      const minFrame = firstFrameAfter(frames, b.t);
      const shown = presentingFrame(frames, draw);
      push(`second_extra_frames_gap_${bucket}`, shown - minFrame);
      push(`second_arrival_to_frame_start_ms_gap_${bucket}`, frames[shown]! - b.t);
    }
  } else if (mode === "flood") {
    const [from, to] = floodWindow!;
    const inWindow = frames.filter((t) => t >= from && t <= to);
    inWindow.slice(1).forEach((t, i) => push("flood_frame_interval_ms", t - inWindow[i]!));
    for (const key of rec.keys) {
      if (key.key.length !== 1) continue;
      // Under a flood the echo scrolls away before any frame draws it (the screen moves ~2000 rows per frame), so the
      // typing latency that counts is the predicted letter (needs a round trip above 60 ms: run with RTT 300).
      const overlay = rec.draws.find((d) => d.overlay && d.t >= key.t && d.t < key.t + 100);
      if (!overlay) { push("typed_no_overlay", 1); continue; }
      const shown = presentingFrame(frames, overlay);
      push("typed_key_to_frame_start_ms", frames[shown]! - key.t);
      push("typed_key_to_overlay_draw_ms", overlay.t - key.t);
      push("typed_extra_frames", shown - firstFrameAfter(frames, key.t));
    }
  } else {
    const msgs = rec.msgs;
    for (const key of rec.keys) {
      if (key.key.length !== 1) continue;
      const overlay = rec.draws.find((d) => d.overlay && d.t >= key.t && d.t < key.t + 100);
      if (overlay) {
        const shown = presentingFrame(frames, overlay);
        const minFrame = firstFrameAfter(frames, key.t);
        push("predicted_key_to_overlay_draw_ms", overlay.t - key.t);
        push("predicted_key_to_frame_start_ms", frames[shown]! - key.t);
        push("predicted_extra_frames", shown - minFrame);
        push("predicted_draw_in_task", overlay.inRaf ? 0 : 1);
      }
      // The echo is the first terminal-canvas draw of this letter after the prediction; its message is the last one before it.
      const draw = rec.draws.find((d) => !d.overlay && d.t >= key.t + 100 && d.text.includes(key.key));
      const echoMsg = draw ? [...msgs].reverse().find((m) => m.t <= draw.t) : undefined;
      if (draw && echoMsg && draw.t - echoMsg.t < 100) {
        const shown = presentingFrame(frames, draw);
        const minFrame = firstFrameAfter(frames, echoMsg.t);
        push("echo_arrival_to_frame_start_ms", frames[shown]! - echoMsg.t);
        push("echo_extra_frames", shown - minFrame);
        push("echo_draw_in_task", draw.inRaf ? 0 : 1);
      }
    }
  }
  for (const [name, values] of Object.entries(results)) if (values.length) console.log(summary(name, values));
  if (outFile) writeFileSync(outFile, JSON.stringify({ mode, intervals: { p50: pct(intervals, 0.5), p99: pct(intervals, 0.99) }, results }));
});
