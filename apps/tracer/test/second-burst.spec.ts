/**
 * The D375 "second burst" row (#569): output that arrives right behind a previous burst is shown by the same frame, not
 * the next one.
 *
 * A shell echoes a key and then redraws its prompt, often as two messages a millisecond apart. The terminal parses one
 * write at a time and used to start the second only after the first was painted, which put the second burst's first draw
 * one frame (8.3 ms at 120 Hz) late. Each round here sends two live-output messages back to back, records which animation
 * frame draws the marker in the second, and compares it with the first frame that could (`test/paint-frames.ts`). The
 * row's value is the p99 of that difference in frames, target 0. Frame counts do not depend on the display rate, so the
 * row is valid in the unthrottled run that gates and in the 60 Hz run printed beside it. Like every functional-suite row it
 * only prints (#314); `scripts/verify latency` gates it.
 */
import { expect, test } from "playwright/test";
import { d375Row } from "./latency-targets";
import { firstFrameAfter, pct, presentingFrame, recording, RECORDER, signIn } from "./paint-frames";

const PAIRS = 40;

test("second burst: output right behind a previous burst is drawn by the same frame", async ({ page }) => {
  test.setTimeout(180_000);
  await page.addInitScript(RECORDER);
  const backend = `http://localhost:${Number(process.env.TRACER_BACKEND_PORT ?? String(Number(process.env.TRACER_TEST_PORT ?? "4621") + 1))}`;
  await signIn(page, false);
  const post = (text: string) => page.context().request.post(`${backend}/__mock/live-output`, { data: { text } });
  let id = 2000;
  const seconds: number[] = [];
  for (let round = 0; round < PAIRS; round += 1) {
    // A random idle wait de-correlates the pair from the frame phase.
    await page.waitForTimeout(40 + Math.random() * 30);
    seconds.push(id + 1);
    void post(`\r\n@@${id}@@`);
    void post(`@@${id + 1}@@`);
    id += 2;
    await expect.poll(async () => (await recording(page)).msgs.filter((m) => m.id !== undefined).length).toBeGreaterThanOrEqual((round + 1) * 2);
  }
  const rec = await recording(page);
  let joined = "";
  const owner: number[] = [];
  const draws = rec.draws.filter((d) => !d.overlay);
  draws.forEach((d, index) => { joined += d.text; for (let i = 0; i < d.text.length; i += 1) owner.push(index); });
  const extra: number[] = [];
  for (const marker of seconds) {
    const message = rec.msgs.find((m) => m.id === marker);
    const at = joined.indexOf(String(marker));
    if (!message || at < 0) { extra.push(Number.POSITIVE_INFINITY); continue; }
    const shown = presentingFrame(rec.frames, draws[owner[at]!]!);
    extra.push(shown - firstFrameAfter(rec.frames, message.t));
  }
  const late = extra.filter((value) => value > 0).length;
  const row = d375Row({
    key: "second_burst_extra_frames", source: "tracer-production-build", n: extra.length, value: pct(extra, 0.99), unit: "frames",
    target: 0, extra: `late_pairs=${late}`,
  });
  console.log(row.line);
});
