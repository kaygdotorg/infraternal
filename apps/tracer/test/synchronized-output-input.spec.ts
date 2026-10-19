/** Checks that an active synchronized-output hold leaves the terminal input path live. */
import { expect, test } from "playwright/test";

type MockState = { accepted_input_bytes: number; output_sequence: string };
type InputProbe = {
  acceptedAt: number;
  acceptedWhileHeld: boolean;
  inputSentAt: number;
  inputSentWhileHeld: boolean;
  keydownAt: number;
  keydownWhileHeld: boolean;
  animationFrames: number[];
};
type InputProbeWindow = Window & {
  __syncHoldInputProbe?: InputProbe;
};

/** A dropped pooled proxy socket must not turn a state poll into a terminal assertion. */
const retry = <T>(call: () => Promise<T>): Promise<T> => call().catch(() => call());

async function mockState(page: import("playwright/test").Page): Promise<MockState> {
  return (await (await retry(() => page.request.get("/__mock/state"))).json()) as MockState;
}

test("terminal input reaches the host during an unreleased synchronized-output hold", async ({ page }) => {
  test.setTimeout(20_000);
  const request = page.context().request;
  expect((await retry(() => request.post("/__mock/reset"))).ok()).toBe(true);
  expect((await retry(() => request.post("/__mock/open-terminal"))).ok()).toBe(true);
  await page.setViewportSize({ width: 1280, height: 800 });
  await page.goto("/?mock=1&theme=ink&bg=none");
  await expect.poll(() => page.evaluate(() => window.__tracerTestDouble?.isConnected() === true), { timeout: 30_000 }).toBe(true);
  await expect.poll(async () => (await mockState(page)).accepted_input_bytes).toBe(0);

  const baseline = await retry(() => request.post("/__mock/text-output", { data: { text: "BASELINE" } }));
  expect(baseline.ok()).toBe(true);
  await expect.poll(async () => BigInt(await page.evaluate(
    () => window.__tracerTestDouble?.rendererMetrics()?.outputSequence ?? "0",
  ))).toBeGreaterThanOrEqual(BigInt((await baseline.json() as { bytes: number }).bytes));
  await page.locator("#terminal-host").click();
  await page.keyboard.press("c");
  await expect.poll(async () => (await mockState(page)).accepted_input_bytes).toBe(1);
  await expect.poll(async () => BigInt((await mockState(page)).output_sequence)).toBeGreaterThan(8n);

  await page.evaluate(() => {
    const probeWindow = window as InputProbeWindow;
    probeWindow.__syncHoldInputProbe = {
      acceptedAt: 0,
      acceptedWhileHeld: false,
      inputSentAt: 0,
      inputSentWhileHeld: false,
      keydownAt: 0,
      keydownWhileHeld: false,
      animationFrames: [],
    };
    const frameStart = performance.now();
    const recordFrame = (at: number): void => {
      const probe = probeWindow.__syncHoldInputProbe;
      if (!probe || performance.now() - frameStart >= 5_000) return;
      probe.animationFrames.push(at);
      window.requestAnimationFrame(recordFrame);
    };
    window.requestAnimationFrame(recordFrame);
    window.addEventListener("keydown", (event) => {
      if (event.key !== "z") return;
      const probe = probeWindow.__syncHoldInputProbe;
      if (!probe) return;
      probe.keydownAt = performance.now();
      probe.keydownWhileHeld = window.__tracerTestDouble?.rendererMetrics()?.synchronizedOutputHoldsPaint ?? false;
      const nativeSend = WebSocket.prototype.send;
      WebSocket.prototype.send = function (data: string | ArrayBufferLike | Blob | ArrayBufferView): void {
        if (probe.inputSentAt === 0 && typeof data !== "string" && !(data instanceof Blob)) {
          const bytes = data instanceof ArrayBuffer
            ? new Uint8Array(data)
            : ArrayBuffer.isView(data)
              ? new Uint8Array(data.buffer, data.byteOffset, data.byteLength)
              : new Uint8Array(data);
          const skipVarint = (offset: number): number => {
            while (offset < bytes.byteLength) {
              const value = bytes[offset];
              offset += 1;
              if (value !== undefined && (value & 0x80) === 0) return offset;
            }
            return -1;
          };
          // A muxed frame is stream-id varint, frame-length varint, then the wire type byte.
          const frameLengthOffset = skipVarint(0);
          const frameTypeOffset = frameLengthOffset < 0 ? -1 : skipVarint(frameLengthOffset);
          if (frameTypeOffset >= 0 && bytes[frameTypeOffset] === 0x10) {
            probe.inputSentAt = performance.now();
            probe.inputSentWhileHeld = window.__tracerTestDouble?.rendererMetrics()?.synchronizedOutputHoldsPaint ?? false;
          }
        }
        nativeSend.call(this, data);
      };
      void (async () => {
        while (performance.now() - probe.keydownAt < 1_000) {
          const response = await fetch("/__mock/state");
          const state = await response.json() as MockState;
          if (state.accepted_input_bytes >= 2) {
            probe.acceptedAt = performance.now();
            probe.acceptedWhileHeld = window.__tracerTestDouble?.rendererMetrics()?.synchronizedOutputHoldsPaint ?? false;
            return;
          }
          await new Promise((resolve) => window.setTimeout(resolve, 1));
        }
      })();
    }, { capture: true });
  });

  const held = await retry(() => request.post("/__mock/live-query-output", {
    data: { text: "\u001b[?2026h\u001b[2J\u001b[HHELD" },
  }));
  expect(held.ok()).toBe(true);
  const heldSequence = (await held.json() as { output_sequence: string }).output_sequence;
  await expect.poll(() => page.evaluate((sequence) => {
    const metrics = window.__tracerTestDouble?.rendererMetrics();
    return {
      received: metrics?.receivedSequence ?? "0",
      held: metrics?.synchronizedOutputHoldsPaint ?? false,
    };
  }, heldSequence), { timeout: 1_000, intervals: [2] }).toEqual({ received: heldSequence, held: true });

  const echoMode = await retry(() => request.post("/__mock/echo-mode", { data: { mode: "normal" } }));
  expect(echoMode.ok()).toBe(true);
  await page.keyboard.press("z");
  await expect.poll(() => page.evaluate(() => (window as InputProbeWindow).__syncHoldInputProbe?.acceptedAt ?? 0), {
    timeout: 1_000,
    intervals: [2],
  }).toBeGreaterThan(0);
  const probe = await page.evaluate(() => (window as InputProbeWindow).__syncHoldInputProbe);
  if (!probe) throw new Error("terminal input timing probe was not installed");
  const sendMs = probe.inputSentAt - probe.keydownAt;
  console.log(`synchronized_output_input send_ms=${sendMs.toFixed(2)} ` +
    `keydown_held=${probe.keydownWhileHeld} sent_held=${probe.inputSentWhileHeld} accepted_held=${probe.acceptedWhileHeld}`);
  expect(probe.keydownWhileHeld).toBe(true);
  expect(probe.inputSentAt).toBeGreaterThan(0);
  expect(probe.inputSentWhileHeld).toBe(true);
  expect(probe.acceptedWhileHeld).toBe(true);
  expect(sendMs).toBeLessThanOrEqual(16);

  let echoSequence = "0";
  await expect.poll(async () => {
    echoSequence = (await mockState(page)).output_sequence;
    return BigInt(echoSequence);
  }, { timeout: 1_000, intervals: [2] }).toBeGreaterThan(BigInt(heldSequence));
  await expect.poll(() => page.evaluate((sequence) =>
    window.__tracerTestDouble?.rendererMetrics()?.receivedSequence ?? "0", echoSequence,
  ), { timeout: 1_000, intervals: [2] }).toBe(echoSequence);
  expect(await page.evaluate(() => window.__tracerTestDouble?.rendererMetrics()?.synchronizedOutputHoldsPaint ?? false))
    .toBe(true);
  expect(await page.evaluate(() => window.__tracerTestDouble?.screenText() ?? "")).not.toContain("HELD");

  await expect.poll(() => page.evaluate(() =>
    window.__tracerTestDouble?.rendererMetrics()?.synchronizedOutputHoldsPaint ?? true,
  ), { timeout: 1_000, intervals: [2] }).toBe(false);
  await expect.poll(() => page.evaluate(() => window.__tracerTestDouble?.rendererMetrics()?.outputSequence ?? "0"), {
    timeout: 1_000,
    intervals: [2],
  }).toBe(echoSequence);
  await expect.poll(() => page.evaluate(() => window.__tracerTestDouble?.screenText() ?? ""))
    .toContain("HELDz");
  const paintMetrics = await page.evaluate(() => window.__tracerTestDouble?.rendererMetrics());
  if (!paintMetrics) throw new Error("terminal paint metrics disappeared after hold release");
  const animationFrames = await page.evaluate(() => (window as InputProbeWindow).__syncHoldInputProbe?.animationFrames ?? []);
  const echoAfterReleaseMs = paintMetrics.lastPaintedOutputAt - paintMetrics.synchronizedTimeoutReleasedAt;
  const frameAtOrBefore = (at: number): number => animationFrames.filter((frameAt) => frameAt <= at).length;
  const releasedFrame = frameAtOrBefore(paintMetrics.synchronizedTimeoutReleasedAt);
  const paintedFrame = frameAtOrBefore(paintMetrics.lastPaintedOutputAt);
  const nextFrameAfterRelease = animationFrames[releasedFrame];
  const followingFrame = animationFrames[releasedFrame + 1];
  if (releasedFrame === 0 || nextFrameAfterRelease === undefined || followingFrame === undefined) {
    throw new Error("the animation-frame probe did not span synchronized-output release and paint");
  }
  const framesAfterRelease = paintedFrame - releasedFrame;
  const frameMs = followingFrame - nextFrameAfterRelease;
  console.log(`synchronized_output_echo_after_release_ms=${echoAfterReleaseMs.toFixed(2)} ` +
    `frame_ms=${frameMs.toFixed(2)} frames_after_release=${framesAfterRelease}`);
  expect(framesAfterRelease).toBeGreaterThanOrEqual(0);
  expect(framesAfterRelease).toBeLessThanOrEqual(1);
});
