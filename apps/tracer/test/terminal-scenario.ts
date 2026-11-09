/** Shared access, input and resume scenario; performance budgets are enforced only by the perf-VM suite (#314). */
import { writeFile } from "node:fs/promises";
import { expect as baseExpect, test, type Page, type TestInfo } from "playwright/test";
import { d375Row, FRAME_MS, latencyDisplay, RECONNECT_ALLOWANCE_MS, roundTripBoundMs } from "./latency-targets";

// A fresh proxied document loads assets before access is ready; its readiness wait is independent of speed budgets.
const expect = baseExpect.configure({ timeout: 30_000 });

/**
 * Runs the whole first-use story on one page against the test double behind the delayed link: passkey sign-up and
 * sign-in, a terminal with predictive echo on, a dropped connection that resumes without losing or repeating a key, the
 * safety rules of prediction (no echo, full-screen programs, wrong echoes) and, with `performanceSamples`, the
 * returning-sign-in timings the perf VM reports. Call it from a spec that has set a timeout long enough for all of it.
 */
export async function terminalScenario(page: Page, testInfo: TestInfo, { performanceSamples = false }: { performanceSamples?: boolean } = {}) {
  // The latency profile and the perf VM type 100 probe keys twice (prediction on and off) at a 300 ms round trip
  // and drop the socket 20 times, about four minutes; the functional suite keeps its short run.
  const latencySamples = performanceSamples || process.env.INFRATERNAL_LATENCY_PROFILE === "1";
  test.setTimeout(latencySamples ? 420_000 : 180_000);
  const context = page.context();
  const testRttMs = Number(process.env.INFRATERNAL_TEST_RTT ?? "300");
  const signinTrials = performanceSamples ? Number(process.env.INFRATERNAL_SIGNIN_SAMPLES ?? "10") : 1;
  if (!Number.isInteger(signinTrials) || signinTrials < 1 || signinTrials > 30) {
    throw new Error("INFRATERNAL_SIGNIN_SAMPLES must be an integer from 1 to 30");
  }
  let pageErrors = 0;
  page.on("pageerror", () => { pageErrors += 1; });
  await context.request.post("/__mock/reset");
  const authRequests: string[] = [];
  page.on("request", (request) => { if (new URL(request.url()).pathname.startsWith("/auth/")) authRequests.push(new URL(request.url()).pathname); });
  const cdp = await context.newCDPSession(page);
  await cdp.send("WebAuthn.enable");
  await cdp.send("WebAuthn.addVirtualAuthenticator", {
    options: {
      protocol: "ctap2",
      ctap2Version: "ctap2_1",
      transport: "internal",
      hasResidentKey: true,
      hasUserVerification: true,
      isUserVerified: true,
      automaticPresenceSimulation: true,
      hasPrf: true,
    },
  });

  await page.goto("/?mock=1");
  await expect(page.locator("#setup-card")).toBeVisible();
  await expect(page.locator("#login-passkey")).toHaveCount(0);
  expect(authRequests[0]).toBe("/auth/status");
  await page.setViewportSize({ width: 1280, height: 720 });
  const setupResponse = await context.request.get("/__mock/setup-token");
  const setupBody = await setupResponse.json() as { setup_token: string };
  await page.locator("#setup-token").fill(setupBody.setup_token);
  await page.getByRole("button", { name: "Continue" }).click();
  await page.locator("#setup-username").fill("tracer_browser_test");
  await page.locator("#setup-display-name").fill("Tracer browser test");
  await page.getByRole("button", { name: "Continue" }).click();
  await page.getByRole("button", { name: "Create passkey" }).click();

  await expect(page.getByRole("heading", { name: "Save your recovery key" })).toBeVisible();
  const recoveryWords = await page.locator("#recovery-words li").count();
  // Failed assertions must never print the actual recovery phrase.
  expect(recoveryWords).toBe(24);
  await page.locator(".auth-check").click();
  await page.getByRole("button", { name: "Open infraternal" }).click();
  await expect(page.getByText("TEST DOUBLE")).toBeVisible();
  await expect.poll(() => page.evaluate(() => window.__tracerTestDouble?.isConnected() === true), { timeout: 30_000 }).toBe(true);

  // The persistent app host must release onboarding listeners before terminal interaction.
  await page.locator("#capsule").click();
  await page.keyboard.press("Escape");
  expect(pageErrors).toBe(0);

  // Keep only the resident credential; identity must come from the authenticator.
  await context.clearCookies();
  await page.evaluate(() => localStorage.clear());
  await page.reload();
  await expect(page.locator("#login-passkey")).toBeVisible();
  await expect(page.locator("#account-id")).toHaveCount(0);
  await expect(page.locator("#device-name")).toHaveCount(0);
  await expect(page.locator("#setup-card")).toHaveCount(0);
  await page.setViewportSize({ width: 390, height: 844 });
  await page.screenshot({ path: testInfo.outputPath("signin-dark-small.png") });
  for (const colorScheme of ["light", "dark"] as const) {
    await page.emulateMedia({ colorScheme });
    await page.setViewportSize({ width: 390, height: 844 });
    const path = testInfo.outputPath(`signin-${colorScheme}.png`);
    await page.screenshot({ path });
    await testInfo.attach(`signin-${colorScheme}`, { path, contentType: "image/png" });
  }
  await page.setViewportSize({ width: 1280, height: 720 });
  const returningSigninSamples: number[] = [];
  for (let attempt = 0; attempt < signinTrials; attempt += 1) {
    await instrumentPasskeyGet(page);
    const started = await page.evaluate(() => performance.now());
    await page.getByRole("button", { name: "Continue with passkey" }).click();
    await expect.poll(() => page.evaluate(() => window.__tracerTestDouble?.isConnected() === true), { timeout: 30_000 }).toBe(true);
    returningSigninSamples.push(await page.evaluate((start) => performance.now() - start, started));
    expect(await page.evaluate(() => document.documentElement.dataset.passkeyGets)).toBe("1");
    if (attempt + 1 < signinTrials) {
      await context.clearCookies();
      await page.evaluate(() => localStorage.clear());
      await page.reload();
      await expect(page.locator("#login-passkey")).toBeVisible();
    }
  }
  const returningSigninSorted = returningSigninSamples.sort((left, right) => left - right);
  const returningSigninP50 = percentile(returningSigninSorted, 0.5);
  const returningSigninP99 = percentile(returningSigninSorted, 0.99);
  const returningSigninBudgetMs = 5_000;
  console.log(
    `METRIC name=returning_signin_terminal_usable source=tracer-production-build n=${returningSigninSamples.length} ` +
      `p50_ms=${returningSigninP50.toFixed(2)} p99_ms=${returningSigninP99.toFixed(2)} ` +
      `budget_ms=${returningSigninBudgetMs} result=${returningSigninP99 <= returningSigninBudgetMs ? "PASS" : "FAIL"}`,
  );

  expect(await page.evaluate(() => window.__tracerTestDouble?.predictiveEcho()?.optedIn)).toBe(false);
  await page.goto("/?mock=1&predict=1");
  await expect.poll(() => page.evaluate(() => window.__tracerTestDouble?.isConnected() === true), { timeout: 30_000 }).toBe(true);
  await expect.poll(() => page.evaluate(() => window.__tracerTestDouble?.predictiveEcho()?.roundTripMs ?? 0))
    .toBeGreaterThan(60);
  await page.evaluate(() => window.__tracerTestDouble?.seedPrompt());
  await expect.poll(() => page.evaluate(() => window.__tracerTestDouble?.rendererMetrics()?.cursorVisible ?? false)).toBe(true);

  await page.keyboard.press("a");
  await expect.poll(() => page.evaluate(() => window.__tracerTestDouble?.predictiveEcho()?.pendingText ?? ""))
    .toBe("a");
  await expect.poll(async () => {
    const state = await (await context.request.get("/__mock/state")).json() as { echoed_text: string };
    return state.echoed_text;
  }).toBe("a");
  await expect.poll(() => page.evaluate(() => window.__tracerTestDouble?.screenText() ?? "")).toContain("a");

  // The mock writes b once, drops its Ack and Output, then deduplicates b when it is resent.
  const attachCount = async (): Promise<number> =>
    ((await (await context.request.get("/__mock/state")).json()) as { attach_count: number }).attach_count;
  const attachesBefore = await attachCount();
  await context.request.post("/__mock/drop-next-ack");
  await page.keyboard.press("b");
  await expect.poll(async () => {
    const state = await (await context.request.get("/__mock/state")).json() as { echoed_text: string };
    return state.echoed_text;
  }).toBe("ab");
  // The double closes the socket as it writes b, and the page learns of it one link delay later. Until then
  // `isConnected()` is still true for the old socket, so waiting on it alone let the scenario carry on and type the
  // next key while the page was reconnecting, with no round trip yet (the reattach clears it, and the probe sent
  // with the reattach measures it again). The double's attach count proves the resume happened first (#438).
  await expect.poll(attachCount, { timeout: 30_000 }).toBeGreaterThan(attachesBefore);
  await expect.poll(() => page.evaluate(() => window.__tracerTestDouble?.isConnected() === true), { timeout: 30_000 }).toBe(true);
  await expect.poll(() => page.evaluate(() => window.__tracerTestDouble?.screenText() ?? "")).toContain("ab");
  await expect.poll(() => page.evaluate(() => window.__tracerTestDouble?.predictiveEcho()?.roundTripMs ?? 0))
    .toBeGreaterThan(60);
  const resumedState = await (await context.request.get("/__mock/state")).json() as {
    echoed_text: string;
    accepted_input_bytes: number;
  };
  expect(resumedState.echoed_text).toBe("ab");
  expect(resumedState.accepted_input_bytes).toBe(2);

  const predictionState = () => page.evaluate(() => window.__tracerTestDouble?.predictiveEcho());
  const inject = (data: string) => page.evaluate((value) => window.__tracerTestDouble?.injectInput(value), data);
  const resetScreen = async (): Promise<void> => {
    const state = await page.evaluate(async () => {
      const response = await fetch("/__mock/screen-reset", { method: "POST", cache: "no-store" });
      if (!response.ok) throw new Error(`screen reset returned HTTP ${response.status}`);
      return await response.json() as { output_sequence: string };
    });
    await expect.poll(async () => BigInt(await page.evaluate(
      () => window.__tracerTestDouble?.rendererMetrics()?.outputSequence ?? "0",
    ))).toBeGreaterThanOrEqual(BigInt(state.output_sequence));
  };
  const waitForPendingText = async (expected: string): Promise<void> => {
    await expect.poll(async () => (await predictionState())?.pendingText ?? "").toBe(expected);
  };

  // A no-echo prompt clears the one speculative character at its measured echo deadline.
  await context.request.post("/__mock/echo-mode", { data: { mode: "none" } });
  await inject("p");
  await waitForPendingText("p");
  await expect.poll(async () => (await predictionState())?.muted ?? false, { timeout: 3000 }).toBe(true);
  await waitForPendingText("");
  await context.request.post("/__mock/echo-mode", { data: { mode: "normal" } });
  await inject("q");
  await expect.poll(async () => (await predictionState())?.muted ?? true).toBe(false);

  // Alternate-screen entry suspends prediction; it resumes after a normal-screen write.
  await context.request.post("/__mock/alternate-screen", { data: { active: true } });
  await expect.poll(async () => (await predictionState())?.reason ?? "").toBe("unsafe-screen");
  await inject("u");
  await waitForPendingText("");
  await context.request.post("/__mock/alternate-screen", { data: { active: false } });
  await expect.poll(async () => (await predictionState())?.enabled ?? false).toBe(true);

  // A wrong echo removes the overlay and three consecutive mismatches mute prediction.
  await context.request.post("/__mock/echo-mode", { data: { mode: "wrong" } });
  for (const [index, key] of ["m", "n", "o"].entries()) {
    await inject(key);
    await expect.poll(async () => (await predictionState())?.mispredictions ?? 0).toBe(index + 1);
    await waitForPendingText("");
  }
  await expect.poll(async () => (await predictionState())?.muted ?? false).toBe(true);
  await context.request.post("/__mock/echo-mode", { data: { mode: "normal" } });
  await inject("r");
  await expect.poll(async () => (await predictionState())?.muted ?? true).toBe(false);

  // Backspace, horizontal cursor movement and multi-grapheme paste wait for host output.
  await resetScreen();
  await page.evaluate(() => window.__tracerTestDouble?.seedPrompt());
  let beforeTyping = Number(await page.evaluate(() => window.__tracerTestDouble?.rendererMetrics()?.outputSequence ?? "0"));
  await inject("ABC");
  await expect.poll(() => page.evaluate(() => window.__tracerTestDouble?.screenText() ?? "")).toContain("ABC");
  await expect.poll(async () => Number(await page.evaluate(() => window.__tracerTestDouble?.rendererMetrics()?.outputSequence ?? "0")))
    .toBeGreaterThanOrEqual(beforeTyping + 3);
  const outputBeforeMove = Number(await page.evaluate(() => window.__tracerTestDouble?.rendererMetrics()?.outputSequence ?? "0"));
  const cursorBeforeMove = Number(await page.evaluate(() => window.__tracerTestDouble?.rendererMetrics()?.cursorX ?? 0));
  await inject("\u001b[D");
  await expect.poll(async () => Number(await page.evaluate(() => window.__tracerTestDouble?.rendererMetrics()?.outputSequence ?? "0")))
    .toBeGreaterThanOrEqual(outputBeforeMove + 3);
  const cursorAfterMove = Number(await page.evaluate(() => window.__tracerTestDouble?.rendererMetrics()?.cursorX ?? 0));
  expect(cursorAfterMove).toBe(cursorBeforeMove - 1);
  // Late enough to pass the mute deadline (two round trips plus guards), so the muted window is observable.
  await context.request.post("/__mock/echo-mode", { data: { mode: "normal", delay_ms: 1500 } });
  await inject("Z");
  await waitForPendingText("Z");
  await expect.poll(() => page.evaluate(() => window.__tracerTestDouble?.predictiveEcho()?.overlay?.text ?? "")).toBe("Z");
  const movedCursor = await page.evaluate(() => ({
    x: window.__tracerTestDouble?.predictiveEcho()?.overlay?.glyphs[0]?.x ?? Number.NaN,
    cellWidth: window.__tracerTestDouble?.rendererMetrics()?.cellWidth ?? 0,
    cursorX: window.__tracerTestDouble?.rendererMetrics()?.cursorX ?? 0,
  }));
  expect(movedCursor.cursorX).toBe(cursorAfterMove);
  expect(movedCursor.x).toBeCloseTo(movedCursor.cellWidth * cursorAfterMove, 1);
  await expect.poll(() => page.evaluate(() => window.__tracerTestDouble?.screenText() ?? "")).toContain("Z");
  // This intentionally delayed echo exceeds the mute deadline; require a fresh host proof before resuming.
  await expect.poll(async () => (await predictionState())?.muted ?? false).toBe(true);
  await context.request.post("/__mock/echo-mode", { data: { mode: "normal" } });
  await inject("y");
  await expect.poll(async () => (await predictionState())?.muted ?? true).toBe(false);
  await resetScreen();
  await page.evaluate(() => window.__tracerTestDouble?.seedPrompt());
  await expect.poll(async () => (await predictionState())?.enabled ?? false).toBe(true);
  beforeTyping = Number(await page.evaluate(() => window.__tracerTestDouble?.rendererMetrics()?.outputSequence ?? "0"));
  await inject("ABCZ");
  await waitForPendingText("ABCZ");
  await expect.poll(() => page.evaluate(() => window.__tracerTestDouble?.screenText() ?? "")).toContain("ABCZ");
  await expect.poll(async () => Number(await page.evaluate(() => window.__tracerTestDouble?.rendererMetrics()?.outputSequence ?? "0")))
    .toBeGreaterThanOrEqual(beforeTyping + 4);
  const beforeBackspace = Number(await page.evaluate(() => window.__tracerTestDouble?.rendererMetrics()?.outputSequence ?? "0"));
  await inject("\u007f");
  await waitForPendingText("");
  await expect.poll(async () => Number(await page.evaluate(() => window.__tracerTestDouble?.rendererMetrics()?.outputSequence ?? "0")))
    .toBeGreaterThanOrEqual(beforeBackspace + 3);
  const afterBackspace = await page.evaluate(() => window.__tracerTestDouble?.screenText() ?? "");
  expect(afterBackspace).toContain("ABC");
  expect(afterBackspace).not.toContain("ABCZ");
  beforeTyping = Number(await page.evaluate(() => window.__tracerTestDouble?.rendererMetrics()?.outputSequence ?? "0"));
  await inject("pasted words");
  await waitForPendingText("");
  await expect.poll(() => page.evaluate(() => window.__tracerTestDouble?.screenText() ?? ""))
    .toContain("pasted words");
  await expect.poll(async () => Number(await page.evaluate(() => window.__tracerTestDouble?.rendererMetrics()?.outputSequence ?? "0")))
    .toBeGreaterThanOrEqual(beforeTyping + 12);
  // The host echoes this one after a single round trip (about 300 ms), so the pending prediction lives only that long and
  // a polling wait can miss it entirely on a loaded host. Read it in the same browser task as the input instead.
  expect(await page.evaluate((data) => {
    window.__tracerTestDouble?.injectInput(data);
    return window.__tracerTestDouble?.predictiveEcho()?.pendingText ?? "";
  }, "ok")).toBe("ok");
  await expect.poll(() => page.evaluate(() => window.__tracerTestDouble?.screenText() ?? "")).toContain("ok");
  await waitForPendingText("");
  await context.request.post("/__mock/echo-mode", { data: { mode: "normal" } });

  // Seeded key and echo-delay schedules compare the live Ghostty screen to a second Ghostty replay.
  await resetScreen();
  await page.evaluate(() => window.__tracerTestDouble?.seedPrompt());
  for (let seed = 1; seed <= 24; seed += 1) {
    const random = seededRandom(seed);
    const delayMs = Math.floor(random() * 151);
    await context.request.post("/__mock/echo-mode", { data: { mode: "normal", delay_ms: delayMs } });
    const keys = ["a", "B", " ", "é", "\u007f", "\u001b[D", "\u001b[C", "pasted", "👩🏽‍💻"];
    for (let index = 0; index < 6; index += 1) {
      const key = keys[Math.floor(random() * keys.length)] ?? "a";
      await inject(key);
      await page.waitForTimeout(Math.floor(random() * 31));
    }
    await page.waitForTimeout(delayMs + 350);
  }
  const differential = await (await context.request.get("/__mock/state?input_bytes=1")).json() as { input_bytes: number[] };
  const finalWithPrediction = await page.evaluate(() => window.__tracerTestDouble?.screenText() ?? "");
  let lastReset = -1;
  for (let index = 0; index + 1 < differential.input_bytes.length; index += 1) {
    if (differential.input_bytes[index] === 0x1b && differential.input_bytes[index + 1] === 0x63) lastReset = index;
  }
  expect(lastReset).toBeGreaterThanOrEqual(0);
  const replayBytes = [
    ...differential.input_bytes.slice(0, lastReset + 2),
    0x24,
    0x20,
    ...differential.input_bytes.slice(lastReset + 2),
  ];
  const finalWithoutPrediction = await page.evaluate(
    (bytes) => window.__tracerTestDouble?.baselineScreenText(bytes) ?? Promise.resolve(""),
    replayBytes,
  );
  expect(finalWithPrediction).toBe(finalWithoutPrediction);

  const terminalScreenshot = await page.screenshot({ fullPage: true });
  const terminalScreenshotPath = testInfo.outputPath("tracer-terminal.png");
  await writeFile(terminalScreenshotPath, terminalScreenshot);
  await testInfo.attach("tracer-terminal.png", {
    path: terminalScreenshotPath,
    contentType: "image/png",
  });

  // The probe serializes keys through a completed paint so its latency samples do not measure burst queueing.
  await context.request.post("/__mock/trace/reset");
  // p99 of 20 keys is just the slowest key; 100 makes it the 99th of 100 (#447 round 3). The functional suite, which
  // asserts no speed (#314), keeps 20 to stay quick.
  const probeCount = latencySamples ? 100 : 20;
  // Each probe key waits for its echo, about one round trip; allow a second per key, and never under 20 s.
  const probeTimeoutMs = Math.max(20_000, probeCount * 1_000);
  // The throughput probe deliberately starts a fresh PTY; normal reloads now
  // keep the tab's public session id instead of silently opening another shell.
  await page.evaluate(() => sessionStorage.clear());
  await page.goto(`/?probe=1&n=${probeCount}&mock=1&predict=1`);
  await expect.poll(() => page.evaluate(() => window.__tracerTestDouble?.isConnected() === true), { timeout: 30_000 }).toBe(true);
  await expect.poll(() => page.evaluate(() => window.__tracerTestDouble?.predictiveEcho()?.roundTripMs ?? 0))
    .toBeGreaterThan(60);
  await page.evaluate(() => window.__tracerTestDouble?.seedPrompt());
  const clockCalibration = await page.evaluate(async () => {
    const samples: Array<{ offsetMs: number; roundTripMs: number }> = [];
    for (let index = 0; index < 5; index += 1) {
      const startedAt = performance.now();
      const response = await fetch("/__mock/clock", { cache: "no-store" });
      const body = await response.json() as { monotonic_ns: string };
      const endedAt = performance.now();
      const serverAtMs = Number(body.monotonic_ns) / 1_000_000;
      samples.push({
        offsetMs: (startedAt + endedAt) / 2 - serverAtMs,
        roundTripMs: endedAt - startedAt,
      });
    }
    samples.sort((left, right) => left.roundTripMs - right.roundTripMs);
    return samples[0] ?? { offsetMs: 0, roundTripMs: 0 };
  });
  const measuredRttMs = Number(await page.evaluate(() => window.__tracerTestDouble?.predictiveEcho()?.roundTripMs ?? 0));
  console.log(
    `METRIC name=tracer_rtt_measurement source=tracer-production-build configured_ms=${testRttMs} ` +
      `measured_ms=${measuredRttMs.toFixed(2)} http_clock_sample_ms=${clockCalibration.roundTripMs.toFixed(2)}`,
  );
  await expect(page.locator("#probe-run")).toBeEnabled();
  // The clock calibration above takes about two seconds, long enough for the attachment to be confirmed again after a
  // route refresh; the probe refuses to start on an unconfirmed terminal, so wait for the state it checks, then click.
  await expect.poll(() => page.evaluate(() => window.__tracerTestDouble?.isConnected() === true), { timeout: 30_000 }).toBe(true);
  await page.locator("#probe-run").click();
  await expect.poll(
    async () => (await page.locator("#probe-results").textContent()) ?? "",
    { timeout: probeTimeoutMs },
  ).toContain("p99:");
  const probeState = await (await context.request.get("/__mock/state")).json() as {
    echoed_text: string;
    accepted_input_bytes: number;
    output_sequence: string;
  };
  const probeKeys = "abcdefghijklmnopqrstuvwxyz0123456789";
  const expectedProbeText = Array.from({ length: probeCount }, (_, index) => probeKeys[index % probeKeys.length]).join("");
  expect(probeState.echoed_text).toBe(expectedProbeText);
  expect(probeState.accepted_input_bytes).toBe(probeCount);
  expect(probeState.output_sequence).toBe(String(probeCount));
  await expect(page.locator("#probe-results")).toContainText(`Painted echoes: ${probeCount} / ${probeCount}`);
  // Each drop is a browser reconnect after a lost link: a new socket and the first-message resume, D267's "after a
  // network change" row. The latency profile (INFRATERNAL_LATENCY_PROFILE=1) takes as many samples as the perf VM.
  const reconnectTrials = latencySamples ? 20 : 1;
  const resumeSamples: number[] = [];
  const lastScreenSamples: number[] = [];
  for (let attempt = 0; attempt < reconnectTrials; attempt += 1) {
    await expect(page.locator("#probe-drop")).toBeEnabled();
    lastScreenSamples.push(await dropAndTimeLastScreen(page));
    await expect.poll(async () => (await page.locator("#probe-results").textContent()) ?? "")
      .toMatch(/Time to resume: [0-9.]+ ms/);
    resumeSamples.push(readResumeDuration(await page.locator("#probe-results").textContent()));
  }
  const resumeSorted = resumeSamples.sort((left, right) => left - right);
  const resumeP50 = percentile(resumeSorted, 0.5);
  const resumeP99 = percentile(resumeSorted, 0.99);
  // D375/D267: four round trips (connect, TLS, upgrade, resume token) + 50 ms; "RTT x 2 + 300 ms" is retired.
  const resumeBudgetMs = 4 * roundTripBoundMs(testRttMs) + RECONNECT_ALLOWANCE_MS;
  console.log(d375Row({
    key: "reconnect_network_change", source: "tracer-production-build", n: resumeSamples.length, value: resumeP99,
    unit: "ms", target: resumeBudgetMs, extra: `p50_ms=${resumeP50.toFixed(2)} rtt_ms=${testRttMs}`,
  }).line);
  const lastScreenSorted = lastScreenSamples.sort((left, right) => left - right);
  console.log(d375Row({
    key: "reconnect_last_screen", source: "tracer-production-build", n: lastScreenSorted.length,
    value: percentile(lastScreenSorted, 0.99), unit: "ms", target: FRAME_MS,
    extra: `p50_ms=${percentile(lastScreenSorted, 0.5).toFixed(2)}`,
  }).line);
  const probeReport = (await page.locator("#probe-results").textContent()) ?? "";
  console.log(`S1 probe result (${probeCount} keys)\n${probeReport}`);
  await testInfo.attach("tracer-probe-results.txt", {
    body: probeReport,
    contentType: "text/plain",
  });
  const browserTrace = await page.evaluate(() => window.__tracerTestDouble?.trace() ?? []);
  const keySamples = browserTrace.flatMap((sample) => {
    const started = sample.stages.keydown;
    const received = sample.stages.wsMessage;
    const painted = sample.stages.paint;
    const predicted = sample.stages.prediction;
    const onData = sample.stages.onData;
    const sent = sample.stages.wsSend;
    return started !== undefined && received !== undefined && painted !== undefined &&
      onData !== undefined && sent !== undefined
      ? [{
        received: received - started,
        confirmed: painted - started,
        predicted: (predicted ?? painted) - started,
        overlayVisible: predicted !== undefined,
        cpu: sent - onData,
      }]
      : [];
  });
  expect(keySamples).toHaveLength(probeCount);
  const confirmedMs = keySamples.map((sample) => sample.confirmed).sort((left, right) => left - right);
  const predictedMs = keySamples.map((sample) => sample.predicted).sort((left, right) => left - right);
  const cpuOnMs = keySamples.map((sample) => sample.cpu).sort((left, right) => left - right);
  const confirmedP50 = percentile(confirmedMs, 0.5);
  const confirmedP99 = percentile(confirmedMs, 0.99);
  const predictedP50 = percentile(predictedMs, 0.5);
  const predictedP99 = percentile(predictedMs, 0.99);
  const predictedOverlayCount = keySamples.filter((sample) => sample.overlayVisible).length;
  // D375: the real echo may take the round trip plus two 120 Hz frames.
  const echoBudgetMs = roundTripBoundMs(testRttMs) + 2 * FRAME_MS;
  console.log(
    `METRIC name=keystroke_echo_confirmed_prediction_on source=tracer-production-build n=${keySamples.length} ` +
      `p50_ms=${confirmedP50.toFixed(2)} p99_ms=${confirmedP99.toFixed(2)} ` +
      `profile_budget_ms=${echoBudgetMs} measured_rtt_ms=${measuredRttMs.toFixed(2)} result=REPORT`,
  );
  const predictedSamples = keySamples.filter((sample) => sample.overlayVisible)
    .map((sample) => sample.predicted).sort((left, right) => left - right);
  const predictionFallbackCount = keySamples.length - predictedOverlayCount;
  const fallbackReasons = await page.evaluate(() => window.__tracerTestDouble?.predictiveEcho()?.fallbacks ?? {});
  const predictionCost = (await page.evaluate(() => window.__tracerTestDouble?.predictiveEcho()?.inputCostMs ?? []))
    .slice(-probeCount).sort((left, right) => left - right);
  console.log(
    `METRIC name=keystroke_prediction_cpu source=tracer-production-build n=${predictionCost.length} ` +
      `p50_ms=${percentile(predictionCost, 0.5).toFixed(3)} p99_ms=${percentile(predictionCost, 0.99).toFixed(3)} budget_ms=2 ` +
      `result=${predictionCost.length > 0 && percentile(predictionCost, 0.99) <= 2 ? "PASS" : "FAIL"}`,
  );
  console.log(`METRIC name=keystroke_prediction_fallback_reasons source=tracer-production-build reasons=${JSON.stringify(fallbackReasons)} result=REPORT`);
  // D375 row: every key counts, so a key prediction declined shows up as its (slow) real echo.
  console.log(d375Row({
    key: "predicted_glyph", source: "tracer-production-build", n: predictedMs.length, value: predictedP99, unit: "ms",
    target: FRAME_MS,
    extra: `p50_ms=${predictedP50.toFixed(2)} overlay_n=${predictedOverlayCount} fallback_n=${predictionFallbackCount}`,
  }).line);
  console.log(
    `METRIC name=keystroke_predicted_glyph_visible_prediction_on source=tracer-production-build n=${predictedSamples.length} ` +
      `p50_ms=${percentile(predictedSamples, 0.5).toFixed(2)} p99_ms=${percentile(predictedSamples, 0.99).toFixed(2)} ` +
      `budget_ms=${FRAME_MS.toFixed(2)} ` +
      `result=${predictedSamples.length > 0 && percentile(predictedSamples, 0.99) <= FRAME_MS ? "PASS" : "FAIL"}`,
  );
  console.log(
    `METRIC name=keystroke_browser_cpu_prediction_on source=tracer-production-build n=${cpuOnMs.length} ` +
      `p50_ms=${percentile(cpuOnMs, 0.5).toFixed(3)} p99_ms=${percentile(cpuOnMs, 0.99).toFixed(3)} unit_ms_per_key result=REPORT`,
  );
  const serverTraceResponse = await context.request.get("/__mock/trace");
  const serverTraceBody = await serverTraceResponse.json() as { events: DoubleTraceEvent[] };
  const attribution = summarizeAttribution(browserTrace, serverTraceBody.events, clockCalibration);
  expect(browserTrace).toHaveLength(probeCount);
  console.log(`S1 per-hop attribution (${probeCount} keys)\n${attribution.report}`);
  const attributionPath = testInfo.outputPath("tracer-attribution.json");
  await writeFile(attributionPath, JSON.stringify({
    clockCalibration,
    browserTrace,
    serverTrace: serverTraceBody.events,
    report: attribution.report,
  }, null, 2));
  await testInfo.attach("tracer-attribution.json", { path: attributionPath, contentType: "application/json" });
  await testInfo.attach("tracer-attribution.txt", {
    body: attribution.report,
    contentType: "text/plain",
  });
  const probeScreenshotPath = testInfo.outputPath("tracer-probe.png");
  await page.screenshot({ fullPage: true, path: probeScreenshotPath });
  await testInfo.attach("tracer-probe.png", {
    path: probeScreenshotPath,
    contentType: "image/png",
  });
  console.log(`S1 screenshots: ${terminalScreenshotPath}, ${probeScreenshotPath}`);
  await page.locator("#probe-copy").click();
  await expect(page.locator("#probe-message")).toContainText(/Results copied|Clipboard unavailable/);

  await page.evaluate(() => window.__tracerTestDouble?.setPredictiveEcho(false));
  await expect.poll(() => page.evaluate(() => window.__tracerTestDouble?.predictiveEcho()?.optedIn ?? true)).toBe(false);
  await expect(page.locator("#probe-run")).toBeEnabled();
  await page.locator("#probe-run").click();
  await expect.poll(
    async () => (await page.locator("#probe-results").textContent()) ?? "",
    { timeout: probeTimeoutMs },
  ).toContain(`Painted echoes: ${probeCount} / ${probeCount}`);
  const offTrace = await page.evaluate(() => window.__tracerTestDouble?.trace() ?? []);
  const offSamples = offTrace.flatMap((sample) => {
    const started = sample.stages.keydown;
    const painted = sample.stages.paint;
    const onData = sample.stages.onData;
    const sent = sample.stages.wsSend;
    return started !== undefined && painted !== undefined && painted >= started &&
      onData !== undefined && sent !== undefined
      ? [{ confirmed: painted - started, painted: painted - started, cpu: sent - onData }]
      : [];
  });
  expect(offSamples).toHaveLength(probeCount);
  // The browser's own share of a key with prediction off: keydown to the socket send, plus the echo's arrival to its
  // paint. The network and the test double sit between those two spans and are excluded. The latency report adds the
  // real agent's no-network echo p99 to this p99 to form the D375 own-overhead row (an upper bound on the true p99).
  const browserOwnMs = offTrace.flatMap((sample) => {
    const { keydown, wsSend, wsMessage, paint } = sample.stages;
    return keydown !== undefined && wsSend !== undefined && wsMessage !== undefined && paint !== undefined &&
      wsSend >= keydown && paint >= wsMessage
      ? [(wsSend - keydown) + (paint - wsMessage)]
      : [];
  }).sort((left, right) => left - right);
  console.log(
    `METRIC name=own_overhead_browser source=tracer-production-build display=${latencyDisplay()} n=${browserOwnMs.length} ` +
      `p50_ms=${percentile(browserOwnMs, 0.5).toFixed(2)} p99_ms=${percentile(browserOwnMs, 0.99).toFixed(2)} result=REPORT`,
  );
  const offConfirmed = offSamples.map((sample) => sample.confirmed).sort((left, right) => left - right);
  const offVisible = offSamples.map((sample) => sample.painted).sort((left, right) => left - right);
  const cpuOff = offSamples.map((sample) => sample.cpu).sort((left, right) => left - right);
  // D375 row: with prediction off, the letter appears only when the host's real echo is painted.
  console.log(d375Row({
    key: "real_echo", source: "tracer-production-build", n: offVisible.length, value: percentile(offVisible, 0.99),
    unit: "ms", target: echoBudgetMs, extra: `p50_ms=${percentile(offVisible, 0.5).toFixed(2)} rtt_ms=${testRttMs}`,
  }).line);
  console.log(
    `METRIC name=keystroke_echo_confirmed_prediction_off source=tracer-production-build n=${offConfirmed.length} ` +
      `p50_ms=${percentile(offConfirmed, 0.5).toFixed(2)} p99_ms=${percentile(offConfirmed, 0.99).toFixed(2)} ` +
      `profile_budget_ms=${echoBudgetMs} measured_rtt_ms=${measuredRttMs.toFixed(2)} result=REPORT`,
  );
  console.log(
    `METRIC name=keystroke_browser_cpu_prediction_off source=tracer-production-build n=${cpuOff.length} ` +
      `p50_ms=${percentile(cpuOff, 0.5).toFixed(3)} p99_ms=${percentile(cpuOff, 0.99).toFixed(3)} unit_ms_per_key result=REPORT`,
  );
  return { returningSigninP99, returningSigninBudgetMs, predictedP99, resumeP99, resumeBudgetMs };
}

interface DoubleTraceEvent {
  id: string;
  stage: "doubleReceive" | "doubleDecode" | "doubleEchoEncode" | "doubleEchoSend";
  atNs: string;
}

interface ClockCalibration {
  offsetMs: number;
  roundTripMs: number;
}

/** Counts one virtual passkey request per returning sign-in trial without logging credential data. */
async function instrumentPasskeyGet(page: import("playwright/test").Page): Promise<void> {
  await page.evaluate(() => {
    const get = navigator.credentials.get.bind(navigator.credentials);
    document.documentElement.dataset.passkeyGets = "0";
    navigator.credentials.get = (options) => {
      document.documentElement.dataset.passkeyGets = String(Number(document.documentElement.dataset.passkeyGets) + 1);
      return get(options);
    };
  });
}

/** Parse the exact duration the production probe reports from a completed reconnect. */
/**
 * Drops the terminal's socket through the probe and times how long until a frame shows the last screen while the link
 * is down (D375 "reconnect, last screen": 8.3 ms, drawn from the device's own copy).
 *
 * The clock starts at the click and stops at the first animation frame in which the terminal reports the link down,
 * still holds exactly the text it held before the drop, and its canvas is visible. The drop itself runs the probe's
 * normal handler, so the resume stopwatch it reports is unaffected. Rejects after 5 s if no such frame happens.
 */
async function dropAndTimeLastScreen(page: Page): Promise<number> {
  return page.evaluate(() => new Promise<number>((resolve, reject) => {
    const double = window.__tracerTestDouble;
    const button = document.querySelector<HTMLButtonElement>("#probe-drop");
    const before = double?.screenText() ?? "";
    if (!double || !button || before.trim() === "") {
      reject(new Error("the probe drop or the terminal's screen is unavailable"));
      return;
    }
    // The renderer's canvas, not the prediction overlay: the overlay is a separate canvas that stays hidden while no
    // prediction is pending, so "any canvas" would wrongly read as "the screen is gone".
    const shown = (): boolean => Array.from(document.querySelectorAll<HTMLCanvasElement>("#terminal-screen canvas"))
      .filter((canvas) => !canvas.classList.contains("terminal-text-overlay"))
      .some((canvas) => {
        const style = getComputedStyle(canvas);
        const box = canvas.getBoundingClientRect();
        return style.visibility !== "hidden" && style.display !== "none" && Number(style.opacity) > 0 &&
          box.width > 0 && box.height > 0;
      });
    const started = performance.now();
    button.click();
    let last = { linkDown: false, sameText: false, shown: false };
    const check = (at: number): void => {
      last = { linkDown: !double.isConnected(), sameText: double.screenText() === before, shown: shown() };
      if (last.linkDown && last.sameText && last.shown) {
        resolve(Math.max(0, at - started));
      } else if (performance.now() - started > 5_000) {
        reject(new Error(`no frame showed the last screen while the link was down: ${JSON.stringify(last)}`));
      } else {
        requestAnimationFrame(check);
      }
    };
    requestAnimationFrame(check);
  }));
}

function readResumeDuration(report: string | null): number {
  const match = /Time to resume: ([\d.]+) ms/.exec(report ?? "");
  if (!match) throw new Error("resume probe did not report a completed duration");
  return Number(match[1]);
}

interface BrowserTraceSample {
  id: string;
  stages: Partial<Record<
    "keydown" | "onData" | "encode" | "wsSend" | "wsMessage" | "decode" | "termWrite" | "writeCallback" | "paint" | "prediction",
    number
  >>;
}

/** Joins browser performance.now marks and double hrtime marks using the lowest-RTT clock sample. */
function summarizeAttribution(
  browserTrace: BrowserTraceSample[],
  serverTrace: DoubleTraceEvent[],
  clock: ClockCalibration,
): { report: string; samples: Array<{ id: string; stages: Record<string, number> }> } {
  const stagesById = new Map<string, Record<string, number>>();
  for (const sample of browserTrace) stagesById.set(sample.id, { ...sample.stages });
  for (const event of serverTrace) {
    const stages = stagesById.get(event.id);
    if (stages) stages[event.stage] = Number(event.atNs) / 1_000_000 + clock.offsetMs;
  }

  const hops: ReadonlyArray<readonly [string, string, string]> = [
    ["keydown → onData", "keydown", "onData"],
    ["onData → encode", "onData", "encode"],
    ["encode → ws.send", "encode", "wsSend"],
    ["ws.send → double receive", "wsSend", "doubleReceive"],
    ["double receive → decode", "doubleReceive", "doubleDecode"],
    ["double decode → echo encode", "doubleDecode", "doubleEchoEncode"],
    ["double echo encode → send", "doubleEchoEncode", "doubleEchoSend"],
    ["double echo send → ws.onmessage", "doubleEchoSend", "wsMessage"],
    ["ws.onmessage → decode", "wsMessage", "decode"],
    ["decode → term.write", "decode", "termWrite"],
    ["term.write → write callback", "termWrite", "writeCallback"],
    ["write callback → paint rAF", "writeCallback", "paint"],
  ];
  const lines = [
    `Clock alignment: ${clock.offsetMs.toFixed(3)} ms offset; best HTTP RTT ${clock.roundTripMs.toFixed(3)} ms (cross-process one-way splits assume a symmetric local path).`,
    `Trace coverage: ${browserTrace.length} browser keys, ${serverTrace.length} double marks.`,
  ];
  for (const [label, from, to] of hops) {
    const durations = [...stagesById.values()].flatMap((stages) => {
      const start = stages[from];
      const end = stages[to];
      return start !== undefined && end !== undefined ? [Math.max(0, end - start)] : [];
    }).sort((left, right) => left - right);
    lines.push(durations.length === 0
      ? `${label}: n/a (0 keys)`
      : `${label}: p50 ${percentile(durations, 0.5).toFixed(2)} ms, p99 ${percentile(durations, 0.99).toFixed(2)} ms (${durations.length} keys)`);
  }
  return {
    report: lines.join("\n"),
    samples: [...stagesById.entries()].map(([id, stages]) => ({ id, stages })),
  };
}

function percentile(sorted: number[], fraction: number): number {
  const rank = Math.max(0, Math.ceil(sorted.length * fraction) - 1);
  return sorted[rank] ?? 0;
}

/** Creates repeatable key and echo-delay schedules without shared random state. */
function seededRandom(seed: number): () => number {
  let state = seed >>> 0;
  return () => {
    state = (Math.imul(state, 1_664_525) + 1_013_904_223) >>> 0;
    return state / 0x1_0000_0000;
  };
}
