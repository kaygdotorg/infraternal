/** Browser contract test: virtual passkey, auth round trip, echo, dedupe, probe and screenshot. */
import { writeFile } from "node:fs/promises";
import { expect, test } from "playwright/test";

test("first run, passkey login, terminal resume, and the latency probe", async ({ page }, testInfo) => {
  const context = page.context();
  await context.request.post("/__mock/reset");
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
  await page.getByRole("button", { name: "Set up the first owner" }).click();
  const setupResponse = await context.request.get("/__mock/setup-token");
  const setupBody = await setupResponse.json() as { setup_token: string };
  await page.locator("#setup-token").fill(setupBody.setup_token);
  await page.locator("#owner-name").fill("Tracer browser test");
  await page.getByRole("button", { name: "Register a passkey" }).click();

  await expect(page.getByRole("heading", { name: "Save your recovery key" })).toBeVisible();
  const recoveryWords = (await page.locator("#recovery-words").textContent())?.trim().split(/\s+/) ?? [];
  expect(recoveryWords).toHaveLength(24);
  const userId = await page.locator("#account-id-value").textContent();
  expect(userId).toMatch(/^[0-9a-f-]{36}$/);
  await page.locator("#recovery-saved").check();
  await page.getByRole("button", { name: "Finish setup" }).click();
  await expect(page.getByText("TEST DOUBLE")).toBeVisible();
  await expect.poll(() => page.evaluate(() => window.__tracerTestDouble?.isConnected() === true)).toBe(true);

  // Keep the virtual authenticator and account UUID, but remove the session cookie to exercise login.
  await context.clearCookies();
  await page.reload();
  await expect(page.locator("#login-form")).toBeVisible();
  await expect(page.locator("#account-id")).toHaveValue(userId ?? "");
  await page.getByRole("button", { name: "Continue with passkey" }).click();
  await expect.poll(() => page.evaluate(() => window.__tracerTestDouble?.isConnected() === true)).toBe(true);

  await page.keyboard.press("a");
  await expect.poll(async () => {
    const state = await (await context.request.get("/__mock/state")).json() as { echoed_text: string };
    return state.echoed_text;
  }).toBe("a");
  await expect.poll(() => page.evaluate(() => window.__tracerTestDouble?.screenText() ?? "")).toContain("a");

  // The mock writes b once, drops its Ack and Output, then deduplicates b when it is resent.
  await context.request.post("/__mock/drop-next-ack");
  await page.keyboard.press("b");
  await expect.poll(async () => {
    const state = await (await context.request.get("/__mock/state")).json() as { echoed_text: string };
    return state.echoed_text;
  }).toBe("ab");
  await expect.poll(() => page.evaluate(() => window.__tracerTestDouble?.isConnected() === true)).toBe(true);
  await expect.poll(() => page.evaluate(() => window.__tracerTestDouble?.screenText() ?? "")).toContain("ab");
  const resumedState = await (await context.request.get("/__mock/state")).json() as {
    echoed_text: string;
    accepted_input_bytes: number;
  };
  expect(resumedState.echoed_text).toBe("ab");
  expect(resumedState.accepted_input_bytes).toBe(2);

  const terminalScreenshot = await page.screenshot({ fullPage: true });
  const terminalScreenshotPath = testInfo.outputPath("tracer-terminal.png");
  await writeFile(terminalScreenshotPath, terminalScreenshot);
  await testInfo.attach("tracer-terminal.png", {
    path: terminalScreenshotPath,
    contentType: "image/png",
  });

  // The phone/headless probe uses the same painted-output callback and adds a real forced-drop round trip.
  await context.request.post("/__mock/trace/reset");
  await page.goto("/?probe=1&n=36&mock=1");
  await expect.poll(() => page.evaluate(() => window.__tracerTestDouble?.isConnected() === true)).toBe(true);
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
  await expect(page.locator("#probe-run")).toBeEnabled();
  await page.locator("#probe-run").click();
  await expect.poll(
    async () => (await page.locator("#probe-results").textContent()) ?? "",
    { timeout: 20_000 },
  ).toContain("p99:");
  const probeState = await (await context.request.get("/__mock/state")).json() as {
    echoed_text: string;
    accepted_input_bytes: number;
    output_sequence: string;
  };
  expect(probeState.echoed_text).toBe("abcdefghijklmnopqrstuvwxyz0123456789");
  expect(probeState.accepted_input_bytes).toBe(36);
  expect(probeState.output_sequence).toBe("36");
  await expect(page.locator("#probe-results")).toContainText("Painted echoes: 36 / 36");
  await page.locator("#probe-drop").click();
  await expect.poll(async () => (await page.locator("#probe-results").textContent()) ?? "")
    .toMatch(/Time to resume: [0-9.]+ ms/);
  const probeReport = (await page.locator("#probe-results").textContent()) ?? "";
  console.log(`S1 probe result (36 keys)\n${probeReport}`);
  await testInfo.attach("tracer-probe-results.txt", {
    body: probeReport,
    contentType: "text/plain",
  });
  const browserTrace = await page.evaluate(() => window.__tracerTestDouble?.trace() ?? []);
  const serverTraceResponse = await context.request.get("/__mock/trace");
  const serverTraceBody = await serverTraceResponse.json() as { events: DoubleTraceEvent[] };
  const attribution = summarizeAttribution(browserTrace, serverTraceBody.events, clockCalibration);
  console.log(`S1 per-hop attribution (36 keys)\n${attribution.report}`);
  await testInfo.attach("tracer-attribution.json", {
    body: JSON.stringify({ clockCalibration, browserTrace, serverTrace: serverTraceBody.events, report: attribution.report }, null, 2),
    contentType: "application/json",
  });
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
});

interface DoubleTraceEvent {
  id: string;
  stage: "doubleReceive" | "doubleDecode" | "doubleEchoEncode" | "doubleEchoSend";
  atNs: string;
}

interface ClockCalibration {
  offsetMs: number;
  roundTripMs: number;
}

interface BrowserTraceSample {
  id: string;
  stages: Partial<Record<
    "keydown" | "onData" | "encode" | "wsSend" | "wsMessage" | "decode" | "termWrite" | "writeCallback" | "paint",
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
