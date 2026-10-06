/** Browser contract test: virtual passkey, auth round trip, echo, dedupe, probe and screenshot. */
import { writeFile } from "node:fs/promises";
import { expect, test } from "playwright/test";

test("first run, passkey login, terminal resume, and the latency probe", async ({ page }, testInfo) => {
  const context = page.context();
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
  await expect.poll(() => page.evaluate(() => window.__tracerTestDouble?.isConnected() === true)).toBe(true);

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
  await page.evaluate(() => {
    const get = navigator.credentials.get.bind(navigator.credentials);
    document.documentElement.dataset.passkeyGets = "0";
    navigator.credentials.get = (options) => {
      document.documentElement.dataset.passkeyGets = String(Number(document.documentElement.dataset.passkeyGets) + 1);
      return get(options);
    };
  });
  await page.getByRole("button", { name: "Continue with passkey" }).click();
  await expect.poll(() => page.evaluate(() => window.__tracerTestDouble?.isConnected() === true)).toBe(true);

  expect(await page.evaluate(() => document.documentElement.dataset.passkeyGets)).toBe("1");

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

  // The probe serializes keys through a completed paint so its latency samples do not measure burst queueing.
  await context.request.post("/__mock/trace/reset");
  const probeCount = 500;
  await page.goto(`/?probe=1&n=${probeCount}&mock=1`);
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
  const probeKeys = "abcdefghijklmnopqrstuvwxyz0123456789";
  const expectedProbeText = Array.from({ length: probeCount }, (_, index) => probeKeys[index % probeKeys.length]).join("");
  expect(probeState.echoed_text).toBe(expectedProbeText);
  expect(probeState.accepted_input_bytes).toBe(probeCount);
  expect(probeState.output_sequence).toBe(String(probeCount));
  await expect(page.locator("#probe-results")).toContainText(`Painted echoes: ${probeCount} / ${probeCount}`);
  await page.locator("#probe-drop").click();
  await expect.poll(async () => (await page.locator("#probe-results").textContent()) ?? "")
    .toMatch(/Time to resume: [0-9.]+ ms/);
  const probeReport = (await page.locator("#probe-results").textContent()) ?? "";
  const measuredP99 = /(?:^|\n)p99: ([\d.]+) ms/.exec(probeReport)?.[1];
  expect(measuredP99).toBeDefined();
  expect(Number(measuredP99)).toBeLessThan(20);
  console.log(`S1 probe result (${probeCount} keys)\n${probeReport}`);
  await testInfo.attach("tracer-probe-results.txt", {
    body: probeReport,
    contentType: "text/plain",
  });
  const browserTrace = await page.evaluate(() => window.__tracerTestDouble?.trace() ?? []);
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

/** Access failures must not expose a guessed form or browser exception details. */
test("status failure, invalid setup token, and cancelled passkey have distinct guidance", async ({ page }) => {
  await page.context().request.post("/__mock/reset");
  await page.route("**/auth/status", (route) => route.fulfill({ status: 503, json: {} }));
  await page.goto("/");
  await expect(page.getByRole("alert")).toHaveText("The server could not complete the request. Try again.");
  await expect(page.locator("form")).toHaveCount(0);
  await page.unroute("**/auth/status");
  await page.getByRole("button", { name: "Try again" }).click();
  await page.locator("#setup-token").fill("invalid-input");
  await page.getByRole("button", { name: "Continue" }).click();
  await page.locator("#setup-username").fill("owner");
  await page.getByRole("button", { name: "Continue" }).click();
  await page.getByRole("button", { name: "Create passkey" }).click();
  await expect(page.locator("#passkey-error")).toContainText("The setup token is invalid or expired.");
  await page.route("**/auth/status", (route) => route.fulfill({ json: { setup_required: false } }));
  await page.route("**/auth/login-start", (route) => route.fulfill({ json: {
    ceremony: "cancel-test", options: { publicKey: {
      challenge: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", rpId: "localhost",
      allowCredentials: [], userVerification: "required", extensions: {},
    } },
  } }));
  await page.addInitScript(() => {
    Object.defineProperty(navigator.credentials, "get", { value: async () => {
      throw new DOMException("browser internal diagnostic", "NotAllowedError");
    } });
  });
  await page.goto("/?setup=1");
  await expect(page.locator("#login-passkey")).toBeVisible();
  await page.getByRole("button", { name: "Continue with passkey" }).click();
  await expect(page.locator("#auth-error")).toHaveText("The passkey prompt was cancelled or timed out. Try again when you are ready.");
});

/** Measure the status round trip and access paint across repeated cold documents. */
test("access screens render within the local first-paint budget", async ({ page }) => {
  test.setTimeout(60_000);
  await page.context().request.post("/__mock/reset");
  for (const setupRequired of [true, false]) {
    const samples: number[] = [];
    const firstPaints: number[] = [];
    for (let index = 0; index < 30; index += 1) {
      // Fresh surfaces avoid Chromium reusing an unchanged compositor frame on reload.
      const sample = await page.context().newPage();
      await sample.route("**/auth/status", (route) => route.fulfill({ json: { setup_required: setupRequired } }));
      await sample.goto("/");
      await expect(sample.locator(setupRequired ? "#setup-card" : "#login-passkey")).toBeVisible();
      firstPaints.push(await sample.evaluate(() =>
        performance.getEntriesByName("first-contentful-paint")[0]?.startTime ?? performance.now()));
      // A compositor screenshot confirms painted pixels. The timestamp after capture
      // is an upper bound, including screenshot overhead, rather than FCP telemetry.
      await sample.screenshot();
      samples.push(await sample.evaluate(() => performance.now()));
      await sample.close();
    }
    samples.sort((left, right) => left - right);
    firstPaints.sort((left, right) => left - right);
    const p99 = samples[29] ?? Infinity;
    console.log(`Access render upper bound (${setupRequired ? "setup" : "signin"}, n=30, local production build): p50 ${samples[14]} ms, p99 ${p99} ms`);
    console.log(`Access first-contentful-paint (${setupRequired ? "setup" : "signin"}, n=30, local production build): p50 ${firstPaints[14]} ms, p99 ${firstPaints[29]} ms`);
    expect(p99).toBeLessThan(1000);
  }
});
