/**
 * First paint on a real phone network (owner, 2026-11-21; #573, D375, D41): how long a person on 4G or fast 3G waits
 * to see the sign-in screen, and to see a connected terminal, on the production server and the production tracer.
 *
 * Each sample is a cold start: a fresh browser context (empty HTTP cache), the phone's CPU slowed 4x, and the
 * network shaped by Chromium's own emulation. The profiles (DevTools numbers, the same ones J1069 measured with):
 *
 * | Profile | Down | Up | Latency |
 * |---|---|---|---|
 * | `4g` | 9 Mbps | 9 Mbps | 170 ms |
 * | `3g` (fast 3G) | 1.6 Mbps | 750 kbps | 562.5 ms |
 *
 * `signin` is the first frame showing the sign-in button of a signed-out visit, and `connected` the first frame after
 * a signed-in visit's terminal says it is connected, both from navigation start through the page's own clock
 * (`first-paint-recorder.ts`). It prints four reported rows, `METRIC name=d375_first_paint_<profile>_<measure>`; they
 * gate once the first-paint fixes of J1069 and J1100 land (#573). It measures: run it on a quiet machine.
 * `FIRST_PAINT_SAMPLES` sets the samples per cell (default 5).
 */
import { expect, test, type Browser, type BrowserContext } from "playwright/test";
import { installFirstPaintRecorder, readFirstPaintMarks } from "../test/first-paint-recorder";
import { d375Row, FIRST_PAINT_MS, PHONE_CPU_SLOWDOWN } from "../test/latency-targets";
import { personName, startRealServer } from "./server";
import { percentile } from "./typing-model";

/** Samples per profile and measure. */
const SAMPLES = Number(process.env.FIRST_PAINT_SAMPLES ?? 5);

/** A shaped network: bytes per second each way and the added latency per request, as Chromium's emulation takes them. */
const PROFILES = {
  "4g": { downloadThroughput: 9_000_000 / 8, uploadThroughput: 9_000_000 / 8, latency: 170 },
  "3g": { downloadThroughput: 1_600_000 / 8, uploadThroughput: 750_000 / 8, latency: 562.5 },
} as const;

/** One cold phone context, shaped and slowed, with the recorder installed on its page. */
async function coldPhone(browser: Browser, profile: keyof typeof PROFILES, storageState?: Awaited<ReturnType<BrowserContext["storageState"]>>) {
  const context = await browser.newContext({
    ignoreHTTPSErrors: true, viewport: { width: 393, height: 852 }, deviceScaleFactor: 3, isMobile: true, hasTouch: true,
    ...(storageState ? { storageState } : {}),
  });
  const page = await context.newPage();
  const cdp = await context.newCDPSession(page);
  await cdp.send("Network.enable");
  await cdp.send("Network.emulateNetworkConditions", { offline: false, ...PROFILES[profile] });
  await cdp.send("Emulation.setCPUThrottlingRate", { rate: PHONE_CPU_SLOWDOWN });
  await installFirstPaintRecorder(page);
  return { context, page };
}

test("first paint on 4G and fast 3G phones", async ({ browser }) => {
  test.setTimeout(900_000);
  const server = await startRealServer({});
  // Set the account up once, quickly (no shaping), and keep its signed-in state for the "connected" samples.
  const setup = await browser.newContext({ ignoreHTTPSErrors: true, viewport: { width: 1280, height: 800 } });
  const setupPage = await setup.newPage();
  const cdp = await setup.newCDPSession(setupPage);
  await cdp.send("WebAuthn.enable");
  await cdp.send("WebAuthn.addVirtualAuthenticator", { options: { protocol: "ctap2", ctap2Version: "ctap2_1", transport: "internal", hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true, hasPrf: true } });
  await setupPage.goto(server.origin);
  await setupPage.locator("#setup-token").fill(server.token);
  await setupPage.getByRole("button", { name: "Continue", exact: true }).click();
  await setupPage.locator("#setup-username").fill(personName("first_paint_net"));
  await setupPage.locator("#setup-display-name").fill("First paint net");
  await setupPage.getByRole("button", { name: "Continue", exact: true }).click();
  await setupPage.getByRole("button", { name: "Create passkey" }).click();
  await setupPage.getByRole("heading", { name: "Save your recovery key" }).waitFor();
  await setupPage.locator(".auth-check").click();
  await setupPage.getByRole("button", { name: "Open infraternal" }).click();
  await setupPage.locator(".terminal-host").first().waitFor();
  const signedIn = await setup.storageState();
  await setup.close();
  try {
    for (const profile of Object.keys(PROFILES) as Array<keyof typeof PROFILES>) {
      for (const measure of ["signin", "connected"] as const) {
        const values: number[] = [];
        const firstPaints: number[] = [];
        for (let sample = 0; sample < SAMPLES; sample += 1) {
          const { context, page } = await coldPhone(browser, profile, measure === "connected" ? signedIn : undefined);
          try {
            // A visit that never shows the screen within two minutes is a sample of infinite time, not a crashed run.
            try {
              await page.goto(server.origin, { waitUntil: "commit" });
              const marks = await readFirstPaintMarks(page, measure, 120_000);
              values.push(marks[measure] ?? Number.POSITIVE_INFINITY);
              if (marks.firstPaint !== undefined) firstPaints.push(marks.firstPaint);
            } catch (error) {
              console.log(`first_paint_sample_failed profile=${profile} measure=${measure} sample=${sample}: ${String(error).split("\n")[0]}`);
              values.push(Number.POSITIVE_INFINITY);
            }
          } finally {
            await context.close();
          }
        }
        console.log(d375Row({
          key: `first_paint_${profile}_${measure}`, source: "real-server-tracer-production-build", n: values.length,
          value: percentile(values, 0.99), unit: "ms", target: FIRST_PAINT_MS, reportOnly: true,
          extra: `p50_ms=${percentile(values, 0.5).toFixed(2)} first_paint_entry_p50_ms=${percentile(firstPaints, 0.5).toFixed(2)} ` +
            `cpu_slowdown=${PHONE_CPU_SLOWDOWN} network=${profile} cache=cold viewport=393x852`,
        }).line);
      }
    }
    expect(true).toBe(true);
  } finally {
    await server.dispose();
  }
});
