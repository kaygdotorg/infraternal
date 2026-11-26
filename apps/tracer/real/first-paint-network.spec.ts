/**
 * First paint on a real phone network (owner, 2026-11-21; #573, D375, D41): how long a person on 4G, slow 4G, or
 * fast 3G waits to see the sign-in screen, and to see a connected terminal, on the production server and the
 * production tracer.
 *
 * Each sample is a cold start: a fresh browser context (empty HTTP cache), the phone's CPU slowed 4x, and the
 * network shaped by Chromium's own emulation. The profiles (DevTools numbers, the same ones J1069 and J1263 measured):
 *
 * | Profile | Down | Up | Latency |
 * |---|---|---|---|
 * | `4g` | 9 Mbps | 9 Mbps | 170 ms |
 * | `slow4g` | 1.6 Mbps | 750 kbps | 150 ms |
 * | `3g` (fast 3G) | 1.6 Mbps | 750 kbps | 562.5 ms |
 *
 * `signin` is the first frame showing the sign-in button of a signed-out visit, and `connected` the first frame after
 * a signed-in visit's terminal says it is connected, both from navigation start through the page's own clock
 * (`first-paint-recorder.ts`). It prints the four D375 reported rows, `METRIC name=d375_first_paint_<profile>_<measure>`;
 * they gate once the first-paint fixes of J1069 and J1100 land (#573). It measures: run it on a quiet machine.
 *
 * Environment controls:
 * - `FIRST_PAINT_SAMPLES`: samples per cell (default `5`).
 * - `FIRST_PAINT_PROTOCOL`: `"http1"` (default, or `REAL_SERVER_PROTOCOL`), `"http2"`, or `"both"`. Each mode verifies
 *   Chromium's negotiated `nextHopProtocol` (`"http/1.1"` vs `"h2"`) on the document and same-origin assets.
 * - `FIRST_PAINT_PROFILES`: comma-separated subset of `4g,slow4g,3g` (default `4g,3g`).
 */
import { expect, test, type Browser, type BrowserContext, type Page } from "playwright/test";
import { installFirstPaintRecorder, readFirstPaintMarks } from "../test/first-paint-recorder";
import { d375Row, FIRST_PAINT_MS, latencyDisplay, PHONE_CPU_SLOWDOWN } from "../test/latency-targets";
import { personName, resolveServerProtocol, startRealServer, type RealServerProtocol } from "./server";
import { percentile } from "./typing-model";

/** Samples per profile and measure. */
const SAMPLES = Number(process.env.FIRST_PAINT_SAMPLES ?? 5);

/** A shaped network: bytes per second each way and the added latency per request, as Chromium's emulation takes them. */
const PROFILES = {
  "4g": { downloadThroughput: 9_000_000 / 8, uploadThroughput: 9_000_000 / 8, latency: 170 },
  "slow4g": { downloadThroughput: 1_600_000 / 8, uploadThroughput: 750_000 / 8, latency: 150 },
  "3g": { downloadThroughput: 1_600_000 / 8, uploadThroughput: 750_000 / 8, latency: 562.5 },
} as const;

/** Network profile names accepted by `FIRST_PAINT_PROFILES`. */
type NetworkProfile = keyof typeof PROFILES;

/** Resolves the list of transport protocols to measure from `FIRST_PAINT_PROTOCOL`. */
function selectedProtocols(): RealServerProtocol[] {
  const raw = process.env.FIRST_PAINT_PROTOCOL;
  if (raw === undefined || raw === "") return [resolveServerProtocol()];
  if (raw === "http1" || raw === "http2") return [raw];
  if (raw === "both") return ["http1", "http2"];
  throw new Error(`FIRST_PAINT_PROTOCOL must be "http1", "http2", or "both" (got ${JSON.stringify(raw)})`);
}

/** Resolves the network profiles to measure from `FIRST_PAINT_PROFILES` (default `4g,3g`). */
function selectedProfiles(): NetworkProfile[] {
  const raw = process.env.FIRST_PAINT_PROFILES;
  if (raw === undefined || raw.trim() === "") return ["4g", "3g"];
  const names = raw.split(",").map((entry) => entry.trim()).filter(Boolean);
  for (const name of names) {
    if (!(name in PROFILES)) {
      throw new Error(`FIRST_PAINT_PROFILES entry ${JSON.stringify(name)} must be one of: ${Object.keys(PROFILES).join(", ")}`);
    }
  }
  return names as NetworkProfile[];
}

/** Reads the negotiated HTTP protocol reported by the browser for the document and same-origin static assets. */
async function readWireProtocols(page: Page, origin: string): Promise<{ navigation: string; resources: string[] }> {
  return page.evaluate((expectedOrigin) => {
    const nav = performance.getEntriesByType("navigation")[0] as PerformanceNavigationTiming | undefined;
    const resources = (performance.getEntriesByType("resource") as PerformanceResourceTiming[])
      .filter((entry) => entry.name.startsWith(expectedOrigin) && entry.nextHopProtocol !== "")
      .map((entry) => entry.nextHopProtocol);
    return {
      navigation: nav?.nextHopProtocol ?? "",
      resources: [...new Set(resources)].sort(),
    };
  }, origin);
}

/** One cold phone context, shaped and slowed, with the recorder installed on its page. */
async function coldPhone(browser: Browser, profile: NetworkProfile, storageState?: Awaited<ReturnType<BrowserContext["storageState"]>>) {
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

/** Runs every requested network profile and measure against one fixture server transport (`http1` or `http2`). */
async function measureProtocol(browser: Browser, protocol: RealServerProtocol, profiles: NetworkProfile[]): Promise<void> {
  const expectedWire = protocol === "http2" ? "h2" : "http/1.1";
  const server = await startRealServer({ protocol });
  // Set the account up once, quickly (no shaping), and keep its signed-in state for the "connected" samples.
  const setup = await browser.newContext({ ignoreHTTPSErrors: true, viewport: { width: 1280, height: 800 } });
  const setupPage = await setup.newPage();
  const cdp = await setup.newCDPSession(setupPage);
  await cdp.send("WebAuthn.enable");
  await cdp.send("WebAuthn.addVirtualAuthenticator", { options: { protocol: "ctap2", ctap2Version: "ctap2_1", transport: "internal", hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true, hasPrf: true } });
  try {
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

    for (const profile of profiles) {
      for (const measure of ["signin", "connected"] as const) {
        const values: number[] = [];
        const firstPaints: number[] = [];
        let verifiedWire = false;
        for (let sample = 0; sample < SAMPLES; sample += 1) {
          const { context, page } = await coldPhone(browser, profile, measure === "connected" ? signedIn : undefined);
          try {
            // A visit that never shows the screen within two minutes is a sample of infinite time, not a crashed run.
            try {
              await page.goto(server.origin, { waitUntil: "commit" });
              const marks = await readFirstPaintMarks(page, measure, 120_000);
              if (!verifiedWire) {
                const wire = await readWireProtocols(page, server.origin);
                expect(wire.navigation, `expected ${expectedWire} navigation in ${protocol} mode`).toBe(expectedWire);
                expect(wire.resources, `expected ${expectedWire} resources in ${protocol} mode`).toEqual([expectedWire]);
                verifiedWire = true;
              }
              values.push(marks[measure] ?? Number.POSITIVE_INFINITY);
              if (marks.firstPaint !== undefined) firstPaints.push(marks.firstPaint);
            } catch (error) {
              console.log(`first_paint_sample_failed protocol=${protocol} profile=${profile} measure=${measure} sample=${sample}: ${String(error).split("\n")[0]}`);
              values.push(Number.POSITIVE_INFINITY);
            }
          } finally {
            await context.close();
          }
        }
        expect(verifiedWire, `no sample verified ${expectedWire} wire protocol for ${protocol} ${profile} ${measure}`).toBe(true);
        const p99 = percentile(values, 0.99);
        const p50 = percentile(values, 0.5);
        const fp50 = percentile(firstPaints, 0.5);
        const extra = `p50_ms=${p50.toFixed(2)} first_paint_entry_p50_ms=${fp50.toFixed(2)} ` +
          `cpu_slowdown=${PHONE_CPU_SLOWDOWN} network=${profile} cache=cold viewport=393x852 protocol=${protocol} wire=${expectedWire}`;
        if (profile === "slow4g") {
          console.log(
            `METRIC name=first_paint_slow4g_${measure} source=real-server-tracer-production-build display=${latencyDisplay()} ` +
            `n=${values.length} value=${p99.toFixed(2)} unit=ms target=${FIRST_PAINT_MS.toFixed(2)} gate=${FIRST_PAINT_MS.toFixed(2)} ` +
            `target_met=${Number.isFinite(p99) && p99 <= FIRST_PAINT_MS ? "yes" : "no"} result=REPORT ${extra}`,
          );
        } else {
          console.log(d375Row({
            key: `first_paint_${profile}_${measure}`, source: "real-server-tracer-production-build", n: values.length,
            value: p99, unit: "ms", target: FIRST_PAINT_MS, reportOnly: true, extra,
          }).line);
        }
      }
    }
  } finally {
    await setup.close().catch(() => {});
    await server.dispose();
  }
}

test("first paint on 4G and fast 3G phones", async ({ browser }) => {
  const protocols = selectedProtocols();
  const profiles = selectedProfiles();
  test.setTimeout(900_000 * protocols.length);
  for (const protocol of protocols) {
    await measureProtocol(browser, protocol, profiles);
  }
  expect(true).toBe(true);
});
