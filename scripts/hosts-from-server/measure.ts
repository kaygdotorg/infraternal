/** Measures returning sign-in through real PTYs at configurable admitted-host scale; run only on the locked perf VM [D256], #194. */
import { chromium } from "../../apps/tracer/node_modules/playwright";
import { spawnSync } from "node:child_process";
import { readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { startRealServer } from "../../apps/tracer/real/server";

const job = process.env.HOST_INVENTORY_JOB_ROOT;
if (!job || !process.env.PERF_VM || !process.env.BASELINE_DIST || !process.env.CANDIDATE_DIST) throw new Error("Run with prepared builds on the perf VM");
const hostCount = Number(process.env.HOST_INVENTORY_COUNT ?? "1000");
const trials = Number(process.env.HOST_INVENTORY_TRIALS ?? "12");
if (!Number.isSafeInteger(hostCount) || hostCount < 1 || !Number.isSafeInteger(trials) || trials < 1) throw new Error("Positive host/trial counts required");
const results: Record<string, unknown> = { machine: (await readFile("/proc/sys/kernel/hostname", "utf8")).trim(), loadBefore: (await readFile("/proc/loadavg", "utf8")).trim(), hosts: hostCount, samples: trials, rttMs: 300, tracerTestPort: process.env.TRACER_TEST_PORT, firstFrameDefinition: "first glyph draw on the visible terminal canvas" };
const variants = [["baseline", process.env.BASELINE_DIST], ["candidate", process.env.CANDIDATE_DIST]] as const;
const ordered = process.env.HOST_INVENTORY_REVERSE === "1" ? [...variants].reverse() : variants;
results.variantOrder = ordered.map(([variant]) => variant);
const browser = await chromium.launch({ headless: true, args: ["--disable-renderer-backgrounding"] });
try {
  for (const [variant, dist] of ordered) {
    process.env.TRACER_DIST = dist;
    const server = await startRealServer({ latencyMs: 150, timedControls: true, stateRoot: resolve(job, "state") });
    try {
      const setup = await browser.newContext({ ignoreHTTPSErrors: true });
      const page = await setup.newPage();
      const auth = await setup.newCDPSession(page);
      await auth.send("WebAuthn.enable");
      await auth.send("WebAuthn.addVirtualAuthenticator", { options: { protocol: "ctap2", ctap2Version: "ctap2_1", transport: "internal", hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true, hasPrf: true } });
      await page.goto(server.origin);
      try { await page.locator("#setup-token").fill(server.token); } catch { throw new Error("Fixture setup token field unavailable"); }
      await page.getByRole("button", { name: "Continue", exact: true }).click();
      await page.locator("#setup-username").fill("host_inventory_perf");
      await page.locator("#setup-display-name").fill("Inventory perf");
      await page.getByRole("button", { name: "Continue", exact: true }).click();
      await page.getByRole("button", { name: "Create passkey" }).click();
      await page.getByRole("heading", { name: "Save your recovery key" }).waitFor();
      await page.locator(".auth-check").click();
      await page.getByRole("button", { name: "Open infraternal" }).click();
      await page.locator(".cl-viewport").waitFor();
      const cookies = await setup.cookies();
      // Public fixture records only. Browser ceremony and session capabilities remain in memory.
      const seeded = spawnSync("python3", ["-c", `import sqlite3,sys,uuid,pathlib
p=next(pathlib.Path(sys.argv[1]).glob('infraternal.sqlite'))
c=sqlite3.connect(p);owner=c.execute("SELECT id FROM users WHERE owner=1").fetchone()[0]
for n in range(1,int(sys.argv[2])+1):
 h=uuid.UUID(int=n).bytes
 c.execute("INSERT INTO remote_hosts(id,owner_id,mode,execution_uid,created_at) VALUES(?,?,'rootless',1002,100)",(h,owner))
 c.execute("INSERT INTO remote_certificates(fingerprint,host_id,issuer_fingerprint,public_key,not_before,not_after) VALUES(?,?,zeroblob(32),zeroblob(32),100,604900)",(h+h,h))
 c.execute("INSERT INTO remote_host_bootstrap(host_id,address) VALUES(?,?)",(h,'operator@worker-%04d'%n))
c.commit()`, server.dataDir, String(hostCount)], { stdio: ["ignore", "ignore", "ignore"] });
      if (seeded.status !== 0) throw new Error("Public admitted-host fixture failed");
      await setup.close();
      const samples: number[] = [], inventoryBeforeFrame: boolean[] = [], phases: Record<string, number>[] = [];
      for (let trial = 0; trial < trials; trial++) {
        const context = await browser.newContext({ ignoreHTTPSErrors: true, viewport: { width: 1440, height: 900 } });
        await context.addCookies(cookies);
        await context.addInitScript(() => {
          const record = (): void => {
            const w = window as unknown as { __hostFrame?: number };
            if (w.__hostFrame === undefined) w.__hostFrame = performance.now();
          };
          for (const name of ["fillText", "drawImage"] as const) {
            const original = CanvasRenderingContext2D.prototype[name];
            Reflect.set(CanvasRenderingContext2D.prototype, name, function(this: CanvasRenderingContext2D, ...args: unknown[]) {
              const result = Reflect.apply(original, this, args);
              if (this.canvas.closest("#terminal-host") && this.canvas.isConnected) record();
              return result;
            });
          }
        });
        const returning = await context.newPage();
        await returning.goto(server.origin);
        await returning.waitForFunction(() => (window as unknown as { __hostFrame?: number }).__hostFrame !== undefined);
        const first = await returning.evaluate(() => ({ relative: (window as unknown as { __hostFrame: number }).__hostFrame, origin: performance.timeOrigin }));
        samples.push(first.relative);
        phases.push(await returning.evaluate(() => Object.fromEntries(["mount", "client", "attached", "painted"].map((phase) => [phase, performance.getEntriesByName(`sw:1:${phase}`)[0]?.startTime ?? -1]))));
        const bridge = server.bridges.at(-1);
        inventoryBeforeFrame.push(bridge?.control.some((row) => row.dir === "up" && row.detail === "remote.host.list" && row.at !== undefined && row.at <= first.origin + first.relative) ?? false);
        if (variant === "candidate") {
          await returning.keyboard.press("Control+Shift+K");
          await returning.locator("#palette-input").fill(`Open shell on worker-${String(hostCount).padStart(4, "0")}`);
          await returning.locator("#palette-results [role=option]").filter({ hasText: `Open shell on worker-${String(hostCount).padStart(4, "0")}` }).waitFor({ timeout: 90000 });
        }
        await context.close();
      }
      const sorted = [...samples].sort((a,b) => a-b);
      results[variant] = { firstFrameMs: samples, phases, p50Ms: sorted[Math.floor((trials - 1) / 2)], sampleMaxMs: sorted.at(-1), inventoryAskedBeforeFirstFrame: inventoryBeforeFrame };
    } finally { await server.dispose(); }
  }
} finally { await browser.close(); }
results.loadAfter = (await readFile("/proc/loadavg", "utf8")).trim();
await writeFile(resolve(job, "sign-in.json"), JSON.stringify(results, null, 2));
console.log(JSON.stringify(results));
const candidate = results.candidate as { inventoryAskedBeforeFirstFrame: boolean[] };
if (candidate.inventoryAskedBeforeFirstFrame.some(Boolean)) throw new Error("Inventory competed with the first terminal glyph");
