/** Research-only production-browser flood triage; run on a build VM through build-slot (#260). */
import { chromium } from "../../apps/tracer/node_modules/playwright";
import { startRealServer } from "../../apps/tracer/real/server";
import { WebSocketFrameDecoder } from "../../packages/protocol/src/codec";
import { mkdir, writeFile } from "node:fs/promises";
import { spawnSync } from "node:child_process";
import { join } from "node:path";

/** Store result JSON and screenshots outside the checkout. */
const evidence = process.env.J20_EVIDENCE;
if (!evidence) throw new Error("J20_EVIDENCE must name an evidence directory outside the checkout");
await mkdir(evidence, { recursive: true });
/** Start the disposable real-server fixture with its lean front end. */
const server = await startRealServer({ systemd: false, lean: true });
/** Keep the browser handle available to the final cleanup path. */
let browser: Awaited<ReturnType<typeof chromium.launch>> | undefined;
try {
  const blob = join(server.dataDir, "blob");
  const generated = spawnSync("bash", ["-o", "pipefail", "-c", 'head -c 75000000 /dev/urandom | base64 -w 120 > "$1"', "fixture", blob]);
  if (generated.status !== 0) throw new Error("blob generation failed");
  browser = await chromium.launch({
    executablePath: process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH,
    args: ["--disable-renderer-backgrounding", "--ignore-certificate-errors"],
  });
  const context = await browser.newContext({ ignoreHTTPSErrors: true, viewport: { width: 1440, height: 900 } });
  const page = await context.newPage();
  const closes: Array<{ stream: number; code: number; reason: string; at: number }> = [];
  const socketCloses: number[] = [];
  const errors: string[] = [];
  let bytes = 0, probes = 0, sockets = 0;
  page.on("pageerror", error => errors.push(error.name));
  page.on("websocket", socket => {
    if (!socket.url().endsWith("/v1/ws")) return;
    sockets++;
    const decoder = new WebSocketFrameDecoder();
    socket.on("framereceived", ({ payload }) => {
      if (typeof payload === "string") return;
      decoder.feed(new Uint8Array(payload), (stream, frame) => {
        if (frame.type === "Output") bytes += frame.bytes.byteLength;
        if (frame.type === "Ping") probes++;
        if (frame.type === "Close") closes.push({ stream, code: frame.code, reason: frame.reason, at: Date.now() });
      });
    });
    socket.on("close", () => socketCloses.push(Date.now()));
  });
  const cdp = await context.newCDPSession(page);
  await cdp.send("WebAuthn.enable");
  await cdp.send("WebAuthn.addVirtualAuthenticator", { options: {
    protocol: "ctap2", ctap2Version: "ctap2_1", transport: "internal", hasResidentKey: true,
    hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true, hasPrf: true,
  } });
  await page.goto(server.origin + "/?mock=1&bg=none&theme=ink");
  await page.locator("#setup-token").fill(server.token);
  await page.getByRole("button", { name: "Continue", exact: true }).click();
  await page.locator("#setup-username").fill("flood_research");
  await page.locator("#setup-display-name").fill("Flood research");
  await page.getByRole("button", { name: "Continue", exact: true }).click();
  await page.getByRole("button", { name: "Create passkey" }).click();
  await page.getByRole("heading", { name: "Save your recovery key" }).waitFor();
  await page.locator(".auth-check").click();
  await page.getByRole("button", { name: "Open infraternal" }).click();
  await page.waitForFunction(() => window.__tracerTestDouble?.isConnected());
  for (let run = 1; run <= 3; run++) {
    const before = { bytes, probes, closes: closes.length, sockets, socketCloses: socketCloses.length };
    const marker = `J20_FLOOD_DONE_${run}`;
    const start = Date.now();
    // Split the marker so echoed shell input cannot satisfy the completion check.
    await page.evaluate(({ blob, run }) => window.__tracerTestDouble?.injectInput(
      `cat '${blob}'; printf 'J20_FLOOD_%s_${run}\\n' DONE\r`,
    ), { blob, run });
    let current = true;
    try {
      await page.waitForFunction(marker => window.__tracerTestDouble?.screenText().includes(marker), marker, { timeout: 180_000 });
    } catch { current = false; }
    const result = { run, current, seconds: (Date.now() - start) / 1000,
      bytes: bytes - before.bytes, probes: probes - before.probes,
      closes: closes.slice(before.closes), newSockets: sockets - before.sockets,
      socketCloses: socketCloses.slice(before.socketCloses), errors,
      browser: browser.version(), productionRenderer: true, relay: "lean fixture TLS/WebSocket front" };
    await writeFile(join(evidence, `browser-flood-${run}.json`), JSON.stringify(result, null, 2));
    await page.screenshot({ path: join(evidence, `browser-flood-${run}.png`) });
    console.log(JSON.stringify(result));
    if (!current) { process.exitCode = 1; break; }
  }
  await context.close();
} finally {
  await browser?.close();
  await server.dispose();
}
