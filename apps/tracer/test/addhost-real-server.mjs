/**
 * Integration run of the add-host adapter against the REAL server binary (#87). Not part of `scripts/verify fast`:
 * it needs the server built from the `ssh-bootstrap` branch (merge it into a scratch branch for the run; never commit
 * that merge) and a production tracer build.
 *
 *   cargo build --package infraternal
 *   (cd apps/tracer && bun run build)
 *   INFRATERNAL_BIN=target/debug/infraternal bun run apps/tracer/test/addhost-real-server.mjs
 *
 * What it does: starts the server on a free port with a throwaway data directory and a self-signed certificate,
 * registers the owner through the real sign-in UI with a virtual passkey, then, inside that signed-in page, runs
 * the product adapter (`src/canvas/addhost/real.ts`, bundled for the page) against the live endpoints and prints
 * what each one answered. It makes no SSH connection to any real host and uses no credential of the person's.
 */
import { chromium } from "playwright";
import { spawn, execFileSync } from "node:child_process";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

const here = import.meta.dirname;
const tracer = resolve(here, "..");
const bin = resolve(process.env.INFRATERNAL_BIN ?? resolve(tracer, "../../target/debug/infraternal"));
const dist = resolve(process.env.TRACER_DIST ?? resolve(tracer, "dist"));
const free = () => new Promise((done) => { const s = createServer(); s.listen(0, "127.0.0.1", () => { const { port } = s.address(); s.close(() => done(port)); }); });
const work = mkdtempSync(join(tmpdir(), "addhost-real-"));
const port = await free();
const origin = `https://localhost:${port}`;

// A self-signed certificate for localhost only; the browser is told to accept it.
execFileSync("openssl", ["req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes", "-days", "1", "-subj", "/CN=localhost",
  "-addext", "subjectAltName=DNS:localhost", "-keyout", join(work, "key.pem"), "-out", join(work, "cert.pem")], { stdio: "ignore" });

const common = ["server", "--listen", `127.0.0.1:${port}`, "--data", join(work, "data"), "--public-origin", origin];
const server = spawn(bin, [...common, "--web-root", dist, "--tls-cert", join(work, "cert.pem"), "--tls-key", join(work, "key.pem")], { stdio: ["ignore", "ignore", "inherit"] });
let browser;
const results = [];
try {
  for (let i = 0; i < 100; i++) {
    try { const r = await fetch(`${origin}/healthz`, { dispatcher: undefined }).catch(() => undefined); if (r?.ok) break; } catch { /* retry */ }
    await new Promise((r) => setTimeout(r, 100));
    if (i === 99) throw new Error("the server did not start");
  }
} catch { /* the self-signed certificate makes a plain fetch fail; the browser run below is the real check */ }

try {
  await new Promise((r) => setTimeout(r, 1500));
  const token = execFileSync(bin, [...common, "setup-token"], { encoding: "utf8" }).trim().split(/\s+/).pop();
  // The adapter and client, bundled for the page. Nothing else of the tracer is loaded.
  const built = await Bun.build({ entrypoints: [resolve(tracer, "src/canvas/addhost/real.ts")], target: "browser", format: "esm", minify: false });
  if (!built.success) throw new Error(built.logs.join("\n"));
  const code = (await built.outputs[0].text()).replace(/^export \{[^}]*\};?\s*$/m, "") + "\nwindow.__addhost = { createRealProvisioning };";
  writeFileSync(join(work, "adapter.js"), code);

  browser = await chromium.launch({ headless: true });
  const context = await browser.newContext({ ignoreHTTPSErrors: true, viewport: { width: 1440, height: 900 } });
  const page = await context.newPage();
  const cdp = await context.newCDPSession(page);
  await cdp.send("WebAuthn.enable");
  await cdp.send("WebAuthn.addVirtualAuthenticator", { options: { protocol: "ctap2", ctap2Version: "ctap2_1", transport: "internal", hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true, hasPrf: true } });
  await page.goto(`${origin}/`);
  await page.locator("#setup-token").fill(token);
  await page.getByRole("button", { name: "Continue" }).click();
  await page.locator("#setup-username").fill("owner");
  await page.getByRole("button", { name: "Continue" }).click();
  await page.getByRole("button", { name: "Create passkey" }).click();
  await page.locator(".auth-check").waitFor();
  await page.locator(".auth-check").click();
  await page.getByRole("button", { name: "Open infraternal" }).click();
  // The owner session is the cookie; the app behind it (terminal, embedded agent) is not what this run checks.
  for (let i = 0; i < 100 && !(await context.cookies()).some((cookie) => cookie.name === "__Host-infraternal"); i++) await page.waitForTimeout(100);
  if (!(await context.cookies()).some((cookie) => cookie.name === "__Host-infraternal")) throw new Error("no owner session after setup");
  results.push("signed in as the owner through the real sign-in UI");

  await page.addScriptTag({ content: code });
  const report = await page.evaluate(async () => {
    const service = window.__addhost.createRealProvisioning();
    const out = {};
    const settle = async (name, fn) => { try { out[name] = await fn(); } catch (error) { out[name] = { threw: error.message }; } };
    await settle("serverKey", () => service.serverKey());
    await settle("discover", () => service.discover());
    await settle("installCommand", () => service.installCommand("kayg@127.0.0.1:1"));
    await settle("mintCredential", () => service.mintCredential({ kind: "password", text: "x" }));
    // One batch over the live socket: an address nothing answers on, then root without consent (refused before any SSH).
    out.events = [];
    out.errors = [];
    await new Promise((done) => {
      const run = service.open({ onEvent: (e) => { out.events.push({ step: e.step, message: e.message, kind: e.failure?.kind, auth: e.authentication }); if (e.step === "failed" || e.step === "done") { run.close(); done(); } },
        onError: (e) => out.errors.push(e), onClose: done });
      run.start([{ id: "t1", address: { kind: "manual", value: "kayg@127.0.0.1:1" } }]);
      setTimeout(done, 20_000);
    });
    out.rootWithoutConsent = await new Promise((done) => {
      const run = service.open({ onEvent: () => {}, onError: (e) => { run.close(); done(e); }, onClose: () => done("closed") });
      run.start([{ id: "r1", address: { kind: "manual", value: "kayg@127.0.0.1:1" }, mode: "root" }]);
      setTimeout(() => done("no answer"), 10_000);
    });
    return out;
  });
  results.push(JSON.stringify(report, null, 2));
} finally {
  await browser?.close();
  server.kill("SIGTERM");
  rmSync(work, { recursive: true, force: true });
}
console.log(results.join("\n"));
