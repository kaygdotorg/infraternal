// SPDX-License-Identifier: AGPL-3.0-only
/**
 * J1237 (#260, #580): the scripted owner for the real-path setup-time row.
 *
 * Runs in the fixture network namespace of the VM that has the browser. It does what a person does
 * once per server: opens the server's own page in a headless browser with a virtual passkey, creates the
 * owner with the one-time setup token, and unlocks the host-connection authority. Then it waits on a
 * small HTTP listener: a node's `infraternal up` posts its printed approval code, and the script opens
 * the printed approval link, ticks the confirmation and taps the passkey, exactly the clicks of the
 * production page (the same steps as apps/tracer/real/up-approval.spec.ts). Nothing here talks to the
 * server except through its page.
 *
 *   bun rp-approver.ts <origin> <setup-token-file> <listen-ip> <port> <ready-file>
 *
 * `POST /approve` with the code as the body answers `{ok, approve_ms}` once the page says "Machine approved".
 */
import { chromium, type Page } from "playwright";
import { writeFileSync } from "node:fs";

const [origin, tokenFile, listenIp, port, readyFile] = process.argv.slice(2);
if (!origin || !tokenFile || !listenIp || !port || !readyFile) throw new Error("usage: rp-approver.ts <origin> <token-file> <ip> <port> <ready-file>");
/** The one-time owner setup code, read from its 0600 file and kept in memory only. */
const token = (await Bun.file(tokenFile).text()).trim();

/** The headless browser that stands in for the owner's. */
const browser = await chromium.launch({
  headless: true,
  // CHROMIUM_MAP="<name> <ip>": the server's name resolves to its LAN address in this browser only.
  args: ["--disable-renderer-backgrounding", ...(process.env.CHROMIUM_MAP ? [`--host-resolver-rules=MAP ${process.env.CHROMIUM_MAP}`] : []),
    ...(process.env.CHROMIUM_ARGS ?? "").split(" ").filter(Boolean)],
});
/** One browser context; the server's certificate is self-signed, so its errors are ignored here only. */
const context = await browser.newContext({ ignoreHTTPSErrors: true, viewport: { width: 1440, height: 900 } });
/** The single tab: it holds the passkey, so every approval reuses it. */
const page = await context.newPage();
/** DevTools channel used to attach the virtual authenticator. */
const cdp = await context.newCDPSession(page);
await cdp.send("WebAuthn.enable");
await cdp.send("WebAuthn.addVirtualAuthenticator", { options: {
  protocol: "ctap2", ctap2Version: "ctap2_1", transport: "internal",
  hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true, hasPrf: true,
} });

/** One navigation with the retries the spec uses for transient network-change errors. */
async function goto(target: Page, url: string): Promise<void> {
  for (let attempt = 1; ; attempt += 1) {
    try { await target.goto(url); return; } catch (error) {
      if (attempt === 3) throw error;
      // sleep: a transient network-change error needs a moment before the retry; there is no event to wait for
      await target.waitForTimeout(250);
    }
  }
}

/** Owner set-up: token, name, passkey, recovery key acknowledgement (production page, in order). */
async function enrolOwner(): Promise<void> {
  await goto(page, `${origin}/`);
  await page.locator("#setup-token").fill(token);
  await page.getByRole("button", { name: "Continue", exact: true }).click();
  await page.locator("#setup-username").fill("rp_owner");
  await page.locator("#setup-display-name").fill("Real path owner");
  await page.getByRole("button", { name: "Continue", exact: true }).click();
  await page.getByRole("button", { name: "Create passkey" }).click();
  await page.getByRole("heading", { name: "Save your recovery key" }).waitFor();
  await page.locator(".auth-check").click();
  await page.getByRole("button", { name: "Open infraternal" }).click();
  await page.getByRole("application", { name: "Remote terminal" }).waitFor({ timeout: 15_000 });
}

/** The command-palette "Unlock host connections" ceremony; `up` needs that authority before it can enrol a machine. */
async function unlockHostConnections(): Promise<void> {
  const status = async (): Promise<{ initialized?: boolean; locked?: boolean }> => page.evaluate(async () => {
    const response = await fetch("/remote/ca/status", { method: "POST", credentials: "same-origin", headers: { "content-type": "application/json" }, body: "{}" });
    return await response.json().catch(() => ({}));
  });
  const row = page.locator("#palette-results .result-label").filter({ hasText: "Unlock host connections" });
  for (let attempt = 1; ; attempt += 1) {
    await page.evaluate(() => document.dispatchEvent(new Event("visibilitychange")));
    await page.keyboard.press("Control+Shift+K");
    await page.locator("#palette").waitFor();
    await page.keyboard.type("Unlock host");
    if (await row.isVisible() || await row.waitFor({ timeout: 3_000 }).then(() => true, () => false)) break;
    if (attempt === 6) throw new Error("the palette never offered Unlock host connections");
    await page.keyboard.press("Escape");
    // sleep: the page asks the server for the lock state at most every 5 s, so a faster retry only repeats the question
    await page.waitForTimeout(2_000);
  }
  await row.click();
  for (let attempt = 0; attempt < 30; attempt += 1) {
    const s = await status();
    if (s.initialized === true && s.locked === false) return;
    // sleep: polls the server's lock state, which changes without a page event
    await page.waitForTimeout(1_000);
  }
  throw new Error("host-connection authority did not unlock");
}

/** Approves one printed code on the production approval page; returns the milliseconds the page work took. */
async function approve(code: string): Promise<number> {
  const start = performance.now();
  await page.goto("about:blank");
  await goto(page, `${origin}/#join=${code}`);
  await page.locator("#device-approval-code").waitFor({ timeout: 30_000 });
  if ((await page.locator("#device-approval-code").textContent()) !== code) throw new Error("approval page shows another code");
  await page.locator("label.auth-check").click();
  await page.getByRole("button", { name: "Approve with passkey" }).click();
  await page.getByRole("heading", { name: "Machine approved" }).waitFor({ timeout: 30_000 });
  return Math.round(performance.now() - start);
}

await enrolOwner();
await unlockHostConnections();
/** The previous approval, so the next one starts only after it ends. */
let busy: Promise<unknown> = Promise.resolve();
Bun.serve({
  hostname: listenIp,
  port: Number(port),
  async fetch(request) {
    const code = (await request.text()).trim();
    if (!/^[A-Za-z0-9_-]{16}$/.test(code)) return new Response("bad code", { status: 400 });
    // One approval at a time: the page is one browser tab.
    const run = busy.then(async () => {
      try { return Response.json({ ok: true, approve_ms: await approve(code) }); }
      catch (error) { return Response.json({ ok: false, error: String(error).slice(0, 300) }, { status: 500 }); }
    });
    busy = run;
    return run;
  },
});
writeFileSync(readyFile, `${Date.now()}\n`);
