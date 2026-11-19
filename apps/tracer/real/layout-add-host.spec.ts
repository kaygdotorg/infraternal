// SPDX-License-Identifier: AGPL-3.0-only
/**
 * Exercises Add host on an isolated production server and records only canvas intents, never credentials (#507).
 * Supply REAL_ADD_HOST_TARGET and a private REAL_ADD_HOST_KEY_FILE or REAL_ADD_HOST_PASSWORD_FILE for a disposable SSH host.
 * REAL_ADD_HOST_CA_FILE optionally receives the fixture's public certificate for that host's private TLS trust.
 */
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { spawn } from "node:child_process";
import { once } from "node:events";
import { expect, test } from "playwright/test";
import { WebSocketFrameDecoder } from "../../../packages/protocol/src/codec";
import { enrol, request, settled } from "./layout-devices";
import { cache, watchLayout } from "./layout-observer";
import { startRealServer } from "./server";
import { tracerEvidencePath } from "../test/evidence-path";

test("Add host does not repeatedly submit refused layout edits", async ({ browser }) => {
  test.skip(!process.env.REAL_ADD_HOST_TARGET, "requires a disposable real SSH host and private credential file");
  test.setTimeout(480_000);
  const evidence = tracerEvidencePath("layout-add-host");
  await mkdir(evidence, { recursive: true });
  const certificateFile = process.env.REAL_ADD_HOST_CA_FILE;
  const server = await startRealServer({ remoteListen: "127.0.0.1:0", ...(certificateFile ? {
    certificate: async (pem: string) => { await writeFile(certificateFile, pem); },
  } : {}) });
  const context = await browser.newContext({ ignoreHTTPSErrors: true, viewport: { width: 393, height: 852 }, isMobile: true, hasTouch: true });
  const page = watchLayout(await context.newPage());
  page.setDefaultTimeout(15_000);
  const wire: unknown[] = [], refusals: unknown[] = [];
  page.on("websocket", (socket) => {
    const sent = new WebSocketFrameDecoder(), received = new WebSocketFrameDecoder();
    const calls = new Map<number, unknown>();
    socket.on("framesent", ({ payload }) => {
      if (typeof payload === "string") return;
      sent.feed(new Uint8Array(payload), (_stream, frame) => {
        if (frame.type !== "Call" || frame.actionId !== "canvas.layout.apply") return;
        const input = JSON.parse(new TextDecoder().decode(frame.inputJson));
        const entry = { call: frame.callId, base: input.base_revision, intent: input.intent };
        calls.set(frame.callId, entry); wire.push(entry);
      });
    });
    socket.on("framereceived", ({ payload }) => {
      if (typeof payload === "string") return;
      received.feed(new Uint8Array(payload), (_stream, frame) => {
        if (frame.type !== "Result" || !calls.has(frame.callId)) return;
        if (!frame.ok) refusals.push({ request: calls.get(frame.callId), result: JSON.parse(new TextDecoder().decode(frame.json)) });
        calls.delete(frame.callId);
      });
    });
  });
  let enrolled = false;
  try {
    await enrol(page, server);
    enrolled = true;
    console.log("ADD_HOST enrolled");
    await page.getByRole("button", { name: "Add host", exact: true }).first().click();
    await expect(page.getByRole("textbox", { name: "Hosts to add" })).toBeVisible();
    const target = process.env.REAL_ADD_HOST_TARGET;
    if (target) {
      await page.getByRole("textbox", { name: "Hosts to add" }).fill(target);
      await page.getByRole("button", { name: "Continue", exact: true }).click();
      console.log("ADD_HOST target submitted");
      const confirm = page.getByRole("button", { name: "Confirm with passkey", exact: true });
      const trust = page.getByRole("button", { name: "Trust and continue", exact: true });
      await expect(confirm.or(trust)).toBeVisible({ timeout: 30_000 });
      if (await confirm.isVisible()) {
        // The routine restart notice overlaps this phone flow until the person dismisses it.
        const notice = page.getByRole("group", { name: "Notification", exact: true }).filter({ hasText: "The server restarted." });
        if (await notice.isVisible()) await notice.getByRole("button", { name: "Dismiss", exact: true }).click();
        await confirm.click();
      }
      await expect(trust).toBeVisible({ timeout: 30_000 });
      await trust.click();
      console.log("ADD_HOST trusted");
      const keyFile = process.env.REAL_ADD_HOST_KEY_FILE;
      await page.getByText(keyFile ? "Use a key from your computer" : "Sign in with a password", { exact: true }).click();
      await expect(page.locator(`input[name="ah-method"][value="${keyFile ? "key" : "password"}"]`)).toBeChecked();
      const passwordFile = keyFile ?? process.env.REAL_ADD_HOST_PASSWORD_FILE;
      if (!passwordFile) throw Error("A private credential file must name this throwaway host's SSH credential");
      // A locator fill would put a credential in the failure report; only the private browser input receives it.
      // SSH key files retain their final newline so ssh-add can parse their complete encoding.
      await page.locator(`[data-secret="${keyFile ? "key" : "password"}"]`).evaluate((element, password) => {
        (element as HTMLInputElement).value = password;
        element.dispatchEvent(new Event("input", { bubbles: true }));
      }, keyFile ? await readFile(passwordFile, "utf8") : (await readFile(passwordFile, "utf8")).trim());
      await page.getByRole("button", { name: "Sign in", exact: true }).click();
      console.log("ADD_HOST credential submitted");
      await expect(page.locator('.cl[data-view="console"] .ui-window[data-kind="terminal"]')).toHaveCount(2, { timeout: 300_000 });
      await expect(page.locator('.ui-window[data-kind="flow"]')).toHaveCount(0, { timeout: 60_000 });
    }
    await settled(page);
    await page.screenshot({ path: `${evidence}/add-host.png` });
    expect(refusals).toEqual([]);
  } catch (error) {
    // Never capture the setup/recovery screens: their capabilities are private even in a throwaway fixture.
    if (enrolled && !page.isClosed()) await page.screenshot({ path: `${evidence}/failure.png` }).catch(() => {});
    throw error;
  } finally {
    await writeFile(`${evidence}/wire.json`, JSON.stringify({ wire, refusals }, null, 2));
    try { await context.close(); } finally { await server.dispose(); }
  }
});

/** The real server's retained-operation limit permanently refuses automatic completion of an older account look. */
test("a refused legacy look completion is not automatically resubmitted", async ({ browser }) => {
  test.skip(process.getuid?.() === 0, "requires the real rootless shell refusal");
  test.setTimeout(90_000);
  const evidence = tracerEvidencePath("layout-look-refusal");
  await mkdir(evidence, { recursive: true });
  const server = await startRealServer();
  const context = await browser.newContext({ ignoreHTTPSErrors: true, viewport: { width: 393, height: 852 } });
  const page = watchLayout(await context.newPage());
  const calls: unknown[] = [], refusals: unknown[] = [];
  let recoverySnapshots = 0, automaticCalls = 0;
  try {
    await enrol(page, server, { username: "nobody_here_j532", refusedShell: true });
    // Persist only public layout data; the observer's pending envelopes also carry a private session binding.
    await writeFile(`${evidence}/initial.json`, JSON.stringify((await cache(page)).canonical, null, 2));
    const canonical = (await cache(page)).canonical;
    const legacy = structuredClone(canonical.look!);
    delete legacy.uiFont; delete legacy.windowSizes; delete legacy.extendedInfo;
    const sent = new WebSocketFrameDecoder(), received = new WebSocketFrameDecoder();
    const pending = new Set<number>();
    // Only this page's next connection is observed; reload applies the older account look on first paint.
    page.on("websocket", (socket) => {
      socket.on("framesent", ({ payload }) => {
        if (typeof payload === "string") return;
        sent.feed(new Uint8Array(payload), (_stream, frame) => {
          if (frame.type !== "Call" || frame.actionId !== "canvas.layout.apply") return;
          const input = JSON.parse(new TextDecoder().decode(frame.inputJson));
          if (input.intent?.type !== "look.set") return;
          calls.push(input.intent); pending.add(frame.callId);
        });
      });
      socket.on("framereceived", ({ payload }) => {
        if (typeof payload === "string") return;
        received.feed(new Uint8Array(payload), (_stream, frame) => {
          if (frame.type === "Result" && pending.delete(frame.callId) && !frame.ok) refusals.push(JSON.parse(new TextDecoder().decode(frame.json)));
          if (frame.type === "Event" && refusals.length && JSON.parse(new TextDecoder().decode(frame.eventJson)).type === "canvas.layout.snapshot") recoverySnapshots++;
        });
      });
    });
    // Stop the first page before seeding so the observed attempt belongs to one startup, not a concurrent appearance edit.
    await page.goto("about:blank");
    const seeded = await request(server, context, "canvas.layout.apply", { op_id: "legacy-look", base_revision: canonical.revision, intent: { type: "look.set", look: legacy } });
    expect(seeded.ok).toBe(true);
    // Seed the reachable quota boundary; the unmodified transaction path must make the refusal itself.
    const quota = spawn("python3", ["-c", "import sqlite3,sys\nwith sqlite3.connect(sys.argv[1]) as db: db.execute('UPDATE canvas_heads SET receipt_count=65536')", `${server.dataDir}/infraternal.sqlite`], { stdio: "ignore" });
    const [quotaCode] = await once(quota, "exit");
    expect(quotaCode).toBe(0);
    await page.goto(server.origin);
    await expect.poll(() => recoverySnapshots).toBeGreaterThan(0);
    // A recovery snapshot synchronously announces completion and queues its save; these frames fence that browser work.
    await page.evaluate(() => new Promise<void>((resolve) => requestAnimationFrame(() => requestAnimationFrame(() => resolve()))));
    expect(refusals[0]).toMatchObject({ reason: "operation_limit" });
    automaticCalls = calls.length;
    expect(calls).toHaveLength(1);
    const reopen = spawn("python3", ["-c", "import sqlite3,sys\nwith sqlite3.connect(sys.argv[1]) as db: db.execute('UPDATE canvas_heads SET receipt_count=0')", `${server.dataDir}/infraternal.sqlite`], { stdio: "ignore" });
    const [reopenCode] = await once(reopen, "exit");
    expect(reopenCode).toBe(0);
    // A real choice remains saveable after the refused automatic completion.
    await page.keyboard.press("Control+Shift+K");
    await page.locator("#palette-input").fill("Paper");
    await page.locator('#palette-results [data-action="theme:paper"]').click();
    await expect.poll(async () => {
      const look = (await cache(page)).canonical.look;
      return look?.themes.find((theme) => theme.id === look.selected)?.colors;
    }).toBe("paper");
    await expect.poll(async () => (await cache(page)).pending.length).toBe(0);
    expect(calls).toHaveLength(2);
    await page.screenshot({ path: `${evidence}/recovered.png` });
  } finally {
    await writeFile(`${evidence}/wire.json`, JSON.stringify({ calls, refusals, recoverySnapshots, automaticCalls }, null, 2));
    try { await context.close(); } finally { await server.dispose(); }
  }
});
