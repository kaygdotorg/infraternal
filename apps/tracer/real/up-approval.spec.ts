/** Exercises `infraternal up` through a real server and the production approval page (#263, J82's page). */
import { spawn, type ChildProcess } from "node:child_process";
import { once } from "node:events";
import { access, mkdir, readFile, readlink, stat, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { expect, test, type BrowserContext, type Page } from "playwright/test";
import { startRealServer, type RealServer } from "./server";

const MACHINE = "up-e2e-node";
const SHORT_KEY = /Machine key: ([A-Za-z0-9+/]{4} [A-Za-z0-9+/]{4} [A-Za-z0-9+/]{4} [A-Za-z0-9+/]{4})/;
const USER_CODE = /Code: ([A-Za-z0-9_-]{16})/;
const SERVICE_BINARY = "/var/lib/infraternal/bin/infraternal";

let server: RealServer;
let context: BrowserContext;
let page: Page;
let cli: ChildProcess | undefined;

test.describe.configure({ mode: "serial" });

test.beforeAll(async ({ browser }) => {
  test.setTimeout(180_000);
  if (!process.env.INFRATERNAL_BIN) {
    throw new Error("INFRATERNAL_BIN did not reach the Playwright test process");
  }
  expect(process.env.INFRATERNAL_BIN).toBe(
    join(process.env.CARGO_TARGET_DIR ?? "", "debug/infraternal"),
  );
  const caBundle = process.env.UP_TEST_CA_BUNDLE;
  if (!caBundle) throw new Error("UP_TEST_CA_BUNDLE is required by the namespace proof");
  server = await startRealServer({
    address: "127.0.0.1",
    hostname: "localhost",
    port: 443,
    remoteListen: "127.0.0.1:7443",
    certificate: async (certificate) => {
      await writeFile(caBundle, `\n${certificate}\n`, { flag: "a" });
    },
  });
  context = await browser.newContext({ ignoreHTTPSErrors: true, viewport: { width: 1440, height: 900 } });
  page = await context.newPage();
  await enrolOwner(page);
  await provisionRemoteAuthority(page);
});

test.afterAll(async () => {
  if (cli?.pid && cli.exitCode === null && cli.signalCode === null) {
    try { process.kill(-cli.pid, "SIGTERM"); } catch { /* The command already exited. */ }
    await waitForExit(cli, 5_000).catch(() => undefined);
  }
  await context?.close();
  await server?.dispose();
});

test("up is approved in the real page and enrolls over HTTPS without port 7443", async () => {
  test.setTimeout(180_000);
  const control = process.env.UP_E2E_CONTROL_DIR;
  const sudoCalls = process.env.UP_SUDO_CALLS;
  const systemctlCalls = process.env.UP_SYSTEMCTL_CALLS;
  const serviceSystemctlCalls = process.env.UP_SERVICE_SYSTEMCTL_CALLS;
  const helperOutput = process.env.UP_HELPER_OUTPUT;
  const decoyCalls = process.env.UP_DECOY_CALLS;
  const root = process.env.UP_PRIVATE_ROOT;
  const caBundle = process.env.UP_TEST_CA_BUNDLE;
  const evidence = process.env.INFRATERAL_UP_EVIDENCE_DIR;
  if (!control || !sudoCalls || !systemctlCalls || !serviceSystemctlCalls || !helperOutput || !decoyCalls || !root
    || !caBundle) {
    throw new Error("The namespace proof did not provide its private fixture paths");
  }
  const requestLines: string[] = [];
  const responseLines: string[] = [];
  const addressAtRequest: string[] = [];
  const failedRequests: string[] = [];
  let inspectedResponse: import("playwright/test").Response | undefined;
  // `up` runs in the private root (paths below are as it sees them); /infraternal is server.binary.
  const dataHome = join(root, "home/up/data");
  await mkdir(dataHome, { recursive: true, mode: 0o700 });
  await writeFile(sudoCalls, "");
  await writeFile(helperOutput, "");

  // `up` shows its code only on a terminal (#263): run it on a pseudo-terminal whose output is
  // `output.terminal`, with stdout (the final JSON) redirected to its own file.
  const stdoutFile = join(control, "up-stdout");
  await writeFile(stdoutFile, "");
  const upCommand = [
    "/usr/bin/unshare", "--pid", "--fork", `--mount-proc=${join(root, "proc")}`,
    "/usr/sbin/chroot", root, "/infraternal", "up", server.origin, "--json",
  ].map(shellQuote).join(" ");
  const output = { terminal: "" };
  const stdout = async (): Promise<string> => readFile(stdoutFile, "utf8");
  cli = spawn("/usr/bin/script", [
    "--quiet", "--flush", "--return", "--command", `exec ${upCommand} >${shellQuote(stdoutFile)}`, "/dev/null",
  ], {
    detached: true,
    env: {
      // Decoy sudo and systemctl come first: `up` must use the root-owned ones in /usr/bin.
      PATH: "/tmp/decoy:/usr/local/bin:/usr/bin:/bin",
      // No HOSTNAME: shells do not export it, so the name must come from the
      // namespace's kernel host name (`hostname up-e2e-node`, J134 P2-3).
      HOME: "/home/up",
      XDG_DATA_HOME: "/home/up/data",
      SSL_CERT_FILE: "/etc/ssl/certs/ca-certificates.crt",
    },
    // stdin stays an open pipe so the pseudo-terminal never reads end-of-file.
    stdio: ["pipe", "pipe", "pipe"],
  });
  cli.stdout?.on("data", (chunk: Buffer) => { output.terminal += chunk.toString("utf8"); });
  cli.stderr?.on("data", (chunk: Buffer) => { output.terminal += chunk.toString("utf8"); });

  await waitFor(() => USER_CODE.test(output.terminal) && SHORT_KEY.test(output.terminal), 45_000);
  expect((await stdout()).length, "up --json must keep pending progress off stdout").toBe(0);
  const code = output.terminal.match(USER_CODE)?.[1];
  const machineKey = output.terminal.match(SHORT_KEY)?.[1];
  const approvalOrigin = new URL(server.origin).origin;
  expect(/^[A-Za-z0-9_-]{16}$/.test(code ?? "")).toBe(true);
  expect(/^[A-Za-z0-9+/]{4}( [A-Za-z0-9+/]{4}){3}$/.test(machineKey ?? "")).toBe(true);
  expect(output.terminal.includes(`${approvalOrigin}/#join=${code}`)).toBe(true);
  expect(output.terminal.includes("##"), "the terminal approval output must include a QR").toBe(true);
  expect(!/poll_token|"token"\s*:/i.test(output.terminal)).toBe(true);

  // Force a new document before following the printed link: a fragment-only navigation does not rerun the page's startup.
  // Keep the same page target so its virtual passkey authenticator remains available for fresh approval.
  page.on("request", (request) => {
    const url = new URL(request.url());
    if (url.pathname.startsWith("/auth/")) {
      requestLines.push(url.pathname);
      addressAtRequest.push(new URL(page.url()).hash);
    }
  });
  page.on("response", (response) => {
    const url = new URL(response.url());
    if (url.pathname.startsWith("/auth/") || url.pathname.startsWith("/v1/")) {
      responseLines.push(`${url.pathname} ${response.status()}`);
    }
    if (url.pathname === "/auth/device-inspect") inspectedResponse = response;
  });
  page.on("requestfailed", (request) => {
    const url = new URL(request.url());
    if (url.pathname.startsWith("/auth/") || url.pathname.startsWith("/v1/")) {
      failedRequests.push(`${url.pathname} ${request.failure()?.errorText ?? "unknown failure"}`);
    }
  });
  await page.goto("about:blank");
  await gotoWithNetworkRetry(page, `${server.origin}/#join=${code}`);
  try {
    await expect.poll(() => inspectedResponse, { timeout: 15_000 }).toBeDefined();
  } catch (error) {
    const diagnostic = {
      origin: new URL(page.url()).origin,
      hashPresent: await page.evaluate(() => location.hash.length > 0),
      headings: await page.locator("h1, h2").allTextContents(),
      statuses: await page.locator('[role="status"], [role="alert"]').allTextContents(),
      requests: requestLines,
      responses: responseLines,
      failedRequests,
    };
    console.log(`JOIN_APPROVAL_DIAGNOSTIC ${JSON.stringify(diagnostic)}`);
    throw error;
  }
  const inspected = inspectedResponse!;
  expect(inspected.status()).toBe(200);
  const inspection = await inspected.json() as Record<string, unknown>;
  try {
    await expect(page.getByRole("heading", { name: `Add ${MACHINE} to localhost` })).toBeVisible({ timeout: 15_000 });
  } catch (error) {
    const headings = await page.locator("h1, h2").allTextContents();
    const statuses = await page.locator('[role="status"], [role="alert"]').allTextContents();
    const diagnostic = {
      origin: new URL(page.url()).origin,
      hashPresent: await page.evaluate(() => location.hash.length > 0),
      headings,
      statuses,
      requests: requestLines,
      responses: responseLines,
    };
    console.log(`JOIN_APPROVAL_DIAGNOSTIC ${JSON.stringify(diagnostic)}`);
    throw error;
  }
  expect((await page.locator("#device-approval-code").textContent()) === code).toBe(true);
  await expect(page.getByText("System service", { exact: true })).toBeVisible();
  await expect(page.getByText(machineKey!, { exact: true })).toBeVisible();
  expect(Object.keys(inspection).sort()).toEqual(["hostname", "key_fingerprint", "kind", "mode"]);
  expect(inspection.kind).toBe("join_machine");
  expect(inspection.hostname).toBe(MACHINE);
  expect(inspection.mode).toBe("system");
  expect(inspection.key_fingerprint).toEqual(expect.stringMatching(/^SHA256:[A-Za-z0-9+/]{43}$/));
  const encodedKey = String(inspection.key_fingerprint).slice("SHA256:".length, "SHA256:".length + 16);
  expect(machineKey).toBe(encodedKey.match(/.{4}/g)?.join(" "));
  await expect(page.getByRole("button", { name: "Approve with passkey" })).toBeDisabled();
  expect(await page.evaluate(() => location.hash)).toBe("");
  expect(requestLines.length).toBeGreaterThan(0);
  expect(requestLines.every((line) => !line.includes(code!))).toBe(true);
  expect(addressAtRequest.every((hash) => hash === "")).toBe(true);

  if (evidence) {
    await mkdir(evidence, { recursive: true });
    await page.screenshot({
      path: join(evidence, "up-join-approval.png"),
      animations: "disabled",
      mask: [page.locator("#device-approval-code")],
      maskColor: "#111111",
    });
  }

  await page.locator("label.auth-check").click();
  await page.getByRole("button", { name: "Approve with passkey" }).click();
  try {
    await expect(page.getByRole("heading", { name: "Machine approved" })).toBeVisible();
  } catch (error) {
    const diagnostic = {
      headings: await page.locator("h1, h2").allTextContents(),
      statuses: await page.locator('[role="status"], [role="alert"]').allTextContents(),
      requests: requestLines,
      responses: responseLines,
      failedRequests,
    };
    console.log(`JOIN_APPROVAL_PASSKEY_DIAGNOSTIC ${JSON.stringify(diagnostic)}`);
    throw error;
  }
  const result = await waitForExit(cli, 90_000);
  const finalStdout = await stdout();
  const jsonResult = JSON.parse(finalStdout) as Record<string, unknown>;
  if (result.code !== 0) {
    const helper = await readFile(helperOutput, "utf8").catch(() => "");
    const sudo = await readFile(sudoCalls, "utf8").catch(() => "");
    const systemctl = await readFile(serviceSystemctlCalls, "utf8").catch(() => "");
    const serverSystemctl = await readFile(systemctlCalls, "utf8").catch(() => "");
    const helperStages = helper
      .split(/\r?\n/)
      .filter((line) => /^(UP_STAGE=enrollment|UP_RESULT=[0-9]+)$/.test(line));
    const diagnostic = {
      exitCode: result.code,
      state: jsonResult.state,
      errorCode: jsonResult.error_code,
      message: jsonResult.message,
      helperStages,
      sudoCalls: sudo.trim().split(/\r?\n/).filter(Boolean).length,
      systemctlCalls: systemctl.trim().split(/\r?\n/).filter(Boolean),
      serverSystemctlCalls: serverSystemctl.trim().split(/\r?\n/).filter(Boolean),
    };
    throw new Error(`up failed after approval: ${JSON.stringify(diagnostic)}`);
  }
  expect(jsonResult.command === "up" && jsonResult.state === "ready").toBe(true);
  expect(finalStdout.trim().split(/\r?\n/).length).toBe(1);
  expect(!finalStdout.includes(code!)).toBe(true);
  expect(!finalStdout.includes("#join=")).toBe(true);
  expect(!/user_code|poll_token|approval_(url|qr)|"token"\s*:/i.test(finalStdout)).toBe(true);
  expect(finalStdout.includes("/usr/local/bin/infraternal")).toBe(true);
  expect(finalStdout.includes("active")).toBe(true);

  expect(await readFile(decoyCalls, "utf8"), "a PATH decoy ran instead of the trusted program").toBe("");
  expect(await readFile(sudoCalls, "utf8")).toBe("sudo\n");
  expect(await readFile(serviceSystemctlCalls, "utf8")).toBe(
    "daemon-reload\nenable --now infraternal-agent.service\nis-active infraternal-agent.service\n",
  );
  expect(await readlink("/usr/local/bin/infraternal")).toBe(SERVICE_BINARY);
  expect((await stat(SERVICE_BINARY)).size).toBe((await stat(server.binary)).size);
  const unit = await readFile("/etc/systemd/system/infraternal-agent.service", "utf8");
  expect(unit).toContain(`ExecStart=${SERVICE_BINARY} agent run --data /var/lib/infraternal/agent`);
  await access("/var/lib/infraternal/agent/identity.json");
  await expect(access(join(dataHome, "infraternal/agent/join-key.pk8"))).rejects.toThrow();
});

async function enrolOwner(target: Page): Promise<void> {
  const cdp = await target.context().newCDPSession(target);
  await cdp.send("WebAuthn.enable");
  await cdp.send("WebAuthn.addVirtualAuthenticator", { options: {
    protocol: "ctap2",
    ctap2Version: "ctap2_1",
    transport: "internal",
    hasResidentKey: true,
    hasUserVerification: true,
    isUserVerified: true,
    automaticPresenceSimulation: true,
    hasPrf: true,
  } });
  await gotoWithNetworkRetry(target, `${server.origin}/`);
  await target.locator("#setup-token").fill(server.token);
  await target.getByRole("button", { name: "Continue", exact: true }).click();
  await target.locator("#setup-username").fill("up_e2e_owner");
  await target.locator("#setup-display-name").fill("Up e2e owner");
  await target.getByRole("button", { name: "Continue", exact: true }).click();
  await target.getByRole("button", { name: "Create passkey" }).click();
  await expect(target.getByRole("heading", { name: "Save your recovery key" })).toBeVisible();
  await target.locator(".auth-check").click();
  await target.getByRole("button", { name: "Open infraternal" }).click();
  await expect(target.getByRole("application", { name: "Remote terminal" })).toBeVisible({ timeout: 15_000 });
}

/**
 * The namespace's `ip rule` edits reach Chromium as network changes. A navigation can then fail with
 * ERR_NETWORK_CHANGED, or, when run as real root, be cut short by the error page of an earlier attempt committing late.
 */
async function gotoWithNetworkRetry(target: Page, url: string): Promise<void> {
  for (let attempt = 1; ; attempt += 1) {
    try {
      await target.goto(url);
      return;
    } catch (error) {
      const transient = error instanceof Error
        && (error.message.includes("net::ERR_NETWORK_CHANGED") || error.message.includes("chrome-error://chromewebdata/"));
      if (!transient || attempt === 3) throw error;
      await target.waitForTimeout(250);
    }
  }
}

async function provisionRemoteAuthority(target: Page): Promise<void> {
  const requests: string[] = [];
  const responses: string[] = [];
  const failedRequests: string[] = [];
  const onRequest = (request: import("playwright/test").Request): void => {
    const url = new URL(request.url());
    if (url.pathname.startsWith("/remote/ca/") || url.pathname === "/auth/session" || url.pathname === "/auth/wraps") {
      requests.push(`${request.method()} ${url.pathname}`);
    }
  };
  const onResponse = (response: import("playwright/test").Response): void => {
    const url = new URL(response.url());
    if (url.pathname.startsWith("/remote/ca/") || url.pathname === "/auth/session" || url.pathname === "/auth/wraps") {
      responses.push(`${url.pathname} ${response.status()}`);
    }
  };
  const onRequestFailed = (request: import("playwright/test").Request): void => {
    const url = new URL(request.url());
    if (url.pathname.startsWith("/remote/ca/") || url.pathname === "/auth/session" || url.pathname === "/auth/wraps") {
      failedRequests.push(`${url.pathname} ${request.failure()?.errorText ?? "unknown failure"}`);
    }
  };
  target.on("request", onRequest);
  target.on("response", onResponse);
  target.on("requestfailed", onRequestFailed);
  const notification = target.getByRole("group", { name: "Notification" }).filter({
    hasText: "The server restarted. Confirm your passkey once to reconnect your hosts.",
  });
  const unlock = notification
    .getByRole("group", { name: "Notification actions" })
    .getByRole("button", { name: "Unlock", exact: true });
  try {
    await target.evaluate(() => document.dispatchEvent(new Event("visibilitychange")));
    await expect(unlock).toBeVisible({ timeout: 15_000 });
    const readStatus = async (): Promise<{ status: number; body: unknown }> => target.evaluate(async () => {
      const response = await fetch("/remote/ca/status", {
        method: "POST",
        credentials: "same-origin",
        headers: { "content-type": "application/json" },
        body: "{}",
      });
      return { status: response.status, body: await response.json().catch(() => null) };
    });
    const before = await readStatus();
    expect(before).toEqual({ status: 200, body: { initialized: false, locked: true } });
    await unlock.evaluate((button) => (button as HTMLButtonElement).click());
    const messages = new Set<string>();
    let after = before;
    let ready = false;
    for (let attempt = 0; attempt < 30; attempt += 1) {
      for (const message of await target.locator('[role="status"], [role="alert"]').allTextContents()) {
        if (message.trim()) messages.add(message.trim());
      }
      after = await readStatus();
      if (after.status === 200 && typeof after.body === "object" && after.body !== null
        && "initialized" in after.body && after.body.initialized === true
        && "locked" in after.body && after.body.locked === false) {
        ready = true;
        break;
      }
      await target.waitForTimeout(1_000);
    }
    if (!ready) {
      throw new Error(`remote CA setup failed: ${JSON.stringify({ before, after, messages: [...messages], requests, responses, failedRequests })}`);
    }
  } finally {
    target.off("request", onRequest);
    target.off("response", onResponse);
    target.off("requestfailed", onRequestFailed);
  }
}

function shellQuote(value: string): string {
  return `'${value.replaceAll("'", "'\\''")}'`;
}

async function waitFor(predicate: () => boolean, timeoutMs: number): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (!predicate()) {
    if (cli?.exitCode !== null || cli?.signalCode !== null) {
      throw new Error("infraternal up exited before printing its join code");
    }
    if (Date.now() >= deadline) throw new Error("infraternal up did not print its join code in time");
    await new Promise((resolve) => setTimeout(resolve, 50));
  }
}

async function waitForExit(child: ChildProcess, timeoutMs: number): Promise<{ code: number | null; signal: NodeJS.Signals | null }> {
  if (child.exitCode !== null || child.signalCode !== null) {
    return { code: child.exitCode, signal: child.signalCode };
  }
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([
      once(child, "exit").then(([code, signal]) => ({ code: code as number | null, signal: signal as NodeJS.Signals | null })),
      new Promise<never>((_, reject) => { timer = setTimeout(() => reject(new Error("infraternal up did not finish after approval")), timeoutMs); }),
    ]);
  } finally {
    if (timer) clearTimeout(timer);
  }
}
