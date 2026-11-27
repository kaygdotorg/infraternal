// SPDX-License-Identifier: AGPL-3.0-only
/** Drives enrolled test fixtures through the owner-facing browser and CLI entry points. */
import { readFile, stat } from "node:fs/promises";
import type { Page } from "../../apps/tracer/node_modules/playwright";
import { origin, palette, until } from "./browser";
import type { shellJourney, signIn, skip, step } from "./run";

/** One leased, disposable machine. The driver owns fixture isolation and executes the real CLI. */
interface HostFixture {
  name: string;
  ssh: string;
  fingerprint: string;
  keyFile?: string;
  driver: string;
}

/** Operator-supplied fixture addresses and executable adapters, selected only for a full run. */
interface Fixture {
  linux: HostFixture;
  mac: HostFixture;
  warmUpdate: string;
}

/** Shared recording and browser functions provided by the runner. */
interface Harness {
  signIn: typeof signIn;
  shellJourney: typeof shellJourney;
  step: typeof step;
  skip: typeof skip;
  screenshot(page: Page, file: string): Promise<void>;
}

/** Bound CLI output in memory, since the PTY may carry a join code and its QR. */
function start(program: string, ...args: string[]) {
  if (!program.startsWith("/")) throw new Error("Fixture drivers must be absolute executable paths");
  let output = "";
  const child = Bun.spawn([program, ...args], { stdout: "pipe", stderr: "pipe", stdin: "ignore" });
  /** Collect one pipe without logging it or accumulating unbounded output. */
  async function collect(stream: ReadableStream<Uint8Array>) {
    const reader = stream.getReader();
    const decoder = new TextDecoder();
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      output = (output + decoder.decode(value, { stream: true })).slice(-24_000);
    }
  }
  const finished = Promise.all([child.exited, collect(child.stdout), collect(child.stderr)]).then(([exit]) => exit);
  const timeout = setTimeout(() => child.kill("SIGKILL"), 240_000);
  void finished.finally(() => clearTimeout(timeout));
  return { child, finished, get output() { return output; } };
}

/** Runs an adapter operation and returns its sanitized user-facing text to the journal. */
async function cli(executable: string, operation: string, ...args: string[]) {
  const run = start(executable, operation, ...args);
  const exit = await run.finished;
  const message = run.output.trim();
  if (exit !== 0) throw new Error(`${operation} exited ${exit}: ${message.split("\n").at(-1) || "no message"}`);
  return message || `${operation} exited 0`;
}

/** Opens Add hosts as the owner would, entering only the predeclared fixture address. */
async function addBySsh(page: Page, fixture: HostFixture, shot: () => Promise<void>) {
  const action = await palette(page, "Add hosts");
  await action.filter({ has: page.getByText("Add hosts", { exact: true }) }).click();
  const wizard = page.getByRole("dialog", { name: "Add hosts", exact: true });
  const input = wizard.locator(".ui-chip-text");
  await input.click();
  await page.keyboard.insertText(fixture.ssh);
  await page.keyboard.press("Space");
  await wizard.getByRole("button", { name: "Continue", exact: true }).click();
  const trust = wizard.getByRole("button", { name: "Trust and continue", exact: true });
  const pasteKey = wizard.getByText("Use a key from your computer", { exact: true });
  const ready = wizard.getByText("Ready. The host is in your sidebar.", { exact: true });
  const failure = wizard.locator('.ah-page[data-page="failure"]:not(.is-leaving)');
  const failedRow = wizard.locator('.ah-run[data-state="failed"]:visible');
  const attended = new Set<string>();
  let result: { added: boolean; message: string } | undefined;
  try {
    await until(async () => {
      if (await ready.isVisible()) {
        result = { added: true, message: (await ready.innerText()).trim() };
        return true;
      }
      if (await failure.isVisible()) {
        const message = (await failure.innerText()).trim();
        if (!/\binfraternal up\b/.test(message)) throw new Error(message);
        result = { added: false, message };
        return true;
      }
      if (await failedRow.isVisible() && !await trust.isVisible() && !await pasteKey.isVisible()) {
        const fix = failedRow.getByRole("button", { name: /Check the key|Sign in another way|Install from the host/ });
        if (await fix.isVisible()) { await fix.click(); return false; }
        const message = (await failedRow.innerText()).trim();
        if (!/\binfraternal up\b/.test(message)) throw new Error(message);
        result = { added: false, message };
        return true;
      }
      if (await trust.isVisible() && !attended.has("trust")) {
        const shown = wizard.getByText(fixture.fingerprint, { exact: true });
        if (!await shown.isVisible()) throw new Error("SSH host key did not match the pinned fixture fingerprint");
        await trust.click();
        attended.add("trust");
      }
      if (await pasteKey.isVisible() && !attended.has("key")) {
        if (!fixture.keyFile) throw new Error("The Add hosts card asked for a fixture SSH key");
        const keyInfo = await stat(fixture.keyFile);
        if (!keyInfo.isFile() || keyInfo.mode & 0o077) throw new Error("Fixture SSH key must be a private file");
        await pasteKey.click();
        // Suppress locator input diagnostics, which can include the key itself.
        try {
          await wizard.locator("[data-secret=key]").fill(await readFile(fixture.keyFile, "utf8"));
          await wizard.getByRole("button", { name: "Sign in", exact: true }).click();
        } catch {
          throw new Error("The Add hosts card could not submit the fixture SSH key");
        }
        attended.add("key");
      }
      return false;
    }, "The Add hosts wizard reached neither Ready nor a clear refusal", 100_000);
    await shot();
    if (!result) throw new Error("The Add hosts wizard produced no result");
    return result;
  } finally {
    if (await wizard.isVisible()) {
      await wizard.locator(".ah-close").click();
      const stop = wizard.getByRole("button", { name: "Stop installing", exact: true });
      if (await stop.isVisible()) await stop.click();
    }
  }
}

/** Follows the PTY's approval link only on the test origin and compares the displayed code and machine key. */
async function joinHost(page: Page, host: HostFixture, platform: "linux" | "mac", shot: () => Promise<void>) {
  const run = start(host.driver, "up", origin);
  try {
    const approval = await until(() => {
      const code = run.output.match(/#join=([A-Za-z0-9_-]{16})\b/)?.[1];
      const key = run.output.match(/Machine key: ([A-Za-z0-9+/]{4}(?: [A-Za-z0-9+/]{4}){3})/)?.[1];
      if (code && key) return { code, key };
      if (run.child.exitCode !== null) throw new Error(`up exited ${run.child.exitCode}: ${run.output.trim().split("\n").at(-1)}`);
    }, "infraternal up never printed the approval URL and machine key", 55_000);
    await page.goto("about:blank");
    try {
      await page.goto(`${origin}/#join=${approval.code}`);
    } catch {
      throw new Error("Could not open the test server's machine approval page");
    }
    const title = page.getByRole("heading", { name: new RegExp(`^Add ${host.name.replaceAll(".", "\\.")} to `) });
    await title.waitFor();
    const mode = platform === "mac" ? "User service" : "System service";
    await page.getByText(mode, { exact: true }).waitFor();
    if ((await page.locator("#device-approval-code").innerText()).trim() !== approval.code ||
        !await page.getByText(approval.key, { exact: true }).isVisible()) throw new Error("The browser code or machine key differed from the CLI");
    await shot();
    await page.locator("label.auth-check").click();
    await page.getByRole("button", { name: "Approve with passkey", exact: true }).click();
    await page.getByRole("heading", { name: "Machine approved", exact: true }).waitFor();
    const exit = await run.finished;
    if (exit !== 0) throw new Error(`up exited ${exit}: ${run.output.trim().split("\n").at(-1)}`);
    if (!/Machine joined as|Service: active|joined the server in user mode/.test(run.output)) throw new Error("up exited without a ready installation message");
    await page.goto(origin);
    return `Machine approved, ${mode}. ${run.output.split("\n").filter((line) => /Machine joined as|Service: active|joined the server in user mode/.test(line)).join(" ")}`;
  } finally {
    if (run.child.exitCode === null) run.child.kill("SIGTERM");
    await run.finished;
  }
}

/** Runs the confirmation on a specific hostname and waits for the server's response. */
async function hostAction(page: Page, name: string, verb: "Remove" | "Forget", cancel = false) {
  const label = verb === "Remove" ? `Remove host: ${name}` : `Forget ${name}`;
  const rows = await palette(page, label);
  await rows.filter({ has: page.getByText(label, { exact: true }) }).click();
  const tip = page.locator(".ui-confirm-tip[data-open=true]").filter({ hasText: `${verb} ${name}?` });
  const question = (await tip.innerText()).trim();
  if (cancel) {
    await tip.getByRole("button", { name: "Keep", exact: true }).click();
    return question;
  }
  const route = verb === "Remove" ? "remove/finish" : "forget";
  const reply = page.waitForResponse((response) => {
    const url = new URL(response.url());
    return url.origin === origin && url.pathname === `/remote/hosts/${route}` && response.request().method() === "POST" && response.status() !== 428;
  }, { timeout: 24_000 }).catch(() => undefined);
  await tip.getByRole("button", { name: verb, exact: true }).click();
  const tap = page.getByRole("button", { name: "Confirm with passkey", exact: true });
  if (await Promise.race([tap.waitFor({ timeout: 24_000 }).then(() => true, () => false), reply.then(() => false)])) await tap.click();
  const response = await reply;
  if (!response) throw new Error(`${verb} did not return a completion response`);
  const body = await response.json().catch(() => ({}));
  if (!response.ok() || (verb === "Forget" ? body.state !== "forgotten" : !["pending", "removed"].includes(body.state))) {
    throw new Error(`${verb} returned ${response.status()}: ${body.message ?? body.state ?? "no status"}`);
  }
  return `${question} • ${body.message ?? body.state}`;
}

/** Checks the fixture's displayed identity before any operation which might change machine state. */
function validate(fixture: HostFixture) {
  if (!fixture || !/^owner-journey-[a-z0-9.-]+$/.test(fixture.name) ||
      !/^[a-z_][a-z0-9_-]*@[a-z0-9.-]+(?::[0-9]+)?$/.test(fixture.ssh) ||
      !/^SHA256:[A-Za-z0-9+/]{43}$/.test(fixture.fingerprint) ||
      !fixture.driver?.startsWith("/")) throw new Error("A fixture needs a dedicated owner-journey hostname, SSH address and pinned key, and an absolute driver");
}

/** Covers one disposable machine, releasing its lease and cleaning its installation on every path. */
async function lifecycle(h: Harness, page: Page, host: HostFixture, platform: "linux" | "mac") {
  const phase = `${platform}-${host.name}`;
  const lease = await h.step(`${phase}-fixture-preflight`, undefined, () => cli(host.driver, "prepare", origin, host.name));
  if (!lease) return h.skip(`${phase}-lifecycle`, "Fixture preflight failed");
  try {
    const unique = await h.step(`${phase}-display-name`, page, async () => {
      const rows = await palette(page, host.name);
      const matching = rows.filter({ has: page.getByText(
        new RegExp(`^(?:Open shell on |Remove host: |Forget )?${host.name.replaceAll(".", "\\.")}$`),
      ) });
      if (await matching.count()) throw new Error("A host with the fixture name is already present");
      await page.keyboard.press("Escape");
      return "The fixture name is available";
    });
    if (!unique) return h.skip(`${phase}-lifecycle`, "Fixture name already present or inventory unavailable");
    const ssh = await h.step(`${phase}-add-ssh`, page, async () => {
      const outcome = await addBySsh(page, host, () => h.screenshot(page, `${phase}-add-ssh-outcome.png`));
      return `${outcome.added ? "Added" : "Refused; CLI alternative offered"}: ${outcome.message}`;
    });
    // The SSH install, if successful, is a separate enrollment. Verify it and remove it before exercising fresh up.
    if (ssh?.startsWith("Added:")) {
      await h.shellJourney(page, `${phase}-ssh`, host.name);
      await h.step(`${phase}-remove-ssh-install`, page, () => hostAction(page, host.name, "Remove"));
      await h.step(`${phase}-wait-ssh-cleanup`, undefined, () => cli(host.driver, "verify-clean"));
    }
    const joined = await h.step(`${phase}-up-approve`, page, () => joinHost(page, host, platform, () => h.screenshot(page, `${phase}-approval.png`)));
    if (!joined) return h.skip(`${phase}-joined-host-checks`, "Fresh up or passkey approval failed");
    await h.step(`${phase}-status`, undefined, async () => {
      const output = await cli(host.driver, "status");
      if (!/infraternal agent is running on this machine/i.test(output)) throw new Error(output);
      return output;
    });
    await h.step(`${phase}-mesh-status`, undefined, async () => {
      const output = await cli(host.driver, "mesh-status");
      if (!/Mesh is on|Mesh system service is running/i.test(output)) throw new Error(output);
      return output;
    });
    await h.shellJourney(page, `${phase}-joined`, host.name);
    const offline = await h.step(`${phase}-offline-for-remove`, undefined, () => cli(host.driver, "offline"));
    if (!offline) return h.skip(`${phase}-remove-forget`, "Could not stop the fixture's service for the offline flow");
    await h.step(`${phase}-remove-cancel`, page, () => hostAction(page, host.name, "Remove", true));
    const removed = await h.step(`${phase}-remove`, page, () => hostAction(page, host.name, "Remove"));
    if (removed) await h.step(`${phase}-forget`, page, () => hostAction(page, host.name, "Forget"));
    else await h.skip(`${phase}-forget`, "Remove did not revoke the fixture host");
    await h.step(`${phase}-uninstall`, undefined, () => cli(host.driver, "uninstall"));
    const clean = await h.step(`${phase}-verify-uninstall`, undefined, () => cli(host.driver, "verify-clean"));
    if (clean) {
      const rejoined = await h.step(`${phase}-rejoin`, page, () => joinHost(page, host, platform, () => h.screenshot(page, `${phase}-rejoin-approval.png`)));
      if (rejoined) {
        await h.shellJourney(page, `${phase}-rejoined`, host.name);
        const removedAgain = await h.step(`${phase}-remove-rejoined`, page, () => hostAction(page, host.name, "Remove"));
        if (removedAgain) await h.step(`${phase}-wait-rejoin-cleanup`, undefined, () => cli(host.driver, "verify-clean"));
      }
    } else await h.skip(`${phase}-rejoin`, "Uninstall left state on the machine");
  } finally {
    await h.step(`${phase}-fixture-release`, undefined, () => cli(host.driver, "release"));
  }
}

/** Runs the warm apply and both disposable machine journeys against the same deployed test instance. */
export async function runFixture(config: Fixture, h: Harness) {
  validate(config.linux);
  validate(config.mac);
  if (config.linux.name === config.mac.name || config.linux.ssh === config.mac.ssh) throw new Error("Linux and Mac fixtures must be distinct");
  if (!config.warmUpdate?.startsWith("/")) throw new Error("Warm update requires an absolute test-server driver");
  const desktop = await h.signIn("fixture-desktop", 1440, 900);
  if (desktop) {
    try {
      await h.shellJourney(desktop.page, "embedded-before-warm");
      const applied = await h.step("warm-update-apply", undefined, async () => {
        const output = await cli(config.warmUpdate, "apply", origin);
        if (!/server restarted warm/i.test(output)) throw new Error("Update did not report a successful warm restart: " + output);
        return output;
      });
      if (applied) await h.shellJourney(desktop.page, "embedded-after-warm");
      else await h.skip("embedded-after-warm", "No warm update was verified");
      await lifecycle(h, desktop.page, config.linux, "linux");
    } finally {
      await desktop.close();
    }
  } else await h.skip("warm-and-linux", "Desktop sign-in failed");
  const phone = await h.signIn("fixture-iphone", 393, 852);
  if (phone) {
    try { await lifecycle(h, phone.page, config.mac, "mac"); }
    finally { await phone.close(); }
  } else await h.skip("mac-lifecycle", "iPhone-sized sign-in failed");
}
