// SPDX-License-Identifier: AGPL-3.0-only
/** Records each owner journey and its evidence on the deployed test server. */
import { appendFile, readFile, writeFile } from "node:fs/promises";
import { homedir } from "node:os";
import { join } from "node:path";
import type { Page } from "../../apps/tracer/node_modules/playwright";
import { checkKeys, endShell, openShell, origin, proveShell, until } from "./browser";

const [out, mode, fixturePath] = process.argv.slice(2);

/** Ordered outcomes used to write the final summary after all independent journeys finish. */
const results: { step: string; outcome: string; message: string; ms: number }[] = [];

/** Strip join codes and secret-bearing diagnostic lines before anything is stored or printed. */
export function safe(value: unknown) {
  return String(value)
    .replaceAll(/#join=[A-Za-z0-9_-]+/g, "#join=[redacted]")
    .replaceAll(/^.*(?:private key|passkey material|poll.token|BEGIN [A-Z ]*PRIVATE KEY|(?:^|\s)Code:).*/gim, "[redacted]")
    .replaceAll(/[\u0000-\u0008\u000b-\u001f\u007f]/g, "")
    .slice(0, 1800);
}

/** Saves screenshots with secret inputs and approval codes masked. */
async function screenshot(page: Page, file: string) {
  await page.screenshot({
    path: join(out, file), timeout: 6_000, animations: "disabled",
    mask: [page.locator("#device-approval-code, [data-secret], input[type=password]")],
  });
}

/** Appends a step to the transcript immediately so partial runs remain diagnosable. */
async function record(step: string, outcome: string, message: string, ms: number) {
  const result = { step, outcome, message: safe(message), ms };
  results.push(result);
  await appendFile(join(out, "transcript.jsonl"), JSON.stringify(result) + "\n", { mode: 0o600 });
  console.log(`${outcome.toUpperCase()} ${step} (${ms} ms) ${result.message}`);
}

/** Runs a single step, continuing with independent journeys after a failure. */
export async function step<T>(name: string, page: Page | undefined, action: () => Promise<T>): Promise<T | undefined> {
  const start = Date.now();
  try {
    const value = await action();
    if (page) {
      try { await screenshot(page, `${name}.png`); }
      catch { await record(`${name}-screenshot`, "fail", "Could not save browser screenshot", Date.now() - start); }
    }
    await record(name, "pass", typeof value === "string" ? value : "", Date.now() - start);
    return value;
  } catch (error) {
    // Keep Playwright's first line and app messages. Detailed call logs can include values filled into fields.
    const detail = String(error).split("\n")[0];
    const visible = page ? await page.locator('[role="alert"]:visible, .ui-toast:visible, .ah-page[data-page="failure"]:visible h1')
      .allTextContents().catch(() => []) : [];
    if (page) await screenshot(page, `${name}-failed.png`).catch(() => {});
    await record(name, "fail", [detail, ...visible].join(" | "), Date.now() - start);
    return undefined;
  }
}

/** Reports unmet prerequisites explicitly, without marking a skipped probe as passing. */
export async function skip(stepName: string, reason: string) {
  await record(stepName, "skip", reason, 0);
}

/** Starts the real passkey flow in a fresh desktop or iPhone-sized browser context. */
export async function signIn(label: string, width: number, height: number) {
  return step(`${label}-sign-in`, undefined, async () => {
    const admin = await import(join(homedir(), "infraternal-ops/test-admin-signin.ts"));
    const session: { page: Page; close: () => Promise<void> } = await admin.signIn({ width, height });
    try {
      if (new URL(session.page.url()).origin !== origin) throw new Error("Sign-in reached an unexpected origin");
      session.page.setDefaultTimeout(10_000);
      await screenshot(session.page, `${label}-sign-in.png`);
      return session;
    } catch (error) {
      await session.close();
      throw error;
    }
  });
}

/** Allocates a shell and runs the probe, keys and sidebar confirmation for just that session. */
export async function shellJourney(page: Page, label: string, machine?: string) {
  const shell = await step(`${label}-open-shell`, page, () => openShell(page, machine));
  if (!shell) {
    for (const next of ["shell-output", "shell-keys", "sidebar-end"]) {
      await skip(`${label}-${next}`, "The fresh shell did not open");
    }
    return;
  }
  // A shell's frame is already selected by the palette. The focused input belongs to that newly opened frame.
  const handle = await step(`${label}-shell-focus`, page, async () => {
    const card = page.locator(".ui-window[data-kind=terminal][data-active]");
    await card.waitFor();
    const id = await card.getAttribute("data-window-id");
    if (!id || shell.previous.has(id)) throw new Error("The active terminal belongs to an earlier session");
    return card.locator(".terminal-host textarea").elementHandle();
  });
  try {
    if (handle) {
      await step(`${label}-shell-output`, page, () => proveShell(page, shell, handle));
      await step(`${label}-shell-keys`, page, () => checkKeys(page, shell, handle));
    }
  } finally {
    const ended = await step(`${label}-sidebar-end`, page, () => endShell(page, shell.receipt.id));
    if (!ended && handle) {
      await step(`${label}-shell-exit-cleanup`, undefined, async () => {
        await handle.focus();
        const previous = shell.receipt.input;
        await page.keyboard.press("Control+c");
        await page.keyboard.insertText("exit");
        await page.keyboard.press("Enter");
        await until(() => shell.receipt.input !== previous && shell.receipt.ended,
          "The fresh terminal did not acknowledge exit");
        return "The fresh shell closed after exit";
      });
    }
  }
}

/** Runs each browser size independently and preserves the final status even on a failed step. */
async function main() {
  try {
    for (const [label, width, height] of [["desktop", 1440, 900], ["iphone", 393, 852]] as const) {
      const session = await signIn(label, width, height);
      if (!session) {
        await skip(`${label}-embedded-shell`, "Passkey sign-in failed");
        continue;
      }
      try {
        await shellJourney(session.page, `${label}-embedded`);
      } finally {
        await session.close();
      }
    }
    if (mode === "--fixture") {
      const { runFixture } = await import("./fixtures");
      await runFixture(JSON.parse(await readFile(fixturePath, "utf8")), { signIn, shellJourney, step, skip, screenshot });
    } else {
      for (const check of ["warm-update", "linux-host-lifecycle", "mac-host-lifecycle"]) {
        await skip(check, "This is the unattended browser row. Run --fixture for this journey.");
      }
    }
  } catch (error) {
    await record("runner", "fail", String(error).split("\n")[0], 0);
  } finally {
    await writeFile(join(out, "result.json"), JSON.stringify({ origin, mode, deployedSha: process.env.OWNER_JOURNEYS_DEPLOY_SHA, results }, null, 2) + "\n", { mode: 0o600 });
  }
  process.exitCode = results.some((result) => result.outcome === "fail") ? 1 : 0;
}

if (import.meta.main) await main();
