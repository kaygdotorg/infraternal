/**
 * The product add-host wizard (canvas/addhost) on the clusters canvas, with the real provisioning adapter
 * talking to the test double. Covers every D183 sign-in path, every failure and empty state, and what the
 * wizard hands to the canvas. Secrets: the specs also check that a typed password reaches the server in one
 * request body and nowhere else (no URL, no DOM after submit, no storage).
 */
import { tracerEvidencePath } from "./evidence-path";
import { expect, test, type Page } from "playwright/test";

// These journeys contain several real socket/UI operations. The functional
// watchdog must cover the existing 45-second readiness waits; it is not a
// latency budget. Individual operation assertions retain their own deadlines.
test.setTimeout(120_000);

type Probe = { views(): Array<{ id: string; windows: string[] }>; activeWindow(): string | undefined };
const probe = <T>(page: Page, fn: (p: Probe) => T): Promise<T> =>
  page.evaluate((source) => (new Function("p", `return (${source})(p)`) as (p: unknown) => T)((window as unknown as { __tracerClusters: unknown }).__tracerClusters), fn.toString());

async function config(page: Page, body: Record<string, string>): Promise<void> {
  await page.request.post("/__mock/bootstrap/config", { data: body, maxRetries: 1 });
}

async function open(page: Page, query = "", settings: Record<string, string> = {}): Promise<void> {
  // Fixture setup is idempotent: retry only a reset keep-alive connection,
  // never a product operation or an assertion failure.
  await page.request.post("/__mock/bootstrap/reset", { maxRetries: 1 });
  if (Object.keys(settings).length) await config(page, settings);
  await page.setViewportSize({ width: 1440, height: 900 });
  await page.goto(`/?mock=1&proto=clusters&scene=3&theme=ink&bg=none${query}`);
  await expect(page.locator(".cl-mockup")).toBeVisible({ timeout: 45_000 });
  await expect.poll(() => probe(page, (p) => p.views().length), { timeout: 45_000 }).toBeGreaterThan(0);
  await page.waitForTimeout(400);
}

const wizard = (page: Page) => page.locator(".ah-float");
/** Buttons of the wizard card only: the canvas has its own Back, Close and Retry-like controls. */
const inWizard = (page: Page, name: string) => wizard(page).getByRole("button", { name, exact: true });
/** Waits until a closed wizard has finished its exit, so the next one is the only one on screen. */
const gone = (page: Page) => expect(page.locator(".ah-float")).toHaveCount(0);
async function openWizard(page: Page): Promise<void> {
  await page.evaluate(() => window.dispatchEvent(new CustomEvent("tracer:canvas-action", { detail: { action: "canvas:addhost", source: "keyboard" } })));
  await expect(page.locator(".ah-page[data-page='discovery']")).toBeVisible({ timeout: 45_000 });
}
/** Types a host into the one field and continues. */
async function addTyped(page: Page, host: string): Promise<void> {
  await page.locator(".ui-chip-text").click();
  await page.keyboard.type(`${host} `, { delay: 5 });
  await inWizard(page, "Continue").click();
}
const consoleWindows = (page: Page) => probe(page, (p) => p.views().find((v) => v.id === "console")?.windows ?? []);

test("the toolbar button and the palette open the wizard", async ({ page }) => {
  await open(page);
  // The toolbar row's own button (it is shown on touch and when the canvas row is open); clicking it by script
  // exercises the same wiring.
  await page.locator("[data-cv='add']").evaluate((button) => (button as HTMLButtonElement).click());
  await expect(wizard(page)).toBeVisible();
  await page.keyboard.press("Escape");
  await gone(page);
  await page.keyboard.press("Control+Shift+K");
  await page.keyboard.type("add hosts");
  await page.keyboard.press("Enter");
  await expect(wizard(page)).toBeVisible();
});

test("network access: detected, shown by name, and the host lands in Console and the sidebar", async ({ page }) => {
  await open(page);
  await openWizard(page);
  // The wizard is a window of its own kind, next to the focused window, and it is gone when the flow is done.
  await expect(page.locator(".ui-window[data-kind='flow']")).toHaveCount(1);
  await page.locator(".ah-row[data-host='remoternal']").click();
  await inWizard(page, "Continue").click();
  // remoternal offers sudo: rootless is the default, root needs its own consent.
  await expect(page.getByRole("heading", { name: /Install as root on remoternal/ })).toBeVisible();
  await inWizard(page, "Install as user").click();
  await expect(page.locator(".ah-stage-row[data-stage='detect'] .ah-stage-detail")).toHaveText("Signed in with network access (Tailscale)", { timeout: 15_000 });
  await expect(page.locator(".ah-run[data-state='done']")).toBeVisible({ timeout: 15_000 });
  await expect.poll(() => consoleWindows(page)).toContain("w-remoternal");
  // A closed sidebar stays untouched; opening it renders the current inventory.
  if (await page.locator("#sidebar").isHidden()) await page.locator("#sidebar-toggle").click();
  await expect(page.locator("#tree")).toContainText("remoternal");
  // Setup news belongs to the machine pill; a ready toast can contradict a later failure (D255).
  await expect(page.locator(".toast, [role='status']").filter({ hasText: "remoternal is ready" })).toHaveCount(0);
  await expect(wizard(page)).toHaveCount(0);
  await expect(page.locator(".ui-window[data-kind='flow']")).toHaveCount(0);
});

test("closing the flow window from its own frame ends the wizard", async ({ page }) => {
  await open(page);
  await openWizard(page);
  await page.locator(".ui-window[data-kind='flow'] [data-action='close']").click();
  await expect(wizard(page)).toHaveCount(0);
  await openWizard(page);
  await expect(wizard(page)).toBeVisible();
});

test("the server's own key is the fallback when the network does not sign in", async ({ page }) => {
  await open(page);
  await openWizard(page);
  await page.locator(".ah-row[data-host='web-01']").click();
  await inWizard(page, "Continue").click();
  await expect(page.locator(".ah-stage-row[data-stage='detect'] .ah-stage-detail")).toHaveText("Signed in with this server's key", { timeout: 15_000 });
  await expect.poll(() => consoleWindows(page)).toContain("w-web-01");
});

test("a batch shows every host's own progress and opens every host", async ({ page }) => {
  await open(page);
  await openWizard(page);
  for (const id of ["web-01", "o2", "db-01"]) await page.locator(`.ah-row[data-host='${id}']`).click();
  await inWizard(page, "Continue").click();
  await inWizard(page, "Install as user").click();
  await expect(page.locator(".ah-run")).toHaveCount(3);
  await expect(page.locator(".ah-summary")).toContainText("3 of 3 ready", { timeout: 20_000 });
  await expect.poll(() => consoleWindows(page)).toEqual(expect.arrayContaining(["w-web-01", "w-o2", "w-db-01"]));
});

test("all automatic methods refused: asked to choose, and a password is sent once and never kept", async ({ page }) => {
  const requests: Array<{ url: string; body: string }> = [];
  const privateFrames: boolean[] = [];
  page.on("request", (request) => requests.push({ url: request.url(), body: request.postData() ?? "" }));
  page.on("websocket", (socket) => socket.on("framesent", ({ payload }) => {
    if (!String(payload).startsWith("{")) return;
    const command = JSON.parse(String(payload));
    if (command.auth_once) privateFrames.push(command.auth_once.some((entry: { auth?: { password?: string } }) => entry.auth?.password === "correct horse battery staple"));
  }));
  await open(page);
  await openWizard(page);
  await addTyped(page, "kayg@needs-key.lab");
  await expect(page.getByRole("heading", { name: /Sign in to needs-key.lab/ })).toBeVisible({ timeout: 15_000 });
  await page.getByText("Sign in with a password").click();
  const secret = "correct horse battery staple";
  await page.locator("[data-secret='password']").fill(secret);
  await inWizard(page, "Sign in").click();
  await expect(page.locator(".ah-stage-row[data-stage='detect'] .ah-stage-detail")).toHaveText("Signed in with your password", { timeout: 15_000 });
  await expect.poll(() => consoleWindows(page)).toContain("w-needs-key.lab");
  // Private input is sent once on the authenticated socket; no HTTP credential store exists.
  expect(privateFrames).toEqual([true]);
  expect(requests.some((item) => item.body.includes(secret))).toBe(false);
  expect(requests.some((item) => item.url.includes("correct") || item.url.includes("horse"))).toBe(false);
  expect(await page.evaluate(() => document.body.innerHTML.includes("correct horse") || JSON.stringify({ ...localStorage, ...sessionStorage }).includes("correct horse"))).toBe(false);
});

test("a pasted private key signs in as the user's key", async ({ page }) => {
  await open(page);
  await openWizard(page);
  await addTyped(page, "needs-key.lab");
  await expect(page.getByRole("heading", { name: /Sign in to needs-key.lab/ })).toBeVisible({ timeout: 15_000 });
  await page.getByText("Use a key from your computer").click();
  await inWizard(page, "Sign in").click();
  await expect(page.locator(".ah-error")).toHaveText("Paste the private key first.");
  await page.locator("[data-secret='key']").fill("not-a-real-key-for-the-double");
  await inWizard(page, "Sign in").click();
  await expect(page.locator(".ah-stage-row[data-stage='detect'] .ah-stage-detail")).toHaveText("Signed in with your key", { timeout: 15_000 });
});

test("a saved key (unlocked with the passkey) is offered only when the browser holds one", async ({ page }) => {
  await open(page, "&savedkey=1");
  await openWizard(page);
  await page.locator(".ah-row[data-host='nix-cache']").click();
  await inWizard(page, "Continue").click();
  await inWizard(page, "Install as user").click();
  await expect(page.getByRole("heading", { name: /Sign in to nix-cache/ })).toBeVisible({ timeout: 15_000 });
  await expect(page.getByText("Use work laptop key")).toBeVisible();
  await page.getByText("Use work laptop key").click();
  await inWizard(page, "Sign in").click();
  await expect(page.locator(".ah-stage-row[data-stage='detect'] .ah-stage-detail")).toHaveText("Signed in with your key", { timeout: 15_000 });
});

test("without a saved key the choice does not offer one", async ({ page }) => {
  await open(page);
  await openWizard(page);
  await addTyped(page, "needs-key.lab");
  await expect(page.getByRole("heading", { name: /Sign in to needs-key.lab/ })).toBeVisible({ timeout: 15_000 });
  await expect(page.getByText("Use work laptop key")).toHaveCount(0);
});

test("the server key is shown to copy; adding it and trying again signs in", async ({ page, context }) => {
  await context.grantPermissions(["clipboard-read", "clipboard-write"]);
  await open(page);
  await openWizard(page);
  await addTyped(page, "needs-key.lab");
  await expect(page.getByRole("heading", { name: /Sign in to needs-key.lab/ })).toBeVisible({ timeout: 15_000 });
  const key = page.locator("[data-kv='server'] .ui-kv-value").first();
  await expect(key).toContainText("ssh-ed25519 AAAA");
  await expect(page.locator(".ah-code", { hasText: "authorized_keys" })).toBeVisible();
  await key.click();
  expect(await page.evaluate(() => navigator.clipboard.readText())).toMatch(/^ssh-ed25519 AAAA\S+ infraternal-server$/);
  await inWizard(page, "Try again").click();
  await expect(page.locator(".ah-stage-row[data-stage='detect'] .ah-stage-detail")).toHaveText("Signed in with this server's key", { timeout: 15_000 });
});

test("a locked server key is still shown, with the reason", async ({ page }) => {
  await open(page, "", { sshKey: "locked" });
  await openWizard(page);
  await addTyped(page, "needs-key.lab");
  await expect(page.getByText("locked until an administrator unlocks it")).toBeVisible({ timeout: 15_000 });
  await expect(page.locator("[data-kv='server']")).toContainText("ssh-ed25519");
});

test("no server key to show: the choice is paste or password only", async ({ page }) => {
  await open(page, "", { sshKey: "missing" });
  await openWizard(page);
  await addTyped(page, "needs-key.lab");
  await expect(page.getByRole("heading", { name: /Sign in to needs-key.lab/ })).toBeVisible({ timeout: 15_000 });
  await expect(page.getByText("Use this server's key")).toHaveCount(0);
  await expect(page.locator("input[name='ah-method']:checked")).toHaveValue("key");
});

test("an unknown host key shows its fingerprint and is never trusted without a click", async ({ page }) => {
  await open(page);
  await openWizard(page);
  await addTyped(page, "kayg@newkey.lab");
  await expect(page.getByRole("heading", { name: /Check newkey.lab's key/ })).toBeVisible({ timeout: 15_000 });
  await expect(page.locator(".ah-keyblock")).toContainText(/SHA256:[A-Za-z0-9+/]{43}/);
  await expect(page.locator(".ah-keyblock")).toContainText("ED25519");
  await expect(page.locator(".ah-keyblock")).not.toContainText("Key 2");
  await expect(page.getByText("ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub", { exact: true })).toBeVisible();
  // Nothing proceeds by itself.
  await page.waitForTimeout(800);
  await expect(inWizard(page, "Trust and continue")).toBeVisible();
  expect(await consoleWindows(page)).not.toContain("w-newkey.lab");
  await inWizard(page, "Trust and continue").click();
  await expect(page.locator(".ah-run[data-state='done']")).toBeVisible({ timeout: 15_000 });
});

/** Records every moment a failure screen, a failed row or a danger-toned hero is on screen, so a flow can prove it never showed one. */
async function watchForFailure(page: Page): Promise<void> {
  await page.evaluate(() => {
    const seen: string[] = [];
    (window as unknown as { __sawFailure: string[] }).__sawFailure = seen;
    const look = (): void => {
      if (document.querySelector(".ah-page[data-page='failure']")) seen.push("failure page");
      if (document.querySelector(".ah-run[data-state='failed'], .ah-job[data-state='failed']")) seen.push("failed row");
      if (document.querySelector(".ah-hero[data-tone='danger']")) seen.push("danger hero");
    };
    new MutationObserver(look).observe(document.body, { subtree: true, childList: true, attributes: true });
    look();
  });
}
const sawFailure = (page: Page) => page.evaluate(() => (window as unknown as { __sawFailure: string[] }).__sawFailure);

test("a never-seen host goes straight to the key step: no failure screen, no error icon or tone (#397)", async ({ page }) => {
  await open(page);
  await openWizard(page);
  await watchForFailure(page);
  await addTyped(page, "kayg@newkey.lab");
  await expect(page.getByRole("heading", { name: /Check newkey.lab's key/ })).toBeVisible({ timeout: 15_000 });
  const hero = wizard(page).locator(".ah-page[data-page='hostkey'] .ah-hero");
  await expect(hero).not.toHaveAttribute("data-tone", "danger");
  await expect(hero.locator("path[d^='M10.3 4.6']")).toHaveCount(0);
  await expect(wizard(page).locator(".ah-page[data-page='hostkey'] .ah-lede")).not.toContainText(/warning/i);
  await expect(inWizard(page, "Trust and continue")).toBeVisible();
  await expect(inWizard(page, "Cancel")).toBeVisible();
  await expect(page.locator(".ah-keyblock")).toContainText(/SHA256:/);
  await expect(page.getByText("ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub", { exact: true })).toBeVisible();
  // The step is part of the progress: going back to it shows the host waiting on the key, not failed.
  expect(await sawFailure(page)).toEqual([]);
  await inWizard(page, "Trust and continue").click();
  await expect(page.locator(".ah-run[data-state='done']")).toBeVisible({ timeout: 15_000 });
  expect(await sawFailure(page)).toEqual([]);
});

test("a changed host key stays a real warning with the strong wording (#397)", async ({ page }) => {
  await open(page);
  await openWizard(page);
  await addTyped(page, "kayg@changedkey.lab");
  await expect(page.getByRole("heading", { name: /Check changedkey.lab's key/ })).toBeVisible({ timeout: 15_000 });
  await expect(wizard(page).locator(".ah-page[data-page='hostkey'] .ah-hero")).toHaveAttribute("data-tone", "danger");
  await expect(wizard(page).locator(".ah-page[data-page='hostkey'] .ah-lede")).toContainText("Warning: this host’s trusted key changed");
  await expect(inWizard(page, "Replace trusted key")).toBeVisible();
});

test("a host that does not answer: what happened, Retry, and the one-line install from the host", async ({ page }) => {
  await open(page);
  await openWizard(page);
  await page.locator(".ah-row[data-host='archive-01']").click();
  await inWizard(page, "Continue").click();
  await expect(page.getByRole("heading", { name: "archive-01 isn't answering" })).toBeVisible({ timeout: 15_000 });
  await wizard(page).locator(".ah-details summary").click();
  await expect(page.locator(".ah-details pre")).toContainText("The server said: No SSH answer on port 22");
  await inWizard(page, "Install from the host").click();
  await expect(page.locator(".ah-install .ui-kv-value")).toContainText("curl -fsSL");
  await expect(page.locator(".ah-install")).toContainText("Valid for 15 minutes");
  await inWizard(page, "Back").click();
  await inWizard(page, "Retry").click();
  await expect(page.locator(".ah-run[data-state='done']")).toBeVisible({ timeout: 15_000 });
});

test("a mesh policy block says possible, not certain", async ({ page }) => {
  await open(page);
  await openWizard(page);
  await page.locator(".ah-row[data-host='pve01']").click();
  await inWizard(page, "Continue").click();
  // This discovered host uses a root SSH login; consent still precedes its attempt.
  await expect(page.getByRole("heading", { name: "Install as root on pve01?" })).toBeVisible();
  await page.locator(".ah-consent").click();
  await inWizard(page, "Install as root").click();
  await expect(page.getByRole("heading", { name: "This server can't connect to pve01" })).toBeVisible({ timeout: 15_000 });
  await expect(page.getByText("A network access rule may be blocking it")).toBeVisible();
});

test("an unsupported host cannot be retried; an install failure can", async ({ page }) => {
  await open(page);
  await openWizard(page);
  await addTyped(page, "unsupported.lab");
  await expect(page.getByRole("heading", { name: "unsupported.lab can't run the infraternal agent yet" })).toBeVisible({ timeout: 15_000 });
  await expect(inWizard(page, "Retry")).toHaveCount(0);
  await inWizard(page, "Back").click();
  await inWizard(page, "Back").click();
  await page.locator(".ui-chip-remove").click({ force: true });
  await addTyped(page, "broken.lab");
  await expect(page.getByRole("heading", { name: "Setting up broken.lab didn't finish" })).toBeVisible({ timeout: 15_000 });
  // The failure names its step, so the advice does too (not a chore like "restore access").
  await expect(page.getByText("The infraternal agent was installed but didn't start.", { exact: false })).toBeVisible();
  await expect(page.getByText("restore access", { exact: false })).toHaveCount(0);
  await expect(page.getByText("Automatic cleanup may still need to finish.", { exact: false })).toHaveCount(0);
  await page.locator(".ah-details summary").click();
  await expect(page.locator(".ah-details pre")).toContainText("Failed step: Start infraternal on the host");
  await page.screenshot({ path: tracerEvidencePath("addhost-169", "failure-details.png") });
  await inWizard(page, "Retry").click();
  await expect(page.locator(".ah-run[data-state='done']")).toBeVisible({ timeout: 15_000 });
});

test("one refusal without choose_method still offers another way to sign in", async ({ page }) => {
  await open(page);
  await openWizard(page);
  await addTyped(page, "refused.lab");
  await expect(page.getByRole("heading", { name: "Sign in to refused.lab" })).toBeVisible({ timeout: 15_000 });
});

test("empty, loading and error states of discovery", async ({ page }) => {
  await open(page, "", { discovery: "empty" });
  await openWizard(page);
  await expect(page.locator(".ah-empty")).toContainText("No hosts found yet");
  await page.keyboard.press("Escape");
  await gone(page);

  await config(page, { discovery: "error" });
  await openWizard(page);
  await expect(page.locator(".ah-load-error")).toContainText(/couldn't/i);
  await config(page, { discovery: "ok" });
  await inWizard(page, "Try again").click();
  await expect(page.locator(".ah-row[data-host='o2']")).toBeVisible();
  await page.keyboard.press("Escape");
  await gone(page);

  await config(page, { discovery: "hang" });
  await openWizard(page);
  await expect(page.locator(".ah-loading")).toContainText("Looking for hosts");
  // Typing works while it loads.
  await page.locator(".ui-chip-text").click();
  await page.keyboard.type("kayg@typed.lab ");
  await expect(page.locator(".ui-chip")).toHaveCount(1);
});

test("an SSH config pasted into the field becomes chips", async ({ page }) => {
  await open(page);
  await openWizard(page);
  await page.locator(".ui-chip-text").focus();
  await page.evaluate(() => {
    const data = new DataTransfer();
    data.setData("text/plain", "Host build\n  HostName 10.0.0.5\n  User ops\nHost *\n  User nobody\nHost web\n");
    document.querySelector(".ui-chip-text")!.dispatchEvent(new ClipboardEvent("paste", { clipboardData: data, bubbles: true, cancelable: true }));
  });
  await expect(page.locator(".ui-chip")).toHaveCount(2);
  await expect(page.locator(".ui-chip[data-chip='ops@10.0.0.5']")).toHaveCount(1);
  await expect(page.locator(".ui-chip[data-chip='@web']")).toHaveCount(1);
});

test("closing mid-install asks first, and cancelling ends the run", async ({ page }) => {
  await open(page);
  await openWizard(page);
  await addTyped(page, "cancellation.lab");
  await expect(page.locator(".ah-run[data-state='running']")).toBeVisible({ timeout: 10_000 });
  await page.keyboard.press("Escape");
  await expect(page.getByText("Closing stops installation and asks the server to undo this attempt. Cleanup can remain pending if the host is unavailable.")).toBeVisible();
  await inWizard(page, "Keep installing").click();
  await expect(wizard(page)).toBeVisible();
  await page.locator(".ah-close").click();
  await inWizard(page, "Stop installing").click();
  await expect(wizard(page)).toHaveCount(0);
  expect(await consoleWindows(page)).not.toContain("w-cancellation.lab");
});

test("the wizard works on a phone and keeps the footer on screen", async ({ browser }) => {
  const context = await browser.newContext({ viewport: { width: 393, height: 852 }, hasTouch: true, isMobile: true, baseURL: `http://localhost:${process.env.TRACER_TEST_PORT ?? "4621"}` });
  const page = await context.newPage();
  try {
    // Fixture setup is idempotent: retry only a reset keep-alive connection,
  // never a product operation or an assertion failure.
  await page.request.post("/__mock/bootstrap/reset", { maxRetries: 1 });
    await page.goto("/?mock=1&proto=clusters&scene=3&theme=ink&bg=none");
    await expect(page.locator(".cl-mockup")).toBeVisible({ timeout: 20_000 });
    await openWizard(page);
    // The camera flies to the new window first; measure once it rests.
    await page.waitForTimeout(1500);
    const box = await page.locator(".ah-foot").boundingBox();
    expect(box!.y + box!.height).toBeLessThanOrEqual(852);
    const float = await wizard(page).boundingBox();
    expect(float!.x).toBeGreaterThanOrEqual(0);
    expect(float!.x + float!.width).toBeLessThanOrEqual(393);
  } finally {
    await context.close();
  }
});


for (const mode of ["fresh", "locked"] as const) {
  test(`${mode} CA explains passkey confirmation before starting SSH`, async ({ page }) => {
    await open(page, `&ca=${mode}`);
    await openWizard(page);
    let started = false;
    page.on("websocket", (socket) => socket.on("framesent", ({ payload }) => {
      if (typeof payload === "string") { try { if (JSON.parse(payload).action === "start") started = true; } catch { /* unrelated binary protocol */ } }
    }));
    await addTyped(page, "hosttest@ca-worker");
    await expect(wizard(page).getByRole("heading", { name: `${mode === "fresh" ? "Set up" : "Unlock"} host connections` })).toBeVisible();
    await expect(wizard(page)).toContainText("certificate valid for seven days");
    expect(started).toBe(false);
    await inWizard(page, "Confirm with passkey").click();
    await expect(wizard(page).locator(".ah-page[data-page=progress]")).toBeVisible();
    await expect.poll(() => started).toBe(true);
  });
}


test("a canvas flow remains nonmodal", async ({ page }) => {
  await open(page);
  await openWizard(page);
  await expect(wizard(page)).toHaveAttribute("aria-modal", "false");
});

test("Escape in the palette leaves the add-host flow open", async ({ page }) => {
  await open(page);
  await openWizard(page);
  await page.keyboard.press("Control+Shift+K");
  await expect(page.locator("#palette-input")).toBeVisible();
  await page.locator("#palette-input").focus();
  await page.keyboard.press("Escape");
  await expect(page.locator("#palette-input")).toBeHidden();
  // A closing flow is still in the DOM while its exit runs, so wait out the exit before asserting it stayed.
  await page.waitForTimeout(800);
  await expect(wizard(page)).toBeVisible();
});


test("Tab can leave a canvas flow", async ({ page }) => {
  await open(page);
  await openWizard(page);
  await wizard(page).getByRole("button", { name: "Close", exact: true }).focus();
  await page.keyboard.press("Shift+Tab");
  expect(await wizard(page).evaluate((element) => element.contains(document.activeElement))).toBe(false);
});


test("a typed root login requires consent and cannot pretend to install as a user", async ({ page }) => {
  await open(page);
  await openWizard(page);
  let mode: string | undefined;
  page.on("websocket", (socket) => socket.on("framesent", ({ payload }) => {
    if (typeof payload === "string") { try { const command = JSON.parse(payload); if (command.action === "start") mode = command.targets[0]?.mode; } catch { /* unrelated binary protocol */ } }
  }));
  await addTyped(page, "root@root.lab");
  await expect(wizard(page).getByRole("heading", { name: "Install as root on root.lab?", exact: true })).toBeVisible();
  await expect(inWizard(page, "Install as root")).toBeDisabled();
  await expect(inWizard(page, "Install as user")).toHaveCount(0);
  await expect(wizard(page)).toContainText("go Back and change the SSH sign-in user");
  expect(mode).toBeUndefined();
  await page.locator(".ah-consent").click();
  await inWizard(page, "Install as root").click();
  await expect.poll(() => mode).toBe("root");
});

for (const binary of ["arm64", "x86_64"] as const) for (const viewport of [{ width: 1440, height: 900 }, { width: 393, height: 852 }]) {
  test(`signed ${binary} payload refusal names its step at ${viewport.width}px`, async ({ page }, info) => {
    // Keep the real production wizard and decoder; change only the local
    // stand-in's public failure frame to the release resolver's contract.
    await page.routeWebSocket("**/v1/bootstrap/ws", (socket) => {
      const server = socket.connectToServer();
      server.onMessage((message) => {
        if (typeof message !== "string") { socket.send(message); return; }
        const event = JSON.parse(message) as { failure?: { kind: string; message: string; failed_step?: string; log_tail: string[] }; message: string };
        if (event.failure?.kind === "install") {
          event.failure.failed_step = binary === "arm64" ? "get-arm64-binary" : "get-x86-64-binary";
          event.failure.log_tail = [];
          event.failure.message = "the binary does not match the signed checksum.";
          event.message = event.failure.message;
        }
        socket.send(JSON.stringify(event));
      });
    });
    // Preview-only diagnostics must not cover the product Continue button.
    await open(page, "&fps=0");
    await page.setViewportSize(viewport);
    await openWizard(page);
    await addTyped(page, "broken.lab");
    await expect(wizard(page)).toContainText(`Download infraternal (${binary}): the binary does not match the signed checksum.`, { timeout: 15_000 });
    await wizard(page).locator(".ah-details summary").click();
    await expect(wizard(page).locator(".ah-details pre")).toContainText(`Failed step: Download infraternal (${binary})`);
    const screenshot = info.outputPath(`release-verification-${viewport.width}.png`);
    await page.screenshot({ path: screenshot });
    await info.attach("release verification refusal", { path: screenshot, contentType: "image/png" });
  });
}

// ── Leftovers from an earlier setup (#169): one button forward, never a chore ───────────────────────────────

/** The hero icon's tone: leftovers and a running setup are neutral news, not red errors. */
const heroTone = (page: Page) => page.locator(".ah-page .ah-hero").first().getAttribute("data-tone");

test("leftovers: one Start fresh continues the same setup to done", async ({ page }) => {
  await open(page);
  await openWizard(page);
  await addTyped(page, "stale.lab");
  await expect(page.getByRole("heading", { name: "This host has leftovers from an earlier setup" })).toBeVisible({ timeout: 15_000 });
  await expect(page.locator(".ah-page[data-page='failure'] .ah-lede")).toHaveText("infraternal didn't finish setting up here before. Start fresh to remove what it left behind and continue.");
  expect(await heroTone(page)).toBeNull();
  // The old chores are gone.
  for (const chore of ["restore access", "Finish its cleanup", "lock or unfinished rollback"]) await expect(wizard(page).getByText(chore, { exact: false })).toHaveCount(0);
  // Details lists the findings; they are short sentences, not paths.
  await page.locator(".ah-details summary").click();
  await expect(page.locator(".ah-details pre")).toContainText("An unfinished setup lock");
  await expect(inWizard(page, "Retry")).toHaveCount(0);
  await inWizard(page, "Start fresh").click();
  // No confirmation: straight into the normal progress, then done.
  await expect(page.locator(".ah-page[data-page='progress']")).toBeVisible();
  await expect(page.locator(".ah-run[data-state='done']")).toBeVisible({ timeout: 15_000 });
  await expect.poll(() => consoleWindows(page)).toContain("w-stale.lab");
});

test("leftovers: Back returns to the host list and Start fresh needs the server's challenge", async ({ page }) => {
  await open(page);
  await openWizard(page);
  await addTyped(page, "stale.lab");
  await expect(page.getByRole("heading", { name: "This host has leftovers from an earlier setup" })).toBeVisible({ timeout: 15_000 });
  await inWizard(page, "Back").click();
  await expect(page.locator(".ah-page[data-page='progress']")).toBeVisible();
  // The row offers the same one tap instead of a retry that would only find the leftovers again.
  await expect(page.locator(".ah-job-retry")).toBeHidden();
  await expect(page.locator(".ah-job-fix")).toHaveText("Start fresh");
  await page.locator(".ah-job-fix").click();
  await expect(page.locator(".ah-run[data-state='done']")).toBeVisible({ timeout: 15_000 });
});

test("a setup that is still running: wait, then try again", async ({ page }) => {
  await open(page);
  await openWizard(page);
  await addTyped(page, "running.lab");
  await expect(page.getByRole("heading", { name: "Setup is already running on this host" })).toBeVisible({ timeout: 15_000 });
  await expect(page.getByText("Another setup for this host hasn't finished. Wait for it, or try again in a moment.")).toBeVisible();
  expect(await heroTone(page)).toBeNull();
  await expect(inWizard(page, "Start fresh")).toHaveCount(0);
  await inWizard(page, "Back").click();
  await expect(page.locator(".ah-page[data-page='progress']")).toBeVisible();
  await page.locator(".ah-job-retry").click();
  await expect(page.locator(".ah-run[data-state='done']")).toBeVisible({ timeout: 15_000 });
});

for (const viewport of [{ width: 1440, height: 900 }, { width: 393, height: 852 }]) {
  test(`an already-added host offers its terminal and shows no empty Details at ${viewport.width}`, async ({ page }) => {
    await open(page);
    await page.setViewportSize(viewport);
    await openWizard(page);
    await addTyped(page, "added.lab");
    await expect(page.getByRole("heading", { name: "added.lab is already added" })).toBeVisible({ timeout: 15_000 });
    const failure = wizard(page).locator(".ah-page[data-page='failure']");
    await expect(failure.locator(".ah-lede")).toHaveText("It's already in Console.");
    await expect(failure.locator(".ah-text")).toHaveCount(0);
    await expect(failure.locator(".ah-details")).toHaveCount(0);
    await expect(inWizard(page, "Back")).toBeVisible();
    await page.screenshot({ path: tracerEvidencePath("already-added-open", `after-${viewport.width}.png`) });
    await inWizard(page, "Open a terminal").click();
    await gone(page);
    // The same thing the palette's "Open shell on <host>" does: that host's terminal is the focused window.
    await expect.poll(() => probe(page, (p) => p.activeWindow())).toContain("build-01");
  });

  test(`connect failure has one summary and distinct Details at ${viewport.width}`, async ({ page }) => {
    await open(page);
    await page.setViewportSize(viewport);
    await openWizard(page);
    await addTyped(page, "connectfail.lab");
    await expect(page.getByRole("heading", { name: "Setting up connectfail.lab didn't finish" })).toBeVisible();
    // Page transitions briefly retain the outgoing progress summary in the DOM.
    await expect(wizard(page).locator(".ah-page[data-page='failure'] .ah-lede")).toHaveText("Connecting to the host failed.");
    await expect(wizard(page).getByText("dropped", { exact: false })).toHaveCount(0);
    await wizard(page).locator(".ah-details summary").click();
    const details = wizard(page).locator(".ah-details pre");
    await expect(details).toContainText("The SSH connection setup failed.");
    await expect(details).not.toContainText("Connecting to the host failed.");
    await page.screenshot({ path: tracerEvidencePath("addhost-netbird-connect", `connect-failure-${viewport.width}.png`) });
  });
}

// #394 (owner, production): a root add of minipc01 showed the exit-71 paragraph, and the progress row wrapped it in red.
for (const viewport of [{ width: 1440, height: 900 }, { width: 393, height: 852 }, { width: 375, height: 667 }]) {
  test(`an install this server didn't make is named once, with its location only in Details at ${viewport.width}`, async ({ page }) => {
    await open(page);
    await page.setViewportSize(viewport);
    await openWizard(page);
    await addTyped(page, "installed.lab");
    await expect(page.getByRole("heading", { name: "installed.lab is set up elsewhere" })).toBeVisible({ timeout: 15_000 });
    const failure = wizard(page).locator(".ah-page[data-page='failure']");
    await expect(failure.locator(".ah-lede")).toContainText("nothing was changed");
    // What the page says outside the collapsed Details: no path, no "didn't finish".
    for (const visible of [failure.locator(".ah-title"), failure.locator(".ah-lede")]) {
      await expect(visible).not.toContainText("/var/lib/infraternal");
      await expect(visible).not.toContainText("didn't finish");
    }
    await expect(failure.locator(".ah-text")).toHaveCount(0);
    await expect(inWizard(page, "Try again")).toBeVisible();
    await expect(wizard(page).locator(".ah-page")).toHaveCount(1);
    // The page as it opens: its icon and title are fully inside the card (J314: clipped at 375).
    const top = await failure.evaluate((page) => {
      const scroller = page.closest<HTMLElement>(".ah-scroll") ?? page.parentElement!;
      const box = scroller.getBoundingClientRect();
      return { scrolled: scroller.scrollTop, hero: page.querySelector(".ah-hero")!.getBoundingClientRect().top - box.top, title: page.querySelector(".ah-title")!.getBoundingClientRect().top - box.top };
    });
    expect(top.scrolled).toBe(0);
    expect(top.hero).toBeGreaterThanOrEqual(0);
    expect(top.title).toBeGreaterThanOrEqual(0);
    await page.screenshot({ path: tracerEvidencePath("addhost-394", `installed-failure-${viewport.width}.png`) });
    // Details open shows its text, not an empty caret (J314).
    await failure.locator(".ah-details summary").click();
    await expect(failure.locator(".ah-details pre")).toBeVisible();
    await expect(failure.locator(".ah-details pre")).toContainText("Setup location: /var/lib/infraternal");
    await failure.locator(".ah-details pre").scrollIntoViewIfNeeded();
    await page.screenshot({ path: tracerEvidencePath("addhost-394", `installed-details-${viewport.width}.png`) });
  });

  test(`a login name with no account says so by name at ${viewport.width}`, async ({ page }) => {
    await open(page);
    await page.setViewportSize(viewport);
    await openWizard(page);
    await addTyped(page, "kayg@noacct.lab");
    await expect(page.getByRole("heading", { name: "noacct.lab couldn't find an account named kayg" })).toBeVisible({ timeout: 15_000 });
    await expect(wizard(page).locator(".ah-page[data-page='failure'] .ah-lede")).toHaveText("Use an account that exists there, or add it as root.");
    await expect(wizard(page).locator(".ah-page")).toHaveCount(1);
    await page.screenshot({ path: tracerEvidencePath("addhost-394", `no-account-${viewport.width}.png`) });
  });

  test(`a failed host's progress row says it in one line beside its name at ${viewport.width}`, async ({ page }) => {
    await open(page);
    await page.setViewportSize(viewport);
    await openWizard(page);
    // Two hosts keep the progress page up after the failure, the interim state the owner saw.
    await page.locator(".ui-chip-text").click();
    await page.keyboard.type("installed.lab broken.lab ", { delay: 5 });
    await inWizard(page, "Continue").click();
    await inWizard(page, "Install as user").click({ timeout: 2_000 }).catch(() => undefined);
    const row = wizard(page).locator(".ah-run[data-state='failed']").first();
    await expect(row).toBeVisible({ timeout: 20_000 });
    const step = row.locator(".ah-job-step");
    await expect(step).not.toHaveText("");
    const box = await step.evaluate((element) => {
      const style = getComputedStyle(element);
      const name = element.parentElement!.querySelector(".ah-name")!.getBoundingClientRect();
      const own = element.getBoundingClientRect();
      return { lines: Math.round(own.height / parseFloat(style.lineHeight)), overlap: own.top < name.bottom - 0.5 };
    });
    expect(box).toEqual({ lines: 1, overlap: false });
    // The row tells this news in the page's neutral tone, never red (J314).
    const tone = await row.evaluate((element) => {
      const probe = document.createElement("span");
      probe.style.color = "var(--fg-2)";
      element.append(probe);
      const neutral = getComputedStyle(probe).color;
      probe.remove();
      return { tone: (element as HTMLElement).dataset.tone, step: getComputedStyle(element.querySelector(".ah-job-step")!).color, neutral };
    });
    expect(tone.tone).toBe("info");
    expect(tone.step).toBe(tone.neutral);
    await page.screenshot({ path: tracerEvidencePath("addhost-394", `progress-row-${viewport.width}.png`) });
  });
}

test("a failure with nothing beyond the summary shows no Details at all", async ({ page }) => {
  await open(page);
  await openWizard(page);
  await addTyped(page, "nodetail.lab");
  await expect(page.getByRole("heading", { name: "Setting up nodetail.lab didn't finish" })).toBeVisible();
  // The page already says everything the host reported, so an empty disclosure (or one that repeats the summary) would be noise (TASTE: no empty sections).
  const failure = wizard(page).locator(".ah-page[data-page='failure']");
  await expect(failure.locator(".ah-lede")).toHaveText("Setup stopped before this host was ready.");
  await expect(failure.locator(".ah-details")).toHaveCount(0);
});

// J314 P2-1: the other staging refusals each say what was found, and offer no retry that would meet the same files.
for (const [host, title] of [
  ["unproven-cache.lab", "unproven-cache.lab's download cache isn't setup's own"],
  ["unproven-prepared.lab", "An earlier copy of the agent is in the way on unproven-prepared.lab"],
  ["unproven-foreign.lab", "unproven-foreign.lab's setup folder has files setup didn't make"],
] as const) {
  test(`a staging refusal is named by its cause, with no retry: ${host}`, async ({ page }) => {
    await open(page);
    await openWizard(page);
    await addTyped(page, host);
    await inWizard(page, "Install as user").click({ timeout: 2_000 }).catch(() => undefined);
    await expect(page.getByRole("heading", { name: title, exact: true })).toBeVisible({ timeout: 15_000 });
    await expect(wizard(page).getByText("set up elsewhere", { exact: false })).toHaveCount(0);
    await expect(inWizard(page, "Try again")).toHaveCount(0);
    await expect(inWizard(page, "Retry")).toHaveCount(0);
    await inWizard(page, "Back").click();
    await expect(page.locator(".ah-job-retry")).toBeHidden();
    await page.screenshot({ path: tracerEvidencePath("addhost-394", `refusal-${host.split(".")[0]}-1440.png`) });
  });
}

