/**
 * The product add-host wizard (canvas/addhost) on the clusters canvas, with the real provisioning adapter
 * talking to the test double. Covers every D183 sign-in path, every failure and empty state, and what the
 * wizard hands to the canvas. Secrets: the specs also check that a typed password reaches the server in one
 * request body and nowhere else (no URL, no DOM after submit, no storage).
 */
import { expect, test, type Page } from "playwright/test";

type Probe = { views(): Array<{ id: string; windows: string[] }> };
const probe = <T>(page: Page, fn: (p: Probe) => T): Promise<T> =>
  page.evaluate((source) => (new Function("p", `return (${source})(p)`) as (p: unknown) => T)((window as unknown as { __tracerClusters: unknown }).__tracerClusters), fn.toString());

async function config(page: Page, body: Record<string, string>): Promise<void> {
  await page.request.post("/__mock/bootstrap/config", { data: body });
}

async function open(page: Page, query = "", settings: Record<string, string> = {}): Promise<void> {
  await page.request.post("/__mock/bootstrap/reset");
  if (Object.keys(settings).length) await config(page, settings);
  await page.setViewportSize({ width: 1440, height: 900 });
  await page.goto(`/?mock=1&proto=clusters&scene=3&theme=ink&bg=none${query}`);
  await expect(page.locator(".cl-mockup")).toBeVisible({ timeout: 20_000 });
  await expect.poll(() => probe(page, (p) => p.views().length)).toBeGreaterThan(0);
  await page.waitForTimeout(400);
}

const wizard = (page: Page) => page.locator(".ah-float");
/** Buttons of the wizard card only: the canvas has its own Back, Close and Retry-like controls. */
const inWizard = (page: Page, name: string) => wizard(page).getByRole("button", { name, exact: true });
/** Waits until a closed wizard has finished its exit, so the next one is the only one on screen. */
const gone = (page: Page) => expect(page.locator(".ah-float")).toHaveCount(0);
async function openWizard(page: Page): Promise<void> {
  await page.evaluate(() => window.dispatchEvent(new CustomEvent("tracer:canvas-action", { detail: { action: "canvas:addhost", source: "keyboard" } })));
  await expect(page.locator(".ah-page[data-page='discovery']")).toBeVisible();
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
  await page.keyboard.press("Control+k");
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
  await expect(page.locator(".toast, [role='status']").filter({ hasText: "remoternal is ready" })).toBeVisible();
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
  await expect(page.locator(".ah-stage-row[data-stage='detect'] .ah-stage-detail")).toHaveText("Signed in with your saved key", { timeout: 15_000 });
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
  await expect(page.locator(".ah-stage-row[data-stage='detect'] .ah-stage-detail")).toHaveText("Signed in with your saved key", { timeout: 15_000 });
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
  // Nothing proceeds by itself.
  await page.waitForTimeout(800);
  await expect(inWizard(page, "Trust this key")).toBeVisible();
  expect(await consoleWindows(page)).not.toContain("w-newkey.lab");
  await inWizard(page, "Trust this key").click();
  await expect(page.locator(".ah-run[data-state='done']")).toBeVisible({ timeout: 15_000 });
});

test("a host that does not answer: what happened, Retry, and the one-line install from the host", async ({ page }) => {
  await open(page);
  await openWizard(page);
  await page.locator(".ah-row[data-host='archive-01']").click();
  await inWizard(page, "Continue").click();
  await expect(page.getByRole("heading", { name: "archive-01 isn't answering" })).toBeVisible({ timeout: 15_000 });
  await page.getByText("Details").click();
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
  await expect(page.getByText("undone").first()).toBeVisible();
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
  await page.locator(".ah-row[data-host='web-01']").click();
  await inWizard(page, "Continue").click();
  await expect(page.locator(".ah-run[data-state='running']")).toBeVisible({ timeout: 10_000 });
  await page.keyboard.press("Escape");
  await expect(page.getByText("If you close this now, the install stops and its changes on the host are undone.")).toBeVisible();
  await inWizard(page, "Keep installing").click();
  await expect(wizard(page)).toBeVisible();
  await page.locator(".ah-close").click();
  await inWizard(page, "Stop installing").click();
  await expect(wizard(page)).toHaveCount(0);
  expect(await consoleWindows(page)).not.toContain("w-web-01");
});

test("the wizard works on a phone and keeps the footer on screen", async ({ browser }) => {
  const context = await browser.newContext({ viewport: { width: 393, height: 852 }, hasTouch: true, isMobile: true, baseURL: `http://localhost:${process.env.TRACER_TEST_PORT ?? "4621"}` });
  const page = await context.newPage();
  try {
    await page.request.post("/__mock/bootstrap/reset");
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

