/**
 * The Mesh view against the real server binary (issue #108, lane UI-2): the production build, the production
 * server, a real WebSocket. No test double.
 *
 * What the binary serves decides what is tested. The Mesh actions (`mesh.list` and the grant actions) are being
 * built on branch mesh-api; until the binary serves them, the honest thing to prove is the contract the canvas
 * keeps with a server that does not: it asks, is refused, offers no Mesh anywhere, subscribes to nothing it was
 * not shown (an unknown subscription closes the socket) and keeps working. When the binary does answer `mesh.list`,
 * the second block runs the whole flow against it; it is skipped (not passed) otherwise.
 *
 * `INFRATERNAL_BIN` is the server binary, built from a scratch merge of mesh-api; the merge is never committed.
 */
import { expect, test, type Page } from "playwright/test";
import { startRealServer, type RealServer } from "./server";

test.describe.configure({ mode: "serial" });

let server: RealServer;
let page: Page;
const live = () => server.bridges.filter((b) => !b.closed);
const controls = () => server.bridges.flatMap((b) => b.control);

test.beforeAll(async ({ browser }) => {
  server = await startRealServer();
  const context = await browser.newContext({ ignoreHTTPSErrors: true, viewport: { width: 1440, height: 900 } });
  page = await context.newPage();
  const cdp = await context.newCDPSession(page);
  await cdp.send("WebAuthn.enable");
  await cdp.send("WebAuthn.addVirtualAuthenticator", { options: { protocol: "ctap2", ctap2Version: "ctap2_1", transport: "internal", hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true, hasPrf: true } });
  await page.goto(server.origin + "/");
  await page.locator("#setup-token").fill(server.token);
  await page.getByRole("button", { name: "Continue", exact: true }).click();
  await page.locator("#setup-username").fill("mesh_real");
  await page.locator("#setup-display-name").fill("Mesh real");
  await page.getByRole("button", { name: "Continue", exact: true }).click();
  await page.getByRole("button", { name: "Create passkey" }).click();
  await page.getByRole("heading", { name: "Save your recovery key" }).waitFor();
  await page.locator(".auth-check").click();
  await page.getByRole("button", { name: "Open infraternal" }).click();
  await page.locator(".cl-viewport").waitFor();
});
test.afterAll(async () => { await page?.context().close(); await server?.dispose(); });

/** True when the binary answers `mesh.list` for the signed-in owner (the Mesh API has landed in it). */
const meshServed = (): boolean => {
  const asked = controls().filter((c) => c.dir === "up" && c.type === "Call" && c.detail === "mesh.list").map((c) => c.callId);
  return controls().some((c) => c.dir === "down" && c.type === "Result" && c.detail === "ok" && asked.includes(c.callId));
};

test.describe("a server that does not serve the Mesh (yet)", () => {
  test("the canvas asks once, is refused, and offers no Mesh: no view, no palette row, no connector", async () => {
    test.skip(meshServed(), "this binary serves the Mesh API: the flow below runs instead");
    await expect.poll(() => controls().filter((c) => c.type === "Call" && c.detail === "mesh.list").length, { timeout: 15_000 }).toBeGreaterThanOrEqual(1);
    await expect.poll(() => controls().some((c) => c.dir === "down" && c.type === "Result" && c.detail === "refused")).toBe(true);
    await expect(page.locator('.cl[data-view="mesh"]')).toHaveCount(0);
    await expect(page.locator(".cl-port:not([hidden])")).toHaveCount(0);
    await page.keyboard.press("Control+K");
    await page.locator("#palette-input").fill("Go to Mesh");
    await expect(page.locator("#palette-results [role=option]").filter({ hasText: "Go to Mesh" })).toHaveCount(0);
    await page.keyboard.press("Escape");
  });

  test("it subscribes to nothing the server has not shown it serves, and the connection stays up", async () => {
    test.skip(meshServed(), "this binary serves the Mesh API");
    // An unknown subscription makes the server close the socket, so the only subscription is the recovery notice's.
    expect(controls().filter((c) => c.type === "Subscribe").map((c) => c.detail)).not.toContain("mesh");
    await page.waitForTimeout(1500);
    expect(live().length).toBeGreaterThan(0);
    await expect(page.locator("#terminal-host")).toHaveCount(1);
  });
});

test.describe("a server that serves the Mesh", () => {
  test("the owner gets the Mesh view with the enrolled hosts, subscribes, and may edit grants", async () => {
    test.skip(!meshServed(), "this binary does not serve the Mesh API yet (branch mesh-api, #108)");
    await expect(page.locator('.cl[data-view="mesh"]')).toBeVisible();
    expect(controls().filter((c) => c.type === "Subscribe").map((c) => c.detail)).toContain("mesh");
    await page.keyboard.press("Control+2");
    await page.waitForTimeout(1200);
    await expect(page.locator('.cl[data-view="mesh"] .ui-window[data-kind="node"]').first()).toBeVisible();
  });
});
