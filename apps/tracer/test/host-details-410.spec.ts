/**
 * Each window's machine details describe the window's own host (#410): the server's window shows the server's machine and an
 * added host's window shows that host's system, CPU, address and kind. An offline host says so in plain words and never shows the
 * server's machine in its place. The server's replies come from the socket interceptor below (the test double has no remote
 * agents); the real-server run with a real added host is a separate job step. Screenshots (1440x900 and 393x852, ink and
 * paper) go to the external evidence directory.
 */
import { resolve } from "node:path";
import { expect, test, type Page } from "playwright/test";
import { decodeMuxedFrame, encodeMuxedFrame } from "../../../packages/protocol/src/codec";
import { tracerEvidencePath } from "./evidence-path";

/** How long to wait for a panel value that arrives from the (intercepted) socket. */
const slow = { timeout: 40_000 };
/** Where the captures go: the external evidence directory, never the checkout. */
const OUT = tracerEvidencePath("host-details-410");
/** The admitted id of the one added host in this spec. */
const WORKER_ID = "22222222-3333-4444-8555-666666666666";
/** Encodes a JSON reply body for a Result frame. */
const reply = (value: unknown) => new TextEncoder().encode(JSON.stringify(value));
/** What the server's own agent reports: the machine the panel must show only for the server's own windows. */
const SERVER_FACTS = { os: "AlmaLinux", version: "10.2", kernel: "6.12.0-124", architecture: "x86_64", cpuModel: "Intel N100", logicalCpus: 4, executionUid: 0, mode: "embedded", engines: [] };
/** What the added host's agent reports: different in system, CPU, architecture and kind from the server's. */
const WORKER_FACTS = { os: "Debian GNU/Linux", version: "13", kernel: "6.12.57", architecture: "aarch64", cpuModel: "Neoverse N1", logicalCpus: 8, executionUid: 1000, mode: "remote", engines: ["Podman"] };
/** The two review sizes: a desktop and a phone (name, viewport, pixel ratio). */
const SIZES = [["desktop", { width: 1440, height: 900 }, 1], ["phone", { width: 393, height: 852 }, 2]] as const;

/** Answers the socket's host-facts and host-list calls: the server's own facts, one added host, and that host's facts (or "host offline"). */
async function serve(page: Page, worker: { online: boolean }): Promise<{ asked: string[] }> {
  const asked: string[] = [];
  await page.routeWebSocket(/\/v1\/ws(?:\?|$)/, (socket) => {
    const server = socket.connectToServer();
    const send = (callId: number, ok: boolean, value: unknown) => socket.send(Buffer.from(encodeMuxedFrame(0, { type: "Result", callId, ok, json: reply(value) })));
    socket.onMessage((message) => {
      if (typeof message === "string") { server.send(message); return; }
      const { frame } = decodeMuxedFrame(message);
      if (frame.type === "Call" && frame.actionId === "host.facts.read") { asked.push("host.facts.read"); send(frame.callId, true, SERVER_FACTS); return; }
      if (frame.type === "Call" && frame.actionId === "remote.host.facts") {
        asked.push(`remote.host.facts ${JSON.parse(new TextDecoder().decode(frame.inputJson)).host_id}`);
        if (worker.online) send(frame.callId, true, WORKER_FACTS); else send(frame.callId, false, { error: "host offline" });
        return;
      }
      if (frame.type === "Call" && frame.actionId === "remote.host.list") {
        send(frame.callId, true, { hosts: [{ id: WORKER_ID, name: "worker", user: "operator", os: "Debian GNU/Linux", address: "operator@worker.lan", online: worker.online }], next: null });
        return;
      }
      // The test double closes the socket on a session open for a host it does not know, which would hide every later read.
      if (frame.type === "Call" && frame.actionId === "ssh.session.open") { send(frame.callId, false, { error: "unavailable" }); return; }
      server.send(message);
    });
    server.onMessage((message) => socket.send(message));
  });
  return { asked };
}

/** Lets the popover finish opening so the capture shows its settled frame, not the growth animation. */
async function settle(page: Page): Promise<void> {
  // sleep: the popover grows for about 300 ms; the capture is evidence for a human, not an assertion
  await page.waitForTimeout(700);
}

/** The value beside `key` in the open popover. */
const value = (page: Page, key: string) => page.locator(".canvas-popover .ui-kv-key", { hasText: new RegExp(`^${key}$`) }).locator("xpath=..").locator(".ui-kv-value");

/** Replacement rows keep labels at the left edge and values at the right edge on desktop and phone. */
async function checkAlignment(page: Page): Promise<void> {
  const edges = await page.locator(".canvas-popover .ui-kv-value").evaluateAll((cells) => cells
    .filter((cell) => cell.getBoundingClientRect().width > 0)
    .map((cell) => cell.getBoundingClientRect().right));
  expect(edges.length).toBeGreaterThan(1);
  expect(Math.max(...edges) - Math.min(...edges)).toBeLessThanOrEqual(0.5);
  const labels = await page.locator(".canvas-popover .ui-kv-key").evaluateAll((cells) => cells
    .filter((cell) => cell.getBoundingClientRect().width > 0)
    .map((cell) => cell.getBoundingClientRect().left));
  expect(Math.max(...labels) - Math.min(...labels)).toBeLessThanOrEqual(0.5);
}

/** Opens a shell on the added host through the palette, so its window exists next to the server's. */
async function openWorker(page: Page): Promise<void> {
  await page.keyboard.press("Control+Shift+K");
  await page.locator("#palette-input").fill("Open shell on worker");
  await page.locator("#palette-results [role=option]").filter({ hasText: "Open shell on worker" }).click();
}

/** The window whose pill names `host`. */
const windowOf = (page: Page, host: string) => page.locator(".ui-window").filter({ has: page.locator(".ui-window-host", { hasText: host }) }).first();

for (const [name, viewport, scale] of SIZES) {
  for (const theme of ["ink", "paper"]) {
    test(`machine details name the window's own host: ${name} ${theme}`, async ({ browser }) => {
      test.setTimeout(120_000);
      const context = await browser.newContext({ viewport, deviceScaleFactor: scale, ...(name === "phone" ? { hasTouch: true, isMobile: true } : {}) });
      const page = await context.newPage();
      const worker = { online: true };
      const { asked } = await serve(page, worker);
      await page.request.post("/__mock/reset");
      await page.goto(`/?mock=1&proto=product&fresh=1&bg=none&theme=${theme}`);
      const first = page.locator(".ui-window").first();
      await expect(first.locator(".ui-window-host")).toHaveText(/\S/, slow);
      const serverHost = (await first.locator(".ui-window-host").innerText()).trim();

      // The server's own window: the server's machine.
      await first.locator(".ui-window-pill").click();
      await expect(value(page, "System")).toHaveText("AlmaLinux 10.2", slow);
      await expect(value(page, "CPU")).toHaveText("4 logical cores · Intel N100");
      await expect(value(page, "Infraternal agent")).toHaveText("Embedded · root");
      await settle(page);
      await page.screenshot({ path: resolve(OUT, `server-host-${name}-${theme}.png`) });
      await first.locator(".ui-window-pill").click();
      await expect(page.locator(".canvas-popover")).toHaveCount(0);

      // An added host's window: that host's machine, its address, and its kind.
      await openWorker(page);
      const added = windowOf(page, "worker");
      await added.locator(".ui-window-pill").click();
      await expect(value(page, "System")).toHaveText("Debian GNU/Linux 13", slow);
      await expect(value(page, "CPU")).toHaveText("8 logical cores · Neoverse N1");
      await expect(value(page, "Address")).toHaveText("operator@worker.lan");
      await expect(value(page, "Infraternal agent")).toHaveText("Remote · user");
      await expect(page.locator(".canvas-popover")).not.toContainText("AlmaLinux");
      await expect(page.locator(".canvas-popover")).not.toContainText("Intel N100");
      await checkAlignment(page);
      await settle(page);
      await page.screenshot({ path: resolve(OUT, `added-host-${name}-${theme}.png`) });
      expect(asked).toContain("host.facts.read");
      expect(asked).toContain(`remote.host.facts ${WORKER_ID}`);
      expect(serverHost).not.toBe("worker");

      // The same host once it goes offline: said in plain words, with nothing from the server in its place.
      await added.locator(".ui-window-pill").click();
      await expect(page.locator(".canvas-popover")).toHaveCount(0);
      worker.online = false;
      await added.locator(".ui-window-pill").click();
      await expect(value(page, "System")).toHaveText("Can't be read while this machine is offline", slow);
      await expect(page.locator(".canvas-popover")).not.toContainText("AlmaLinux");
      await expect(page.locator(".canvas-popover")).not.toContainText("Intel N100");
      await checkAlignment(page);
      await settle(page);
      await page.screenshot({ path: resolve(OUT, `added-host-offline-${name}-${theme}.png`) });
      await context.close();
    });
  }
}
