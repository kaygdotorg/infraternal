// SPDX-License-Identifier: AGPL-3.0-only
/**
 * A terminal window never waits silently (#305): every refusal the server sends, and a link that stays "connecting", becomes
 * a plain state in the window itself, with the one action that helps. Run on the production build against the test double,
 * which this spec scripts through the page's socket (the double has no remote hosts of its own).
 *
 * Three scenes, each at 1440×900, 393×852 and 375×667 in a dark and a light theme, with a screenshot per state:
 *  - the server's own console is refused for want of a login (`no_login`): the strip says why and offers "Add host", and the
 *    palette lists the remote hosts although no terminal ever painted;
 *  - hosts that refuse (denied, offline) each show their own sentence in their own window;
 *  - a host that never answers says "Can't reach <host>", and its retry brings the window live.
 *
 * Every strip is also measured: its mark, sentence and buttons share one centre line (±0.5 px) and it stays inside its window.
 */
import { mkdir } from "node:fs/promises";
import { resolve } from "node:path";
import { expect, test, type Locator, type Page } from "playwright/test";
import { decodeMuxedFrame, encodeMuxedFrame } from "../../../packages/protocol/src/codec";
import { tracerEvidencePath } from "./evidence-path";

/** The three screens every state is checked on: a desktop, a large phone and a small phone. */
const VIEWPORTS = [
  { name: "1440x900", width: 1440, height: 900, touch: false },
  { name: "393x852", width: 393, height: 852, touch: true },
  { name: "375x667", width: 375, height: 667, touch: true },
] as const;
/** One dark and one light theme. */
const THEMES = ["ink", "paper"] as const;

/** The sentence a refused login shows. */
const ROOTLESS = "This server runs without root, so it can only open shells as its own user. Add a host to work elsewhere.";
/** Remote hosts the scripted server lists, and how each refuses to open a shell. */
const HOSTS = [
  { id: "11111111-1111-4111-8111-111111111111", name: "denied-host", user: "operator", online: true, os: "Debian", refusal: "forbidden" },
  { id: "22222222-2222-4222-8222-222222222222", name: "offline-host", user: "operator", online: false, os: "Debian", refusal: "unavailable" },
  { id: "33333333-3333-4333-8333-333333333333", name: "busy-host", user: "operator", online: true, os: "Debian", refusal: "host_memory_low", counters: { available_mib: 212, session_count: 9 } },
];

/** What the scripted socket does with the server's own `ssh.session.open`: pass it on, refuse it, or never answer. */
type Console = "forward" | "no_login" | "silent";

/** Scripts the page's socket: the host list, a refusal per host, and the chosen behaviour for the server's own console. */
async function script(page: Page, state: { console: Console; listed: number[] }): Promise<void> {
  const reply = (socket: { send(data: Buffer): void }, callId: number, ok: boolean, body: unknown): void => {
    socket.send(Buffer.from(encodeMuxedFrame(0, { type: "Result", callId, ok, json: new TextEncoder().encode(JSON.stringify(body)) })));
  };
  await page.routeWebSocket(/\/v1\/ws(?:\?|$)/, (socket) => {
    const server = socket.connectToServer();
    socket.onMessage((message) => {
      if (typeof message === "string") { server.send(message); return; }
      const { frame } = decodeMuxedFrame(message);
      if (frame.type === "Call" && frame.actionId === "remote.host.list") {
        state.listed.push(Date.now());
        reply(socket, frame.callId, true, { hosts: HOSTS.map(({ refusal: _refusal, counters: _counters, ...host }) => host), next: null });
        return;
      }
      if (frame.type === "Call" && frame.actionId === "ssh.session.open") {
        const { host_id: hostId } = JSON.parse(new TextDecoder().decode(frame.inputJson)) as { host_id?: string };
        const host = HOSTS.find((entry) => entry.id === hostId);
        if (host) { reply(socket, frame.callId, false, { error: "terminal unavailable", reason: host.refusal, ..."counters" in host ? host.counters : {} }); return; }
        if (state.console === "no_login") { reply(socket, frame.callId, false, { error: "terminal unavailable", reason: "no_login" }); return; }
        if (state.console === "silent") return;
      }
      server.send(message);
    });
    server.onMessage((message) => socket.send(message));
  });
}

/** Opens a window on `host` from the palette, as a person does, and returns that window. */
async function openFromPalette(page: Page, host: string): Promise<Locator> {
  const before = await page.locator(".ui-window[data-kind='terminal']").count();
  await page.keyboard.press("Control+Shift+K");
  await page.locator("#palette-input").fill(`Open shell on ${host}`);
  await page.locator("#palette-results [role=option]").filter({ hasText: `Open shell on ${host}` }).first().click();
  await expect(page.locator(".ui-window[data-kind='terminal']")).toHaveCount(before + 1);
  return page.locator(".ui-window[data-kind='terminal']").last();
}

/** The retry arc: "Try again" wears it on every strip, and a plus is only for adding. */
const RETRY_ARC = "M5 12a7 7 0 1 1 2.1 5";

/** The strip's parts share one centre line and the strip stays inside its window (±0.5 px). */
async function expectAligned(win: Locator, strip: Locator): Promise<void> {
  // A window that was just opened is still flying in under the camera: measure once both boxes have stopped moving.
  let last = "";
  await expect.poll(async () => {
    const now = JSON.stringify([await win.boundingBox(), await strip.boundingBox()]);
    const still = now === last;
    last = now;
    return still;
  }, { intervals: [100, 100, 200], timeout: 10_000 }).toBe(true);
  const frame = (await win.boundingBox())!;
  const box = (await strip.boundingBox())!;
  expect(box.x, "the strip starts inside its window").toBeGreaterThanOrEqual(frame.x - 0.5);
  expect(box.x + box.width, "the strip ends inside its window").toBeLessThanOrEqual(frame.x + frame.width + 0.5);
  // Nothing is clipped: every part sits inside the strip, and the sentence shows whole.
  for (const part of await strip.locator(".ui-mark, .cl-sx-strip-text, .cl-sx-again, .cl-sx-dismiss").all()) {
    const b = (await part.boundingBox())!;
    expect(b.x, "a part starts inside the strip").toBeGreaterThanOrEqual(box.x - 0.5);
    expect(b.x + b.width, "a part ends inside the strip").toBeLessThanOrEqual(box.x + box.width + 0.5);
  }
  const text = strip.locator(".cl-sx-strip-text");
  expect(await text.evaluate((node) => node.scrollWidth <= node.clientWidth + 1 && node.scrollHeight <= node.clientHeight + 1), "the sentence is not clipped").toBe(true);
  const textBox = (await text.boundingBox())!;
  const again = strip.locator(".cl-sx-again");
  const stacked = (await again.count()) > 0 && (await again.boundingBox())!.y >= textBox.y + textBox.height - 1;
  if (stacked) {
    // A narrow window: the sentence has most of the strip's width, and the action starts on the sentence's left edge.
    expect(textBox.width, "the sentence gets the strip's width").toBeGreaterThan(box.width * 0.55);
    expect(Math.abs((await again.boundingBox())!.x - textBox.x), "the action starts on the sentence's edge").toBeLessThanOrEqual(0.5);
    const first = textBox.y + (await text.evaluate((node) => Number.parseFloat(getComputedStyle(node).lineHeight))) / 2;
    for (const part of await strip.locator(".ui-mark, .cl-sx-dismiss").all()) {
      const b = (await part.boundingBox())!;
      expect(Math.abs(b.y + b.height / 2 - first), "mark and close sit on the first line's centre").toBeLessThanOrEqual(0.5);
    }
    return;
  }
  const centres: number[] = [];
  for (const part of await strip.locator(".ui-mark, .cl-sx-again, .cl-sx-dismiss").all()) {
    const b = (await part.boundingBox())!;
    centres.push(b.y + b.height / 2);
  }
  expect(centres.length, "mark and the close button at least").toBeGreaterThanOrEqual(2);
  for (const centre of centres) expect(Math.abs(centre - centres[0]!)).toBeLessThanOrEqual(0.5);
}

for (const viewport of VIEWPORTS) {
  for (const theme of THEMES) {
    test.describe(`${viewport.name} ${theme}`, () => {
      test.use({ viewport: { width: viewport.width, height: viewport.height }, deviceScaleFactor: 2, ...(viewport.touch ? { isMobile: true, hasTouch: true } : {}) });
      const shot = async (page: Page, state: string): Promise<void> => {
        const dir = tracerEvidencePath("terminal-states");
        await mkdir(dir, { recursive: true });
        await page.screenshot({ path: resolve(dir, `${state}-${viewport.name}-${theme}.png`), animations: "disabled" });
      };
      const boot = async (page: Page, console: Console): Promise<{ console: Console; listed: number[] }> => {
        await page.request.post("/__mock/reset");
        const state = { console, listed: [] as number[] };
        await script(page, state);
        await page.goto(`/?mock=1&proto=product&fresh=1&bg=none&theme=${theme}`);
        return state;
      };

      test("a refused login is a state with Add host, and the palette still lists the hosts", async ({ page }) => {
        test.setTimeout(90_000);
        const started = Date.now();
        const state = await boot(page, "no_login");
        const win = page.locator(".ui-window[data-kind='terminal']").first();
        const strip = win.locator(".cl-sx-strip");
        await expect(strip.locator(".cl-sx-strip-text")).toHaveText(ROOTLESS, { timeout: 8_000 });
        // The refusal is the window's own state, not a toast that fades while the spinner stays.
        await expect(page.locator(".ui-toast").filter({ hasText: "runs without root" })).toHaveCount(0);
        await expect(strip.getByRole("button", { name: "Add host" })).toBeVisible();
        await expect(strip.getByRole("button", { name: "Try again" })).toHaveCount(0);
        await expectAligned(win, strip);
        await shot(page, "refused-login");
        // The palette learned the hosts although no terminal has painted: the console shows a refusal, not a prompt.
        await expect.poll(() => state.listed.length, { timeout: 8_000 }).toBeGreaterThan(0);
        expect(state.listed[0]! - started, "the list was read before the 10 s 'can't reach' state").toBeLessThan(10_000);
        await page.keyboard.press("Control+Shift+K");
        await page.locator("#palette-input").fill("Open shell on offline-host");
        await expect(page.locator("#palette-results [role=option]").filter({ hasText: "Open shell on offline-host" })).toHaveCount(1);
        await page.keyboard.press("Escape");
        // The strip's action does what it says.
        await strip.getByRole("button", { name: "Add host" }).click();
        await expect(page.getByRole("dialog", { name: "Add hosts" })).toBeVisible();
      });

      test("denied and offline hosts each say what happened in their own window", async ({ page }) => {
        test.setTimeout(90_000);
        await boot(page, "forward");
        await expect(page.locator(".ui-window[data-kind='terminal']").first()).toHaveAttribute("data-status", "live", { timeout: 20_000 });
        const denied = await openFromPalette(page, "denied-host");
        const deniedStrip = denied.locator(".cl-sx-strip");
        await expect(deniedStrip.locator(".cl-sx-strip-text")).toHaveText("You do not have access to denied-host. Ask an admin for access.");
        // Nothing to retry: only closing the window is left.
        await expect(deniedStrip.locator(".cl-sx-again")).toHaveCount(0);
        await expect(deniedStrip.getByRole("button", { name: "Close window" })).toBeVisible();
        await expectAligned(denied, deniedStrip);
        await shot(page, "denied");
        const offline = await openFromPalette(page, "offline-host");
        const offlineStrip = offline.locator(".cl-sx-strip");
        await expect(offlineStrip.locator(".cl-sx-strip-text")).toHaveText("offline-host is offline or cannot reach this server. Check its network, then try again.");
        await expect(offlineStrip.getByRole("button", { name: "Try again" })).toBeVisible();
        expect(await offlineStrip.getByRole("button", { name: "Try again" }).locator("path").first().getAttribute("d"), "one retry icon").toBe(RETRY_ARC);
        await expectAligned(offline, offlineStrip);
        await shot(page, "offline");
        // Neither window spins: both read offline, not connecting.
        await expect(denied).not.toHaveAttribute("data-status", "connecting");
        await expect(offline).not.toHaveAttribute("data-status", "connecting");
      });

      test("a host short of memory keeps a way to its sessions", async ({ page }) => {
        test.setTimeout(90_000);
        await boot(page, "forward");
        await expect(page.locator(".ui-window[data-kind='terminal']").first()).toHaveAttribute("data-status", "live", { timeout: 20_000 });
        const busy = await openFromPalette(page, "busy-host");
        const strip = busy.locator(".cl-sx-strip");
        await expect(strip.locator(".cl-sx-strip-text")).toHaveText("busy-host is low on memory (212 MiB free, 9 sessions running). Close sessions you no longer need.");
        await expectAligned(busy, strip);
        await shot(page, "low-memory");
        // The sentence asks for sessions to be closed, so the one action opens them.
        await strip.getByRole("button", { name: "Sessions" }).click();
        await expect(page.locator(".cl-sx-pop")).toBeVisible();
        await expect(page.locator(".cl-sx-pop")).toContainText("busy-host");
      });

      test("a host that never answers says it cannot be reached, and Try again brings it live", async ({ page }) => {
        test.setTimeout(90_000);
        const state = await boot(page, "silent");
        const win = page.locator(".ui-window[data-kind='terminal']").first();
        const strip = win.locator(".cl-sx-strip");
        // While it waits it is plainly connecting; only after the wait does it say it cannot reach the host.
        await expect(strip).toHaveCount(0);
        await expect(strip.locator(".cl-sx-strip-text")).toHaveText(/^Can't reach .+\. It keeps trying in the background\.$/, { timeout: 25_000 });
        expect(await strip.getByRole("button", { name: "Try again" }).locator("path").first().getAttribute("d"), "one retry icon").toBe(RETRY_ARC);
        await expectAligned(win, strip);
        await shot(page, "cannot-reach");
        // The host starts answering; asking again attaches the window in place.
        state.console = "forward";
        await strip.getByRole("button", { name: "Try again" }).click();
        await expect(strip).toHaveCount(0, { timeout: 10_000 });
        await expect(win).toHaveAttribute("data-status", "live", { timeout: 20_000 });
        await shot(page, "cannot-reach-recovered");
      });
    });
  }
}
