/** The window pill takes the host's real mark and the shell's real account as soon as they are known, in place, on every open window. */
import { expect, test } from "playwright/test";
import { decodeMuxedFrame, encodeMuxedFrame } from "../../../packages/protocol/src/codec";

const slow = { timeout: 40_000 };
const id = "11111111-2222-3333-4444-555555555555";
const reply = (value: unknown) => new TextEncoder().encode(JSON.stringify(value));

for (const uid of [0, 1000]) {
  test(`pill identity: embedded host facts (uid ${uid}) and a later host list update open windows in place`, async ({ page }, info) => {
    test.setTimeout(90_000);
    await page.request.post("/__mock/reset");
    let list: Record<string, unknown>[] = [];
    let subscription: number | undefined;
    let push: (() => void) | undefined;
    await page.routeWebSocket(/\/v1\/ws(?:\?|$)/, (socket) => {
      const server = socket.connectToServer();
      push = () => { if (subscription !== undefined) socket.send(Buffer.from(encodeMuxedFrame(0, { type: "Event", subId: subscription, eventJson: reply({ type: "changed" }) }))); };
      socket.onMessage((message) => {
        if (typeof message === "string") { server.send(message); return; }
        const { frame } = decodeMuxedFrame(message);
        if (frame.type === "Call" && frame.actionId === "host.facts.read") {
          socket.send(Buffer.from(encodeMuxedFrame(0, { type: "Result", callId: frame.callId, ok: true, json: reply({ os: "NixOS", executionUid: uid }) })));
          return;
        }
        if (frame.type === "Call" && frame.actionId === "remote.host.list") {
          socket.send(Buffer.from(encodeMuxedFrame(0, { type: "Result", callId: frame.callId, ok: true, json: reply({ hosts: list, next: null }) })));
          return;
        }
        if (frame.type === "Subscribe" && JSON.parse(new TextDecoder().decode(frame.filterJson)).topic === "remote.hosts") { subscription = frame.subId; return; }
        if (frame.type === "Call" && frame.actionId === "ssh.session.open") {
          const input = JSON.parse(new TextDecoder().decode(frame.inputJson)) as { host_id?: string };
          if (input.host_id === id) { socket.send(Buffer.from(encodeMuxedFrame(0, { type: "Result", callId: frame.callId, ok: false, json: reply({ error: "unavailable" }) }))); return; }
        }
        server.send(message);
      });
      server.onMessage((message) => socket.send(message));
    });
    list = [{ id, name: "minipc01", user: "root", online: true }];
    await page.goto("/?mock=1&proto=product&fresh=1&bg=none");
    const pill = page.locator(".ui-window").first().locator(".ui-window-pill");
    // The embedded window: the system's own mark (not the machine glyph) and only a true account.
    const mark = pill.locator(".ui-window-mark svg");
    await expect(pill.locator(".ui-window-host")).toHaveText(/\S/, slow);
    if (uid === 0) await expect(pill.locator(".ui-window-user")).toHaveText("root@", slow);
    else await expect(pill.locator(".ui-window-user")).toHaveText("", slow);
    await expect.poll(() => mark.evaluate((n) => n.outerHTML), slow).not.toContain("M4 5.5A2.5 2.5 0 0 1 6.5 3h11");
    await page.screenshot({ path: info.outputPath(`embedded-uid${uid}.png`), animations: "disabled" });
    // A remote host's window opened before its system is known switches in place when the list says it.
    await page.keyboard.press("Control+Shift+K");
    await page.locator("#palette-input").fill("Open shell on minipc01");
    await page.locator("#palette-results [role=option]").filter({ hasText: "Open shell on minipc01" }).click();
    const remote = page.locator(".ui-window").filter({ has: page.locator(".ui-window-host", { hasText: "minipc01" }) }).first().locator(".ui-window-pill");
    await expect(remote.locator(".ui-window-user")).toHaveText("root@", slow);
    const before = await remote.locator(".ui-window-mark svg").evaluate((n) => n.innerHTML);
    list = [{ id, name: "minipc01", user: "root", os: "Debian GNU/Linux", online: true }];
    push?.();
    await expect.poll(() => remote.locator(".ui-window-mark svg").evaluate((n) => n.innerHTML), slow).not.toBe(before);
    await page.screenshot({ path: info.outputPath(`remote-uid${uid}.png`), animations: "disabled" });
  });
}
