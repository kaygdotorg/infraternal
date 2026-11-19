/**
 * Bracketed paste survives a reconnect that repaints the screen (#524).
 *
 * A repaint begins with RIS, which turns every mode off in the browser's terminal. The shim's approximate painter
 * (the one a plain shell always gets) used to restore none of the program's input modes, so after a reconnect the
 * browser sent a pasted multi-line command as plain keystrokes: the shell ran it line by line while the program on
 * the host still had bracketed paste on. This spec drives the real server, shim and a production tracer build:
 * a command in a real session turns bracketed paste on and floods more output than the shim's 8 MiB replay ring
 * while no tab is attached, so the reopened tab gets a host repaint, not a raw replay. Then it pastes two lines and
 * reads, from the browser's own WebSocket frames, whether the paste went out wrapped in the bracketed-paste markers.
 * The browser's terminal adds those markers only when its own engine has mode 2004 on, so the frame is the oracle.
 */
import { expect, test, type Page } from "playwright/test";
import { existsSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { WebSocketFrameDecoder } from "../../../packages/protocol/src/codec";
import { enrol } from "./layout-devices";
import { watchLayout } from "./layout-observer";
import { startRealServer } from "./server";
import { tracerEvidencePath } from "../test/evidence-path";

/** What one terminal WebSocket carried: repaints, the replay fence, and the input bytes sent after `mark`. */
interface Connection {
  snapshots: number;
  approximate: number;
  fenced: boolean;
  /** Input bytes sent since the spec set `recording`, as Latin-1 text so escape bytes stay visible. */
  input: string;
  recording: boolean;
}

/** Records repaint, fence and input frames on every terminal socket of `page`. Never records terminal output. */
function observe(page: Page): Connection[] {
  const connections: Connection[] = [];
  page.on("websocket", (socket) => {
    if (!socket.url().endsWith("/v1/ws")) return;
    const connection: Connection = { snapshots: 0, approximate: 0, fenced: false, input: "", recording: false };
    connections.push(connection);
    const up = new WebSocketFrameDecoder(), down = new WebSocketFrameDecoder();
    socket.on("framesent", ({ payload }) => {
      if (typeof payload === "string") return;
      up.feed(new Uint8Array(payload), (_stream, frame) => {
        // Query replies are the terminal's answers, not typing; only user input is the paste under test.
        if (frame.type === "Input" && frame.replyTo === undefined && connection.recording) {
          connection.input += String.fromCharCode(...frame.bytes);
        }
      });
    });
    socket.on("framereceived", ({ payload }) => {
      if (typeof payload === "string") return;
      down.feed(new Uint8Array(payload), (_stream, frame) => {
        if (frame.type === "Snapshot") connection.snapshots++;
        if (frame.type !== "Event") return;
        const notice = JSON.parse(new TextDecoder().decode(frame.eventJson));
        if (notice.type === "terminal.replay_complete") connection.fenced = true;
        if (notice.type === "terminal.snapshot" && notice.approximate === true) connection.approximate++;
      });
    });
  });
  return connections;
}

/** Pastes `text` into the terminal the way a browser paste does: a `paste` event carrying clipboard data. */
async function paste(page: Page, text: string): Promise<void> {
  await page.locator('.cl[data-view="console"] .terminal-host textarea').evaluate((input, value) => {
    const data = new DataTransfer();
    data.setData("text/plain", value);
    input.dispatchEvent(new ClipboardEvent("paste", { clipboardData: data, bubbles: true, cancelable: true }));
  }, text);
}

test("a pasted multi-line command stays one bracketed paste after a reconnect repaint", async ({ browser }) => {
  test.setTimeout(180_000);
  const scratch = mkdtempSync(join(tmpdir(), "j766-"));
  const done = join(scratch, "flooded");
  const server = await startRealServer({ port: Number(process.env.TRACER_TEST_PORT ?? 4857) });
  const context = await browser.newContext({ viewport: { width: 1440, height: 852 }, ignoreHTTPSErrors: true });
  // enrol() waits for the layout to settle, which it reads from the observer; it must watch before the first page.
  const page = watchLayout(await context.newPage());
  const connections = observe(page);
  try {
    await enrol(page, server);
    const host = page.locator('.cl[data-view="console"] .terminal-host');
    await expect(host.locator("textarea")).toHaveCount(1);
    await host.click();
    await host.locator("textarea").focus();
    // The program, not the shell's line editor, owns the mode here: `cat` holds the terminal with 2004 on, so the
    // shell cannot switch it off or on around the paste. The flood waits until the tab has gone, so it lands only in
    // the shim's ring (10 MB > the 8 MiB ring) and the reopened tab must be repainted.
    await page.keyboard.type(`sleep 2; head -c 10000000 /dev/zero | tr '\\0' y; printf '\\033[?2004h\\033[2J\\033[Hj766 bracketed paste on\\n'; touch ${done}; cat >/dev/null`);
    await page.keyboard.press("Enter");
    const url = page.url();
    await page.goto("about:blank");
    await expect.poll(() => existsSync(done), { timeout: 90_000 }).toBe(true);
    const before = connections.length;
    await page.goto(url);
    await expect(host.locator("textarea")).toHaveCount(1);
    await expect.poll(() => connections.length).toBeGreaterThan(before);
    const current = connections.at(-1)!;
    await expect.poll(() => current.fenced, { timeout: 60_000 }).toBe(true);
    // The reopened tab was repainted from the host's engine, not replayed: this is the path under test.
    expect(current.snapshots).toBeGreaterThan(0);
    expect(current.approximate, "the reconnect must exercise the approximate painter").toBeGreaterThan(0);
    await page.screenshot({ path: tracerEvidencePath("j766-reopened-after-flood.png") });
    await host.click();
    await host.locator("textarea").focus();
    current.recording = true;
    await paste(page, "echo j766-one\necho j766-two");
    await expect.poll(() => current.input.length).toBeGreaterThan(0);
    // sleep: let the rest of a split paste reach the socket before its bytes are judged.
    await page.waitForTimeout(500);
    console.log("J766_PASTE_RECEIPT", JSON.stringify({ snapshots: current.snapshots, approximate: current.approximate, input: current.input }));
    await page.screenshot({ path: tracerEvidencePath("j766-after-paste.png") });
    expect(current.input.startsWith("\x1b[200~"), "the paste is sent as one bracketed paste").toBe(true);
    expect(current.input.endsWith("\x1b[201~")).toBe(true);
  } finally {
    await context.close();
    await server.dispose();
    rmSync(scratch, { recursive: true, force: true });
  }
});
