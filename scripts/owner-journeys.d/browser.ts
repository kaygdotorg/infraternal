// SPDX-License-Identifier: AGPL-3.0-only
/** Browser actions and passive terminal receipts from the deployed test instance. */
import type { ElementHandle, Page } from "../../apps/tracer/node_modules/playwright";
import { WebSocketFrameDecoder } from "../../packages/protocol/src/codec";

/** The only public origin these owner journeys open. */
export const origin = "https://test.ssh.kayg.org";

/** Opens the same command palette used by the owner and filters its shipped rows. */
export async function palette(page: Page, query: string) {
  const input = page.locator("#palette-input");
  if (!await input.isVisible()) await page.keyboard.press("Control+Shift+K");
  await input.fill(query);
  return page.locator("#palette-results [role=option]");
}

/** Waits on a condition with a deadline and gives the caller's exact step on timeout. */
export async function until<T>(read: () => T | Promise<T>, message: string, timeout = 20_000): Promise<NonNullable<T>> {
  const deadline = Date.now() + timeout;
  do {
    const value = await read();
    if (value) return value;
    // Recheck because CLI pipes and protocol frames have no shared ordering with locator events.
    // sleep: these are bounded readiness polls, not an assumed UI delay.
    await Bun.sleep(100);
  } while (Date.now() < deadline);
  throw new Error(message);
}

/** Bounded wire observations for the current fresh terminal, without retaining unrelated shell traffic. */
function observeShell(page: Page) {
  const receipt = { id: "", input: "", open: "", ended: false };
  let tail = "";
  let armed = false;
  page.on("websocket", (socket) => {
    const address = new URL(socket.url());
    if (address.origin !== origin.replace("https:", "wss:") || address.pathname !== "/v1/ws") return;
    const sent = new WebSocketFrameDecoder(), received = new WebSocketFrameDecoder();
    let activeCall: number | undefined;
    let activeStream: number | undefined;
    socket.on("framesent", ({ payload }) => {
      if (!armed || typeof payload === "string") return;
      sent.feed(payload, (stream, frame) => {
        if (frame.type === "Call" && frame.actionId === "ssh.session.open" && activeCall === undefined) activeCall = frame.callId;
        if (frame.type === "AttachTerm" && Buffer.from(frame.sessionId).toString("hex") === receipt.id.replaceAll("-", "")) activeStream = stream;
        if (frame.type === "Input" && frame.replyTo === undefined && stream === activeStream) {
          receipt.input = (receipt.input + Buffer.from(frame.bytes).toString("hex")).slice(-4096);
        }
      });
    });
    socket.on("framereceived", ({ payload }) => {
      if (!armed || typeof payload === "string") return;
      received.feed(payload, (stream, frame) => {
        if (frame.type === "Result" && frame.callId === activeCall) {
          const value = JSON.parse(new TextDecoder().decode(frame.json));
          receipt.open = frame.ok ? "shell allocated" : "server refused the shell";
          if (frame.ok && typeof value.session_id === "string") receipt.id = value.session_id;
        }
        if (stream !== activeStream) return;
        if (frame.type === "Event" && frame.subId === 0) {
          const notice = JSON.parse(new TextDecoder().decode(frame.eventJson));
          if (notice.type === "terminal.exited" && notice.session_id === receipt.id) receipt.ended = true;
        }
        if (frame.type === "Output") {
          // Hold a short private tail for split probe receipts. No shell output is written to the transcript.
          tail = (tail + new TextDecoder().decode(frame.bytes)).slice(-4096);
        }
      });
    });
  });
  return {
    receipt,
    /** Start observing immediately before the owner clicks their chosen shell. */
    arm() { armed = true; },
    /** Look up a run-generated receipt in the fresh shell's output. */
    hasOutput(value: string) { return tail.includes(value); },
    /** Returns only the hex field from the PTY probe's own receipt. */
    capturedBytes(id: string) { return tail.match(new RegExp(`owner-bytes-${id}:([0-9a-f]{0,32})[.]`))?.[1]; },
  };
}

/** Opens a fresh shell through the palette and observes its server allocation. */
export async function openShell(page: Page, name?: string) {
  const observed = observeShell(page);
  // Observe the socket from its start. Existing restored sessions are left alone.
  await page.reload();
  const rows = await palette(page, name ? `Open shell on ${name}` : "Open shell");
  const row = name
    ? rows.filter({ has: page.getByText(`Open shell on ${name}`, { exact: true }) })
    : page.locator('#palette-results [data-action="canvas:open:embedded"]');
  await row.waitFor({ timeout: 20_000 });
  const cards = page.locator(".ui-window[data-kind=terminal][data-window-id]");
  const previous = new Set(await cards.evaluateAll((elements) => elements.map((element) => element.getAttribute("data-window-id"))));
  observed.arm();
  await row.click({ timeout: 20_000 });
  const receipt = observed.receipt;
  await until(() => receipt.open, "The server did not answer the fresh-shell request");
  if (!receipt.id) {
    const message = page.locator(".ui-window[data-active] .cl-sx-strip[data-result=refused] .cl-sx-strip-text");
    const text = await message.innerText({ timeout: 4_000 }).catch(() => receipt.open);
    throw new Error(text);
  }
  return { observed, receipt, previous };
}

/** Sends a command through the fresh shell's own input and waits for its output. */
export async function proveShell(page: Page, shell: Awaited<ReturnType<typeof openShell>>, input: ElementHandle) {
  await input.focus();
  const marker = `owner-journey-${crypto.randomUUID()}`;
  // Splitting the marker stops the shell's command echo from satisfying the output assertion.
  await page.keyboard.insertText(`printf '%s%s\\n' owner-journey- ${marker.slice("owner-journey-".length)}`);
  await page.keyboard.press("Enter");
  await until(() => shell.observed.hasOutput(marker), "The fresh shell never printed the probe marker");
  return "Fresh shell executed the probe and returned its marker";
}

/** Checks the actual bytes generated by each owner keystroke for the fresh shell's stream. */
export async function checkKeys(page: Page, shell: Awaited<ReturnType<typeof openShell>>, input: ElementHandle) {
  await input.focus();
  const id = crypto.randomUUID().slice(0, 8);
  // A temporary raw PTY read sees Ctrl+C and Ctrl+R as bytes. A VTIME deadline and restoration trap
  // return the fixture shell to its original mode even if a tested key never arrives.
  const command = `saved=$(stty -g) && trap 'stty "$saved"' EXIT && stty -icanon -echo -isig min 0 time 50 && printf '%s%s\\n' owner-ready- ${id} && bytes=$(dd bs=1 count=16 2>/dev/null | od -An -v -tx1 | tr -d '[:space:]') && printf '%s%s:%s.\\n' owner-bytes- ${id} "$bytes"`;
  await page.keyboard.insertText("sh -c '" + command.replaceAll("'", "'\\''") + "'");
  await page.keyboard.press("Enter");
  await until(() => shell.observed.hasOutput("owner-ready-" + id), "The PTY byte reader did not become ready");
  const { receipt } = shell;
  const keys = [
    ["Control+a", /^01$/], ["Control+c", /^03$/], ["Control+d", /^04$/],
    ["ArrowUp", /^1b(?:5b|4f)41$/], ["ArrowDown", /^1b(?:5b|4f)42$/],
    ["ArrowRight", /^1b(?:5b|4f)43$/], ["ArrowLeft", /^1b(?:5b|4f)44$/],
    ["Control+r", /^12$/],
  ] as const;
  const seen = [];
  let wire = "";
  for (const [key, expected] of keys) {
    receipt.input = "";
    await page.keyboard.press(key);
    const bytes = await until(() => receipt.input, `${key} emitted no terminal input`, 3_000);
    if (!expected.test(bytes)) throw new Error(`${key} emitted 0x${bytes} (expected ${expected})`);
    seen.push(`${key}=0x${bytes}`);
    wire += bytes;
  }
  const pty = await until(() => {
    const found = shell.observed.capturedBytes(id);
    return found === undefined ? undefined : { found };
  }, "The PTY did not report the received bytes");
  if (pty.found !== wire) throw new Error(`PTY received 0x${pty.found}; browser sent 0x${wire}`);
  return `${seen.join(" ")} (PTY confirmed 0x${wire})`;
}

/** Interrupts a foreground sleep and proves the same shell accepts another command immediately. */
export async function checkInterrupt(page: Page, shell: Awaited<ReturnType<typeof openShell>>, input: ElementHandle) {
  await input.focus();
  const id = crypto.randomUUID().slice(0, 8);
  await page.keyboard.insertText(`sh -c 'printf "%s%s\\n" owner-sleep- ${id}; exec sleep 30'`);
  await page.keyboard.press("Enter");
  await until(() => shell.observed.hasOutput("owner-sleep-" + id), "The foreground sleep did not start");
  const started = Date.now();
  await page.keyboard.press("Control+c");
  const marker = "owner-interrupted-" + id;
  // Split the marker so the echoed command cannot count as a resumed prompt.
  await page.keyboard.insertText(`printf '%s%s\\n' owner-interrupted- ${id}`);
  await page.keyboard.press("Enter");
  await until(() => shell.observed.hasOutput(marker), "Ctrl+C did not return control from sleep", 5_000);
  return `Ctrl+C interrupted sleep 30 and the shell answered in ${Date.now() - started} ms`;
}

/** Cancels once, then ends exactly the session this run opened, using its sidebar row. */
export async function endShell(page: Page, id: string) {
  if (!/^[0-9a-f-]{36}$/.test(id)) throw new Error("Shell did not return a session UUID");
  const toggle = page.locator("#sidebar-toggle");
  const tree = page.locator('#tree[data-rows="ready"]');
  if (!await tree.isVisible()) await toggle.click();
  const row = tree.locator(`[data-id^="s:"][data-id$="/${id}"]`);
  /** Opens the exact session's sidebar menu and waits for its inline confirmation. */
  async function ask() {
    await row.focus();
    await page.keyboard.press("ContextMenu");
    const options = page.locator(".ui-window-menu-item:visible");
    await options.first().waitFor();
    const end = options.filter({ hasText: "End session" });
    if (!await end.isVisible()) {
      const labels = (await options.allTextContents()).map((label) => label.trim()).join(", ");
      throw new Error(`Sidebar offered ${labels}; End session was missing`);
    }
    await end.click();
    return page.locator(".ui-row-ask");
  }
  const first = await ask();
  await first.getByRole("button", { name: "Cancel", exact: true }).click();
  const second = await ask();
  await second.getByRole("button", { name: "End", exact: true }).click();
  await until(async () => !await row.isVisible() || /exited|ended/i.test(await row.innerText()),
    "The sidebar still shows the session running after End");
  return "Cancelled once, then ended the fresh session from the sidebar";
}
