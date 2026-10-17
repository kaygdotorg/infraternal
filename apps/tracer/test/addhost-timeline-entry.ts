/** Diagnostic entry reuses the shipping provisioning client, connection and terminal renderer; no product code imports it (#189). */
import { ProvisioningRun } from "../src/provisioning-client";
import { TerminalClient } from "../src/terminal";
import { MuxConnection } from "../src/connection";
import { WebSocketFrameDecoder } from "../../../packages/protocol/src/codec";
import { Terminal as RendererTerminal } from "../vendor/ghostty-web";

const epoch = (): number => performance.timeOrigin + performance.now();
const records: Array<{ step: string; epoch_ms: number; bytes?: number }> = [];
const mark = (step: string, bytes?: number): void => { records.push({ step, epoch_ms: epoch(), ...(bytes === undefined ? {} : { bytes }) }); };
// Fixed boundary names are safe to retain even if setup or rendering refuses;
// request bodies, terminal contents and exception text never enter this list.
Object.assign(window, { addhostTimelineRecords: () => records });
const rendererOpen = RendererTerminal.prototype.open;
RendererTerminal.prototype.open = function (parent: HTMLElement): void {
  mark("renderer_dom_open_started");
  try { rendererOpen.call(this, parent); } finally { mark("renderer_dom_open_done"); }
};
const OriginalSocket = WebSocket;
/** Observe only public protocol boundaries; capabilities and terminal contents stay in memory. */
class TimingSocket extends OriginalSocket {
  private readonly sent = new WebSocketFrameDecoder();
  constructor(url: string | URL, protocols?: string | string[]) {
    super(url, protocols);
    const decoder = new WebSocketFrameDecoder();
    this.addEventListener("close", (event) => mark(`socket_closed_${event.code}`));
    this.addEventListener("message", (event: MessageEvent<unknown>) => {
      if (!(event.data instanceof ArrayBuffer)) return;
      try { decoder.feed(new Uint8Array(event.data), (stream, frame) => { if (frame.type === "Close") mark(`wire_close_${frame.code}_stream_${stream}`); if (stream === 0 && frame.type === "Pong") mark("wire_received_Pong"); }); } catch { mark("wire_decode_failed"); }
    });
  }
  override send(data: Parameters<WebSocket["send"]>[0]): void {
    const bytes = data instanceof ArrayBuffer ? new Uint8Array(data) : ArrayBuffer.isView(data) ? new Uint8Array(data.buffer, data.byteOffset, data.byteLength) : undefined;
    if (bytes) {
      try { this.sent.feed(bytes, (stream, frame) => { if (frame.type === "Hello" || frame.type === "AttachTerm" || frame.type === "Credit" || (stream === 0 && frame.type === "Ping")) mark(`wire_sent_${frame.type}`); }); } catch { mark("wire_encode_failed"); }
    }
    super.send(data);
  }
  override close(code?: number, reason?: string): void {
    mark(`socket_close_requested_${code ?? 1000}`);
    super.close(code, reason);
  }
}
window.WebSocket = TimingSocket;
const connection = new MuxConnection();
const warm = new Promise<void>((resolve) => connection.openStream({ onSocketOpen() {}, onWelcome() { mark("mux_welcomed"); resolve(); }, onFrame() {}, onDisconnected() {}, hasSession() { return false; }, onStatus() {} }));
Object.assign(window, { addhostTimeline: async (address: string) => {
  await warm;
  const host = document.createElement("div");
  host.style.cssText = "width:900px;height:500px";
  const status = document.createElement("div");
  document.body.append(host, status);
  let terminal: TerminalClient | undefined;
  let output = "";
  let prompted = false;
  let ready = false;
  let sentAfter = false;
  let paintedBefore = false;
  let paintedAfter = false;
  let setup: WebSocket | undefined;
  let wizard: ProvisioningRun;
  let check = (): void => {};
  const traceSeen = new Set<string>();
  const proofSeen = new Set<string>();
  let previousAck = -1n;
  const result = new Promise<typeof records>((resolve, reject) => {
    const timeout = setTimeout(() => { mark("integrity_timeout", Number(terminal?.inputAcknowledged ?? 0n)); reject(new Error("timeline timeout")); }, 120000);
    check = (): void => {
      // Keep byte counters and fixed witness flags on refusal; never retain
      // terminal text. These distinguish a cursor stall from repaint syntax.
      if (terminal && terminal.inputAcknowledged !== previousAck) {
        previousAck = terminal.inputAcknowledged;
        mark("input_acknowledged", Number(previousAck));
      }
      for (const [name, witness] of [["before_marker", "BEFORE_HANDOVER"], ["before_line", "BEFORE_HANDOVER\r\n"], ["after_marker", "AFTER_HANDOVER"], ["after_line", "AFTER_HANDOVER\r\n"]]) {
        if (name && witness && !proofSeen.has(name) && output.includes(witness)) { proofSeen.add(name); mark(name); }
      }
      if (paintedBefore && !proofSeen.has("before_complete_row")) { proofSeen.add("before_complete_row"); mark("before_complete_row"); }
      if (paintedAfter && !proofSeen.has("after_complete_row")) { proofSeen.add("after_complete_row"); mark("after_complete_row"); }
      if (!terminal || !ready || !paintedBefore || terminal.inputAcknowledged < terminal.inputSequence) return;
      if (!sentAfter) { sentAfter = true; terminal.injectInput("printf 'AFTER_%s\\n' HANDOVER\n"); mark("after_command_enqueued", Number(terminal.inputSequence)); }
      if (paintedAfter && terminal.inputAcknowledged === terminal.inputSequence) {
        mark("integrity_confirmed", Number(terminal.inputAcknowledged));
        clearTimeout(timeout);
        setup?.close(); wizard.close(); terminal.dispose(); connection.dispose();
        resolve(records);
      }
    };
    wizard = new ProvisioningRun({ onEvent(event) {
      if (event.step === "failed") { mark("setup_refused"); clearTimeout(timeout); reject(new Error("setup refused")); return; }
      if (event.step !== "done" || !event.session_id || !event.host_id) return;
      mark("publication_received");
      setup = new WebSocket(`${location.origin.replace("https", "wss")}/v1/bootstrap/setup/ws`);
      setup.onopen = () => setup?.send(JSON.stringify({ action: "subscribe", host_id: event.host_id, window_id: "timeline", after: 0 }));
      setup.onmessage = (message) => {
        const value = JSON.parse(String(message.data)) as { setup?: { stage: string; state: string } };
        if (value.setup?.state === "failed") { mark("background_setup_refused"); clearTimeout(timeout); reject(new Error("background setup refused")); }
        if (value.setup?.stage === "ready" && value.setup.state === "done") { ready = true; mark("fully_joined_received"); check(); }
      };
      void TerminalClient.open({ host, status, hostId: event.host_id, attachSessionId: event.session_id, connection, hooks: {
        onTrace(_id, hop, at) {
          const key = `${hop}:${at}`;
          if (!prompted && !traceSeen.has(key)) { traceSeen.add(key); records.push({ step: `terminal_${hop}`, epoch_ms: performance.timeOrigin + at }); }
        },
        onPaintedOutput(bytes, at) {
          output += new TextDecoder().decode(bytes);
          if (!prompted && /[$#] /.test(output)) { prompted = true; records.push({ step: "first_prompt_painted", epoch_ms: performance.timeOrigin + at, bytes: bytes.length }); terminal?.injectInput("printf 'BEFORE_%s\\n' HANDOVER\n"); }
          // A Snapshot is a positioned repaint, not the original PTY byte
          // stream. Require whole rows from the shipped reader after paint;
          // timer polling must not accept parsed-but-unpainted output.
          const rows = terminal?.readScreenText().split("\n") ?? [];
          paintedBefore = rows.includes("BEFORE_HANDOVER");
          paintedAfter = rows.includes("AFTER_HANDOVER");
          check();
        },
      } }).then((value) => { terminal = value; mark("renderer_open"); }).catch(() => { clearTimeout(timeout); reject(new Error("renderer failed")); });
    }, onError() { clearTimeout(timeout); reject(new Error("bootstrap rejected")); } });
    mark("sign_in_click");
    if (new URLSearchParams(location.search).get("prepare") === "1") {
      mark("renderer_prepare_started");
      void TerminalClient.prepare().then(() => mark("renderer_prepare_done"));
    }
    wizard.start([{ id: "live", address: { kind: "manual", value: address }, mode: "rootless" }]);
  });
  // Input acknowledgements can arrive after the output callback.
  const poll = setInterval(() => check(), 20);
  try { return await result; } finally { clearInterval(poll); }
} });
