/** Measures confirmed remote PTY output through the shipping browser protocol, with no synthetic CPU or output load. */
import { WebSocket } from "../../apps/tracer/node_modules/ws/index.js";
import { WebSocketFrameDecoder, encodeMuxedFrame, type WireFrame } from "../../packages/protocol/src/codec";
import { randomBytes } from "node:crypto";
export async function remoteEcho(origin: string, cookie: string, session: string) {
  const endpoint = new URL(origin.replace("https:", "wss:") + "/v1/ws");
  endpoint.hostname = "10.69.69.125";
  const ws = new WebSocket(endpoint, { headers: { Origin: origin, Cookie: cookie }, rejectUnauthorized: false });
  const decoder = new WebSocketFrameDecoder();
  let ready: () => void;
  let out = "";
  let ack = 0n;
  let failed = false;
  let phase = "attach";
  let welcomed = false;
  let observed = 0;
  const welcome = new Promise<void>((resolve) => { ready = resolve; });
  const send = (stream: number, frame: Parameters<typeof encodeMuxedFrame>[1]) => ws.send(encodeMuxedFrame(stream, frame));
  ws.on("error", () => { failed = true; });
  ws.on("message", (data) => decoder.feed(new Uint8Array(Buffer.from(data as Buffer)), (stream: number, frame: WireFrame) => {
    if (frame.type === "Ping") send(0, { type: "Pong", nonce: frame.nonce, sentUs: frame.sentUs });
    if (frame.type === "Hello") send(0, { type: "Hello", version: 1, caps: 0n, clientInfo: "release-remote-echo" });
    if (frame.type === "Welcome") {
      welcomed = true;
      send(1, { type: "AttachTerm", sessionId: Buffer.from(session, "hex"), lastOutSeq: 0n, lastInSeq: 0n });
      send(1, { type: "Credit", bytes: 1048576 });
    }
    if (stream !== 1) return;
    if (frame.type === "Ack") { ack = frame.inSeqAcked; ready(); }
    if (frame.type === "Snapshot") out = new TextDecoder().decode(frame.bytes);
    if (frame.type === "Output") out += new TextDecoder().decode(frame.bytes);
  }));
  const until = async (condition: () => boolean) => {
    const deadline = performance.now() + 10000;
    while (!condition()) {
      if (failed || performance.now() > deadline) throw new Error("confirmed remote echo unavailable");
      await new Promise((resolve) => setTimeout(resolve, 1));
    }
  };
  let entered = 0n;
  const input = (text: string) => {
    const bytes = Buffer.from(text);
    send(1, { type: "Input", inSeq: entered, bytes });
    entered += BigInt(bytes.length);
  };
  try {
    await Promise.race([welcome, new Promise((_, reject) => setTimeout(() => reject(new Error("remote attachment unavailable")), 10000))]);
    phase = "prepare";
    const marker = `echo-ready-${randomBytes(6).toString("hex")}`;
    input(`stty raw -echo; printf '%s%s' '${marker.slice(0, 10)}' '${marker.slice(10)}'; cat\n`);
    await until(() => out.includes(marker) && ack >= entered);
    const samples: number[] = [];
    phase = "samples";
    const count = Number(process.env.ECHO_SAMPLES ?? 1000);
    if (!Number.isInteger(count) || count < 20 || count > 1000) throw new Error("invalid echo sample count");
    for (let i = 0; i < count; i++) {
      observed = i;
      const before = out.length;
      const glyph = String.fromCharCode(65 + i % 26);
      const start = performance.now();
      input(glyph);
      await until(() => out.slice(before).includes(glyph) && ack >= entered);
      samples.push(performance.now() - start);
    }
    samples.sort((a, b) => a - b);
    return { n: samples.length, p50_ms: samples[Math.ceil(samples.length * .5) - 1], p99_ms: samples[Math.ceil(samples.length * .99) - 1], max_ms: samples.at(-1) };
  } catch {
    console.log(JSON.stringify({ remote_echo_probe: "failed", phase, welcomed, ack: Number(ack), output_bytes: out.length, samples: observed, transport_failed: failed, socket_state: ws.readyState }));
    throw new Error("confirmed remote echo unavailable");
  } finally { ws.terminate(); }
}

/** One real node action, with the browser's exact Origin and ephemeral cookie kept in memory. */
export async function nodeCall(origin: string, cookie: string, input: unknown, actionId = "host.facts.read"): Promise<{ok: boolean; json: Record<string, unknown>}> {
  const endpoint = new URL(origin.replace("https:", "wss:") + "/v1/ws");
  endpoint.hostname = "10.69.69.125";
  const ws = new WebSocket(endpoint, { headers: { Origin: origin, Cookie: cookie }, rejectUnauthorized: false });
  const decoder = new WebSocketFrameDecoder();
  try {
    return await new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error("node action deadline")), 10000);
      const fail = () => { clearTimeout(timer); reject(new Error("node action unavailable")); };
      ws.on("error", fail);
      ws.on("close", fail);
      ws.on("message", data => decoder.feed(new Uint8Array(Buffer.from(data as Buffer)), (_stream, frame) => {
        if (frame.type === "Ping") ws.send(encodeMuxedFrame(0, { type: "Pong", nonce: frame.nonce, sentUs: frame.sentUs }));
        if (frame.type === "Hello") ws.send(encodeMuxedFrame(0, { type: "Hello", version: 1, caps: 0n, clientInfo: "release-node-selection" }));
        if (frame.type === "Welcome") ws.send(encodeMuxedFrame(0, { type: "Call", callId: 37, actionId, inputJson: new TextEncoder().encode(JSON.stringify(input)) }));
        if (frame.type === "Result" && frame.callId === 37) {
          clearTimeout(timer);
          resolve({ ok: frame.ok, json: JSON.parse(new TextDecoder().decode(frame.json)) as Record<string, unknown> });
        }
      }));
    });
  } finally { ws.terminate(); }
}
