/**
 * J1078 experiment (not product code): after a main-thread stall, do the decode worker's credit
 * returns interleave with the queued socket messages? Mirrors the handoff credit of
 * apps/tracer/src/canvas/appwin/stream.ts (MAX_HANDOFF_UNITS = 4) with a real WebSocket and Worker.
 */

/** Node's HTTP server and hashing (for the WebSocket handshake). */
const http = require("http"), crypto = require("crypto");
/** The test page: a socket, a decode worker with the product's credit, and timed stalls. */
const PAGE = `<!doctype html><script>
const MAX = 4; let credit = 0, seq = 0, overflow = 0, log = [], phase = "run", results = [];
const worker = new Worker("/worker.js");
worker.onmessage = () => { credit--; if (log.length < 40 && phase !== "run") log.push("admitted"); };
const ws = new WebSocket("ws://" + location.host + "/ws"); ws.binaryType = "arraybuffer";
ws.onmessage = (e) => {
  seq++;
  if (log.length < 40 && phase !== "run") log.push("socket");
  if (credit >= MAX) { overflow++; return; }
  credit++; const copy = e.data.slice(0); worker.postMessage(copy, [copy]);
};
function block(ms) { const end = performance.now() + ms; while (performance.now() < end) {} }
async function stall(ms) {
  await new Promise((r) => setTimeout(r, 700));
  const before = overflow; log = []; phase = "stall"; block(ms);
  await new Promise((r) => setTimeout(r, 300));
  results.push({ stall_ms: ms, frames_refused: overflow - before, first_events: log.join(",") }); phase = "run";
}
ws.onopen = async () => {
  await new Promise((r) => setTimeout(r, 500));
  const quiet = overflow;
  for (const ms of [20, 40, 80, 160]) await stall(ms);
  await fetch("/done", { method: "POST", body: JSON.stringify({ ua: navigator.userAgent, interval_ms: INTERVAL, frames: seq, refused_before_any_stall: quiet, results }) });
};
</script>`;
/** Milliseconds between frames the server sends (argv[2], default 8). */
const interval = Number(process.argv[2] || 8);
/** Serves the page and speaks a minimal WebSocket that streams numbered frames. */
const server = http.createServer((req, res) => {
  if (req.url === "/worker.js") { res.setHeader("content-type", "text/javascript"); res.end("onmessage = (e) => postMessage(e.data.byteLength);"); return; }
  if (req.url === "/done") { let body = ""; req.on("data", (c) => body += c); req.on("end", () => { console.log("RESULT " + body); res.end("ok"); setTimeout(() => process.exit(0), 100); }); return; }
  res.setHeader("content-type", "text/html"); res.end(PAGE.replace("INTERVAL", String(interval)));
});
server.on("upgrade", (req, socket) => {
  const accept = crypto.createHash("sha1").update(req.headers["sec-websocket-key"] + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").digest("base64");
  socket.write("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: " + accept + "\r\n\r\n");
  socket.setNoDelay(true);
  const payload = Buffer.alloc(600, 7), header = Buffer.from([0x82, 126, payload.length >> 8, payload.length & 255]);
  const timer = setInterval(() => { if (socket.writable) socket.write(Buffer.concat([header, payload])); }, interval);
  socket.on("close", () => clearInterval(timer)); socket.on("error", () => clearInterval(timer));
});
server.listen(0, "127.0.0.1", () => console.log("PORT " + server.address().port));
setTimeout(() => { console.log("TIMEOUT"); process.exit(2); }, 30000);
