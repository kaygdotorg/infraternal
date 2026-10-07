/**
 * Generate a deterministic H.264 clip and measure browser WebCodecs decode plus
 * 2D canvas upload at one and four concurrent desktop-sized decoder instances.
 * The requested software preference does not prove which decoder Chromium chose.
 * This is a host-side reference measurement, not a phone benchmark.
 */

import { spawn, spawnSync } from 'node:child_process';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { loadavg, tmpdir } from 'node:os';
import { join } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { createServer } from 'node:http';

const width = 1280;
const height = 720;
const fps = 30;
const durationSeconds = 6;
const maxQueue = 4;
const startedAt = new Date().toISOString();
const loadAverageAtStart = loadavg();
const tempDir = await mkdtemp(join(tmpdir(), 'vnc-webcodecs-'));
const clipPath = join(tempDir, 'clip.h264');
const chromePath = process.env.CHROMIUM ?? '/home/kayg/.cache/ms-playwright/chromium-1243/chrome-linux64/chrome';

function run(program, args) {
  const result = spawnSync(program, args, { encoding: 'utf8' });
  if (result.status !== 0) {
    throw new Error(`${program} failed (${result.status}): ${result.stderr || result.error}`);
  }
  return result.stdout.trim();
}

function html() {
  return `<!doctype html>
<meta charset="utf-8">
<title>VNC WebCodecs decode benchmark</title>
<pre id="result">running</pre>
<script>
const out = document.querySelector('#result');
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
function nalUnits(bytes) {
  const starts = [];
  for (let i = 0; i + 3 < bytes.length;) {
    if (bytes[i] === 0 && bytes[i + 1] === 0 && bytes[i + 2] === 1) {
      starts.push([i, i + 3]); i += 3;
    } else if (i + 4 < bytes.length && bytes[i] === 0 && bytes[i + 1] === 0 && bytes[i + 2] === 0 && bytes[i + 3] === 1) {
      starts.push([i, i + 4]); i += 4;
    } else i++;
  }
  return starts.map(([start, data], i) => ({ start, data, end: starts[i + 1]?.[0] ?? bytes.length,
    type: bytes[data] & 31 }));
}
function accessUnits(bytes) {
  const units = nalUnits(bytes);
  const result = [];
  let current = null;
  for (const unit of units) {
    if (unit.type === 9) {
      if (current) result.push(current);
      current = { start: unit.start, end: unit.end, key: false };
    } else if (current) {
      current.end = unit.end;
      if (unit.type === 5) current.key = true;
    }
  }
  if (current) result.push(current);
  return result.map((au, i) => ({
    bytes: bytes.slice(au.start, au.end), key: au.key,
    timestamp: Math.round(i * 1000000 / ${fps}),
  }));
}
async function runCase(units, decoderCount) {
  const latencies = [];
  let outputCount = 0;
  const started = performance.now();
  const decoders = Array.from({ length: decoderCount }, (_, index) => {
    const canvas = new OffscreenCanvas(${width}, ${height});
    const context = canvas.getContext('2d', { alpha: false, desynchronized: true });
    const pending = new Map();
    const decoder = new VideoDecoder({
      output(frame) {
        const submitted = pending.get(frame.timestamp);
        if (submitted !== undefined) latencies.push(performance.now() - submitted);
        context.drawImage(frame, 0, 0, ${width}, ${height});
        frame.close();
        pending.delete(frame.timestamp);
        outputCount++;
      },
      error(error) { throw error; },
    });
    decoder.configure({
      codec: 'avc1.42E01E', codedWidth: ${width}, codedHeight: ${height},
      optimizeForLatency: true, hardwareAcceleration: 'prefer-software',
      avc: { format: 'annexb' },
    });
    return { decoder, pending, index };
  });
  for (const unit of units) {
    for (const item of decoders) {
      while (item.decoder.decodeQueueSize >= ${maxQueue}) await sleep(1);
      item.pending.set(unit.timestamp, performance.now());
      item.decoder.decode(new EncodedVideoChunk({
        type: unit.key ? 'key' : 'delta', timestamp: unit.timestamp, data: unit.bytes,
      }));
    }
  }
  await Promise.all(decoders.map(({ decoder }) => decoder.flush()));
  const elapsedMs = performance.now() - started;
  for (const { decoder } of decoders) decoder.close();
  latencies.sort((a, b) => a - b);
  const percentile = p => latencies[Math.min(latencies.length - 1, Math.floor((latencies.length - 1) * p))];
  return {
    decoders: decoderCount,
    outputFrames: outputCount,
    wallMs: Number(elapsedMs.toFixed(2)),
    aggregateFps: Number((outputCount * 1000 / elapsedMs).toFixed(2)),
    outputLatencyMs: {
      p50: Number(percentile(0.50).toFixed(2)),
      p95: Number(percentile(0.95).toFixed(2)),
      max: Number(latencies.at(-1).toFixed(2)),
    },
    perPaneRgbaMiB: Number((${width} * ${height} * 4 / 1048576).toFixed(2)),
    totalCanvasRgbaMiB: Number((${width} * ${height} * 4 * decoderCount / 1048576).toFixed(2)),
  };
}
(async () => {
  try {
    if (!('VideoDecoder' in globalThis) || !('EncodedVideoChunk' in globalThis))
      throw new Error('WebCodecs VideoDecoder is unavailable');
    const bytes = new Uint8Array(await (await fetch('/clip.h264')).arrayBuffer());
    const units = accessUnits(bytes);
    if (!units.length) throw new Error('No H.264 access units found; ffmpeg AUD output changed');
    const config = await VideoDecoder.isConfigSupported({
      codec: 'avc1.42E01E', codedWidth: ${width}, codedHeight: ${height},
      optimizeForLatency: true, hardwareAcceleration: 'prefer-software', avc: { format: 'annexb' },
    });
    if (!config.supported) throw new Error('Baseline H.264 Annex-B configuration unsupported');
    await runCase(units.slice(0, 30), 1);
    const cases = [];
    for (const count of [4, 1]) cases.push(await runCase(units, count));
    out.textContent = JSON.stringify({
      userAgent: navigator.userAgent,
      codec: 'H.264 Baseline, Annex B, software preferred',
      width: ${width}, height: ${height}, sourceFps: ${fps}, accessUnits: units.length,
      sourceBytes: bytes.byteLength,
      sourceBitrateKbps: Math.round(bytes.byteLength * 8 / ${durationSeconds} / 1000),
      sourceBytesPerPaneSecond: Math.round(bytes.byteLength / ${durationSeconds}),
      cases,
    });
  } catch (error) {
    out.textContent = JSON.stringify({ error: String(error), stack: error?.stack });
  }
})();
</script>`;
}

const sourceStream = run('ffmpeg', [
  '-hide_banner', '-loglevel', 'error', '-f', 'lavfi', '-i',
  `testsrc2=size=${width}x${height}:rate=${fps}`, '-t', String(durationSeconds), '-an',
  '-c:v', 'libx264', '-preset', 'ultrafast', '-tune', 'zerolatency', '-profile:v', 'baseline',
  '-pix_fmt', 'yuv420p', '-g', String(fps), '-keyint_min', String(fps), '-sc_threshold', '0',
  '-x264-params', 'aud=1:repeat-headers=1:bframes=0', '-f', 'h264', clipPath,
]);
void sourceStream;
const clip = await readFile(clipPath);
const server = createServer(async (request, response) => {
  if (request.url === '/clip.h264') {
    response.writeHead(200, { 'content-type': 'application/octet-stream', 'content-length': clip.length });
    response.end(clip);
  } else {
    response.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
    response.end(html());
  }
});
await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
const port = server.address().port;
const version = run(chromePath, ['--version']);
const profileDir = join(tempDir, 'chrome-profile');
const browser = spawn(chromePath, [
  '--headless=new', '--no-sandbox', '--disable-dev-shm-usage', '--disable-background-networking',
  '--disable-gpu-sandbox', '--remote-debugging-port=0', `--user-data-dir=${profileDir}`,
  '--autoplay-policy=no-user-gesture-required', `http://127.0.0.1:${port}/`,
], { stdio: 'ignore' });

async function poll(url, timeoutMs = 15000) {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    try { return await (await fetch(url)).json(); } catch { await delay(100); }
  }
  throw new Error(`Timed out polling ${url}`);
}

let socket;
try {
  let targets;
  for (let retry = 0; retry < 100; retry++) {
    try {
      targets = await (await fetch(`http://127.0.0.1:${await readFile(join(profileDir, 'DevToolsActivePort'), 'utf8').then(s => Number(s.split('\n')[0]))}/json/list`)).json();
      break;
    } catch { await delay(100); }
  }
  if (!targets) throw new Error('Chromium did not expose a DevTools target');
  const target = targets.find(item => item.type === 'page');
  if (!target) throw new Error('Chromium page target not found');
  socket = new WebSocket(target.webSocketDebuggerUrl);
  await new Promise((resolve, reject) => {
    socket.addEventListener('open', resolve, { once: true });
    socket.addEventListener('error', reject, { once: true });
  });
  let nextId = 1;
  const pending = new Map();
  socket.addEventListener('message', event => {
    const message = JSON.parse(event.data);
    if (message.id && pending.has(message.id)) {
      const { resolve, reject } = pending.get(message.id);
      pending.delete(message.id);
      message.error ? reject(new Error(message.error.message)) : resolve(message.result);
    }
  });
  const rpc = (method, params = {}) => new Promise((resolve, reject) => {
    const id = nextId++;
    pending.set(id, { resolve, reject });
    socket.send(JSON.stringify({ id, method, params }));
  });
  await rpc('Page.enable');
  await rpc('Runtime.enable');
  await rpc('Page.navigate', { url: `http://127.0.0.1:${port}/bench.html` });
  let result;
  const deadline = Date.now() + 90000;
  while (Date.now() < deadline) {
    const evaluation = await rpc('Runtime.evaluate', {
      expression: 'document.querySelector("#result")?.textContent ?? "loading"',
      returnByValue: true,
    });
    const value = evaluation.result?.value;
    if (value && value !== 'running' && value !== 'loading') {
      result = JSON.parse(value);
      break;
    }
    await delay(100);
  }
  if (!result) throw new Error('Browser benchmark timed out');
  if (result.error) throw new Error(`${result.error}\n${result.stack ?? ''}`);
  console.log(JSON.stringify({
    benchmark: 'WebCodecs H.264 decode + OffscreenCanvas 2D drawImage',
    startedAt,
    endedAt: new Date().toISOString(),
    host: run('uname', ['-a']),
    loadAverageAtStart,
    loadAverageAtEnd: loadavg(),
    chromium: version,
    ffmpeg: run('ffmpeg', ['-version']).split('\n')[0],
    cpu: run('sh', ['-c', 'grep -m1 "model name" /proc/cpuinfo | cut -d: -f2-']).trim(),
    mode: 'headless Chromium; prefer-software requested, selected path unverified; loopback; no phone/GPU measurement',
    ...result,
  }, null, 2));
} finally {
  socket?.close();
  if (browser.exitCode === null && browser.signalCode === null) {
    browser.kill('SIGTERM');
    await Promise.race([
      new Promise(resolve => browser.once('exit', resolve)),
      delay(3000),
    ]);
    if (browser.exitCode === null && browser.signalCode === null) {
      browser.kill('SIGKILL');
      await new Promise(resolve => browser.once('exit', resolve));
    }
  }
  server.close();
  for (let retry = 0; retry < 5; retry++) {
    try {
      await rm(tempDir, { recursive: true, force: true });
      break;
    } catch (error) {
      if (error.code !== 'ENOTEMPTY' || retry === 4) throw error;
      await delay(100);
    }
  }
}
