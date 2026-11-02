/** Compares both incremental mux decoders with direct decoding under identical chunk schedules. */
import { expect, test } from "bun:test";
import { WebSocketFrameDecoder, encodeFrame, decodeFrame, decodeMuxedFrame, encodeMuxedFrame, MAX_FRAME_LEN } from "./codec";

import { desktopCases } from "./desktop-fixtures";

function normalize(value: unknown): unknown {
  return JSON.parse(JSON.stringify(value, (_key, field: unknown) =>
    typeof field === "bigint" ? field.toString() : field instanceof Uint8Array ? Array.from(field) : field));
}

function join(parts: Uint8Array[]): Uint8Array {
  const bytes = new Uint8Array(parts.reduce((sum, part) => sum + part.length, 0));
  let offset = 0;
  for (const part of parts) { bytes.set(part, offset); offset += part.length; }
  return bytes;
}

test("Rust and TypeScript preserve every frame at all boundaries and random multi-splits", async () => {
  const root = new URL("../../../", import.meta.url);
  const manifestUrl = new URL("contracts/vectors/wire/manifest.json", root);
  const manifest: { vectors: { file: string }[] } = JSON.parse(await Bun.file(manifestUrl).text());
  const raw: Uint8Array[] = await Promise.all(manifest.vectors.map(async ({ file }) =>
    new Uint8Array(await Bun.file(new URL(file, manifestUrl)).arrayBuffer())));
  raw.push(new Uint8Array([3, 15, 0, 0]), new Uint8Array([5, 20, 1, 0, 0, 0]));
  raw.push(...desktopCases.map(message => encodeFrame({type:"Desktop",message})));
  const streams: Uint8Array[] = [];
  for (const id of [0, 127, 128, 16384, 2097152, 268435456, 0xffffffff]) {
    for (const bytes of raw) {
      const frame = decodeFrame(bytes).frame;
      streams.push(join([encodeMuxedFrame(id, frame), encodeMuxedFrame(id, frame),
        encodeMuxedFrame(0, { type: "Close", code: 0, reason: "" })]));
    }
  }
  streams.push(join(raw.map((bytes, id) => encodeMuxedFrame(id, decodeFrame(bytes).frame))));
  let state = 0x15c0dec;
  const random = () => { state = (Math.imul(state, 1664525) + 1013904223) >>> 0; return state; };
  const requests: string[] = [];
  const results: unknown[] = [];
  let cases = 0;
  for (const bytes of streams) {
    const expected: unknown[] = [];
    for (let offset = 0; offset < bytes.length;) {
      const decoded = decodeMuxedFrame(bytes.subarray(offset));
      expected.push(normalize({ streamId: decoded.streamId, frame: decoded.frame }));
      offset += decoded.bytesRead;
    }
    const schedules: number[][] = [];
    for (let split = 0; split <= bytes.length; split++) schedules.push([0, split, 0, bytes.length - split, 0]);
    for (let trial = 0; trial < 32; trial++) {
      const chunks: number[] = [0];
      for (let left = bytes.length; left > 0;) {
        const size = Math.min(left, 1 + random() % 37);
        chunks.push(size, 0); left -= size;
      }
      schedules.push(chunks);
    }
    for (const chunks of schedules) {
      const decoder = new WebSocketFrameDecoder();
      const frames: unknown[] = [];
      const encoded: Uint8Array[] = [];
      let offset = 0;
      for (const size of chunks) {
        decoder.feed(bytes.subarray(offset, offset + size), (streamId, frame) => {
          // Snapshot borrowed payloads before the decoder reuses its scratch.
          frames.push(normalize({ streamId, frame }));
          encoded.push(encodeMuxedFrame(streamId, frame));
        });
        offset += size;
      }
      expect(frames).toEqual(expected);
      expect(join(encoded)).toEqual(bytes);
      expect(decoder.bufferedLength).toBe(0);
      requests.push(JSON.stringify({ bytes: Array.from(bytes), chunks }));
      results.push({ frames, buffered: decoder.bufferedLength });
      cases++;
    }
  }
  const bridge = Bun.spawnSync(["cargo", "run", "--quiet", "-p", "infraternal-protocol", "--features", "desktop", "--example", "stream_oracle"], {
    cwd: root.pathname, stdin: new TextEncoder().encode(requests.join("\n") + "\n"), maxBuffer: 128 * 1024 * 1024,
  });
  if (bridge.exitCode !== 0) throw new Error(new TextDecoder().decode(bridge.stderr));
  const rust = new TextDecoder().decode(bridge.stdout).trim().split("\n").map((line) => JSON.parse(line));
  expect(rust).toEqual(results);
  console.log(`stream differential: ${streams.length} streams, ${cases} schedules, zero divergences`);
});

test("maximum frame size and fragmented oversized prefix obey the allocation boundary", () => {
  const bytes = encodeMuxedFrame(0xffffffff, { type: "Output", outSeq: 0n, bytes: new Uint8Array(MAX_FRAME_LEN - 9) });
  const decoder = new WebSocketFrameDecoder();
  let seen = 0;
  for (const chunk of [bytes.subarray(0, 1), bytes.subarray(1, 7), bytes.subarray(7)]) {
    decoder.feed(chunk, (_id, frame) => { expect(frame.type).toBe("Output"); seen++; });
  }
  expect(seen).toBe(1);
  expect(decoder.bufferedLength).toBe(0);
  const oversized = new WebSocketFrameDecoder();
  oversized.feed(new Uint8Array([0]), () => {});
  expect(() => oversized.feed(new Uint8Array([0x81, 0x80, 0x80, 0x02, ...new Uint8Array(10000)]), () => {})).toThrow();
  expect(oversized.bufferedLength).toBe(5);
});
