/**
 * Measures browser-codec hot-path decode cost with the runtime's high-resolution timer.
 *
 * Run it directly with Bun. It encodes a 1-byte `Input` frame and a 64-byte `Output` frame
 * once, then decodes each repeatedly and prints the median nanoseconds per decode. It
 * asserts nothing: speed belongs in the performance harness, not in functional tests.
 */

import { decodeFrame, encodeFrame } from "./codec";

const oneByteInput = encodeFrame({ type: "Input", inSeq: 42n, bytes: new Uint8Array([0x6b]) });
const sixtyFourByteOutput = encodeFrame({
  type: "Output",
  outSeq: 65_535n,
  bytes: new Uint8Array(64).fill(0x78),
});

runBenchmark("wire/decode/input_1b", oneByteInput);
runBenchmark("wire/decode/output_64b", sixtyFourByteOutput);

/**
 * Decodes `frame` for a warm-up of 100,000 calls, then takes five 250 ms samples and prints
 * the median ns/decode and the overall decodes per second under `name`.
 */
function runBenchmark(name: string, frame: Uint8Array): void {
  for (let warmup = 0; warmup < 100_000; warmup += 1) {
    decodeFrame(frame);
  }

  const sampleCount = 5;
  const sampleMillis = 250;
  const nsPerDecode: number[] = [];
  let totalExecs = 0;
  let totalMillis = 0;
  for (let sample = 0; sample < sampleCount; sample += 1) {
    const start = performance.now();
    const stop = start + sampleMillis;
    let execs = 0;
    while (performance.now() < stop) {
      decodeFrame(frame);
      execs += 1;
    }
    const elapsed = performance.now() - start;
    totalExecs += execs;
    totalMillis += elapsed;
    nsPerDecode.push((elapsed * 1_000_000) / execs);
  }

  nsPerDecode.sort((left, right) => left - right);
  const median = nsPerDecode[Math.floor(nsPerDecode.length / 2)];
  if (median === undefined) {
    throw new Error("benchmark did not produce a sample");
  }
  const execsPerSecond = totalExecs / (totalMillis / 1_000);
  console.log(`${name}: median ${median.toFixed(1)} ns/decode; ${execsPerSecond.toFixed(0)} execs/s`);
}
