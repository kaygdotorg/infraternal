/** Exercises worker presentation through its real message/decoder callbacks without a display clock. */
import { expect, test } from "bun:test";
import type { FromWorker, ToWorker } from "./worker-protocol";
import { MAX_VIDEO_BYTES } from "../../../../../packages/protocol/src/desktop";

test("decoder output presents the newest admitted picture immediately and releases stale pictures", async () => {
  const saved = { self: globalThis.self, decoder: globalThis.VideoDecoder, chunk: globalThis.EncodedVideoChunk };
  const messages: FromWorker[] = [];
  const drawn: VideoFrame[] = [];
  let output: ((frame: VideoFrame) => void) | undefined;
  let current: Decoder | undefined;
  let holdDecoder = false;
  let scheduled = 0;
  let failConfigure = false;
  let failDecode = false;
  const scope = {
    onmessage: null as ((event: MessageEvent<ToWorker>) => void) | null,
    postMessage: (message: FromWorker) => messages.push(message),
    requestAnimationFrame: () => { scheduled++; return scheduled; },
    cancelAnimationFrame: () => {},
    setTimeout: () => { scheduled++; return scheduled; },
    clearTimeout: () => {},
    close: () => {},
  };
  class Decoder {
    state = "configured";
    decodeQueueSize = 0;
    held = holdDecoder;
    chunks: EncodedVideoChunk[] = [];
    ondequeue: (() => void) | undefined;
    readonly error: VideoDecoderInit["error"];
    constructor(options: VideoDecoderInit) { output = options.output; this.error = options.error; current = this; }
    configure() { if (failConfigure) throw new Error("configure failed"); }
    decode(chunk: EncodedVideoChunk) {
      if (failDecode) throw new Error("decode failed");
      this.chunks.push(chunk); if (this.held) this.decodeQueueSize++;
    }
    close() { this.state = "closed"; }
  }
  try {
    Object.assign(globalThis, { self: scope, VideoDecoder: Decoder, EncodedVideoChunk: class {
      readonly timestamp: number;
      constructor(init: EncodedVideoChunkInit) { this.timestamp = init.timestamp; }
    } });
    await import("./decode.worker.on-demand");
    const canvas = { width: 0, height: 0, getContext: () => ({ drawImage: (frame: VideoFrame) => drawn.push(frame) }) } as unknown as OffscreenCanvas;
    const send = (data: ToWorker): void => scope.onmessage?.({ data } as MessageEvent<ToWorker>);
    send({ t: "init", canvas, hardware: "no-preference" });
    send({ t: "chunk", sequence: 1, keyframe: true, bytes: new Uint8Array([0, 0, 0, 1, 0x67, 0x64, 0, 0x28]).buffer });
    expect(output).toBeDefined();
    for (let i = 0; i < 3; i++) {
      if (i > 0) send({ t: "chunk", sequence: i + 1, keyframe: false, bytes: new Uint8Array([0x41]).buffer });
      let closed = 0;
      const frame = { timestamp: i + 1, displayWidth: 640, displayHeight: 480, close: () => { closed++; } } as unknown as VideoFrame;
      output!(frame);
      expect(drawn.at(-1)).toBe(frame);
      expect(closed).toBe(1);
    }
    // Both units already reached the decoder before its output callbacks run.
    // Converting the older output would delay the newest one and feed overload.
    for (const sequence of [4, 5]) send({ t: "chunk", sequence, keyframe: false, bytes: new Uint8Array([0x41]).buffer });
    let staleClosed = 0;
    output!({ timestamp: 4, displayWidth: 640, displayHeight: 480, close: () => { staleClosed++; } } as unknown as VideoFrame);
    expect(staleClosed).toBe(1);
    expect(drawn).toHaveLength(3);
    let newestClosed = 0;
    output!({ timestamp: 5, displayWidth: 640, displayHeight: 480, close: () => { newestClosed++; } } as unknown as VideoFrame);
    expect(newestClosed).toBe(1);
    expect(drawn).toHaveLength(4);
    expect(scheduled).toBe(0);
    expect(messages.filter(m => m.t === "first")).toHaveLength(1);
    send({ t: "stats" });
    expect(messages.at(-1)).toMatchObject({ t: "stats", stats: { decoded: 5, painted: 4, superseded: 1 } });
    // Transport can release several continuous units in one turn. They still
    // carry required codec references; a temporarily full decoder is not loss.
    const before = current!.chunks.length;
    current!.held = true;
    for (let sequence = 6; sequence <= 11; sequence++) {
      send({ t: "chunk", sequence, keyframe: false, bytes: new Uint8Array([0x41]).buffer });
    }
    expect(current!.chunks.length - before).toBe(2);
    for (let index = 0; index < 6; index++) {
      const chunk = current!.chunks[before + index];
      expect(chunk, "continuous burst lost a required reference while the decoder was temporarily full").toBeDefined();
      current!.decodeQueueSize--;
      current!.ondequeue?.();
      let closed = 0;
      output!({ timestamp: chunk!.timestamp, displayWidth: 640, displayHeight: 480, close: () => { closed++; } } as unknown as VideoFrame);
      expect(closed).toBe(1);
    }
    expect(drawn).toHaveLength(5);
    expect(messages.filter(m => m.t === "repair")).toHaveLength(0);
    expect(scheduled).toBe(0);

    const key = (sequence: number, profile = 0x64): void => send({ t: "chunk", sequence, keyframe: true, bytes: new Uint8Array([0, 0, 0, 1, 0x67, profile, 0, 0x28]).buffer });
    const delta = (sequence: number, length = 1): void => {
      const bytes = new Uint8Array(length); bytes[0] = 0x41;
      send({ t: "chunk", sequence, keyframe: false, bytes: bytes.buffer });
    };
    const finish = (instance: Decoder, index: number): void => {
      const chunk = instance.chunks[index];
      expect(chunk).toBeDefined();
      instance.decodeQueueSize--;
      instance.ondequeue?.();
      let closed = 0;
      output!({ timestamp: chunk!.timestamp, displayWidth: 640, displayHeight: 480, close: () => { closed++; } } as unknown as VideoFrame);
      expect(closed).toBe(1);
    };
    holdDecoder = true;

    // Codec consumption can precede its dequeue event. Use that available
    // capacity before declaring an arriving continuous unit to be overload.
    send({ t: "reset" }); key(1); delta(2);
    for (let sequence = 3; sequence <= 10; sequence++) delta(sequence);
    const available = current!;
    available.decodeQueueSize = 0;
    const repairsAtConsumption = messages.filter(m => m.t === "repair").length;
    delta(11);
    expect(available.chunks).toHaveLength(4);
    for (let index = 0; index < 2; index++) {
      let closed = 0;
      output!({ timestamp: available.chunks[index]!.timestamp, displayWidth: 640, displayHeight: 480, close: () => { closed++; } } as unknown as VideoFrame);
      expect(closed).toBe(1);
    }
    for (let index = 2; index < 11; index++) finish(available, index);
    expect(messages.filter(m => m.t === "repair")).toHaveLength(repairsAtConsumption);

    // Completed output is another capacity signal. A deferred/coalesced dequeue
    // event must not strand the last buffered references on a now-static source.
    send({ t: "reset" }); key(1);
    for (let sequence = 2; sequence <= 6; sequence++) delta(sequence);
    const completed = current!;
    completed.decodeQueueSize = 0;
    for (let index = 0; index < 6; index++) {
      const chunk = completed.chunks[index];
      expect(chunk, "completed output stranded buffered references before a dequeue event").toBeDefined();
      if (index >= 2) completed.decodeQueueSize--;
      let closed = 0;
      output!({ timestamp: chunk!.timestamp, displayWidth: 640, displayHeight: 480, close: () => { closed++; } } as unknown as VideoFrame);
      expect(closed).toBe(1);
    }
    expect(completed.chunks).toHaveLength(6);

    // Count overload discards the whole unsubmitted chain. Even a repair IDR
    // arriving while the codec is full waits safely instead of being dropped.
    send({ t: "reset" }); key(1); delta(2);
    for (let sequence = 3; sequence <= 11; sequence++) delta(sequence);
    const counted = current!;
    expect(counted.chunks).toHaveLength(2);
    const beforeCounted = drawn.length;
    key(12);
    for (let index = 0; index < 3; index++) finish(counted, index);
    expect(counted.chunks).toHaveLength(3);
    expect(drawn.length - beforeCounted).toBe(1);

    // Byte overload must also refuse a broken chain when its unit count fits.
    send({ t: "reset" }); key(1); delta(2);
    for (let sequence = 3; sequence <= 5; sequence++) delta(sequence, Math.floor(MAX_VIDEO_BYTES / 2));
    const sized = current!;
    finish(sized, 0);
    expect(sized.chunks).toHaveLength(2);
    finish(sized, 1);
    key(6); finish(sized, 2);
    expect(sized.chunks).toHaveLength(3);

    // A profile-changing IDR replaces old pending references, but its own
    // following deltas must survive closing the previous decoder.
    send({ t: "reset" }); key(1); delta(2); delta(3); delta(4);
    const previous = current!;
    const beforeProfile = drawn.length;
    const repairsBefore = messages.filter(m => m.t === "repair").length;
    key(5, 0x42); delta(6); delta(7);
    finish(previous, 0);
    expect(previous.state).toBe("closed");
    const replacement = current!;
    expect(replacement).not.toBe(previous);
    for (let index = 0; index < 3; index++) finish(replacement, index);
    expect(replacement.chunks).toHaveLength(3);
    expect(drawn.length - beforeProfile).toBe(1);
    expect(messages.filter(m => m.t === "repair")).toHaveLength(repairsBefore);

    // A reset releases pending units; a later session never replays them.
    key(8, 0x42); delta(9); delta(10); delta(11);
    const retired = current!;
    send({ t: "reset" }); key(1);
    expect(retired.state).toBe("closed");
    expect(current).not.toBe(retired);
    expect(current!.chunks).toHaveLength(1);
    finish(current!, 0);
    // Every retirement path releases coded references. Recovery starts from
    // the new IDR, including failures while pumping an already buffered chain.
    for (const failure of ["callback", "configure", "decode", "gap", "close"] as const) {
      send({ t: "reset" }); key(1); delta(2); delta(3); delta(4);
      const failed = current!;
      if (failure === "callback") failed.error(new DOMException("codec failed", "EncodingError"));
      if (failure === "configure") {
        key(5, 0x42); delta(6);
        failConfigure = true;
        failed.decodeQueueSize = 0; failed.ondequeue?.();
        failConfigure = false;
      }
      if (failure === "decode") {
        failDecode = true;
        failed.decodeQueueSize = 0; failed.ondequeue?.();
        failDecode = false;
      }
      if (failure === "gap") {
        delta(6);
        failed.decodeQueueSize = 0; failed.ondequeue?.();
        expect(failed.chunks).toHaveLength(2);
      }
      if (failure === "close") {
        send({ t: "close" });
        send({ t: "init", canvas, hardware: "no-preference" });
      }
      key(7); delta(8);
      const recovered = current!;
      if (failure !== "gap") {
        expect(failed.state).toBe("closed");
        expect(recovered).not.toBe(failed);
      }
      const start = failure === "gap" ? 2 : 0;
      expect(recovered.chunks).toHaveLength(start + 2);
      finish(recovered, start); finish(recovered, start + 1);
      expect(recovered.chunks).toHaveLength(start + 2);
    }
    send({ t: "stats" });
    expect(messages.at(-1)).toMatchObject({ t: "stats", stats: { pendingPeak: 8, pendingBytesPeak: MAX_VIDEO_BYTES } });
    expect(messages.filter(m => m.t === "trace")).toHaveLength(0);
    send({ t: "reset" });
    send({ t: "init", canvas, hardware: "no-preference", measure: true });
    for (let i = 0; i < 3; i++) send({
      t: "chunk", sequence: 100 + i, keyframe: i === 0,
      bytes: new Uint8Array(i === 0 ? [0, 0, 0, 1, 0x67, 0x64, 0, 0x28] : [0x41]).buffer,
      trace: { captureNs: String(900 + i), bytes: i === 0 ? 8 : 1, receivedAt: 1, copyFinishedAt: 2 },
    });
    const measured = current!;
    for (let i = 0; i < 3; i++) finish(measured, i);
    const receipts = messages.filter(m => m.t === "trace").map(m => m.frame);
    expect(receipts.map(r => [r.sequence, r.captureNs, r.outcome])).toEqual([
      [100, "900", "superseded"], [101, "901", "superseded"], [102, "902", "painted"],
    ]);
    for (const receipt of receipts) {
      expect(receipt.workerReceivedAt).toBeLessThanOrEqual(receipt.submittedAt!);
      expect(receipt.submittedAt).toBeLessThanOrEqual(receipt.decodedAt!);
    }
    expect(receipts[2]!.decodedAt).toBeLessThanOrEqual(receipts[2]!.drawStartedAt!);
    expect(receipts[2]!.drawStartedAt).toBeLessThanOrEqual(receipts[2]!.drawFinishedAt!);
    // A codec may admit requests before delivering output. Missing callbacks
    // must not turn the opt-in diagnostic into an unbounded metadata queue.
    send({ t: "reset" }); holdDecoder = false; messages.length = 0;
    send({ t: "init", canvas, hardware: "no-preference", measure: true });
    for (let i = 1; i <= 515; i++) send({
      t: "chunk", sequence: i, keyframe: i === 1,
      bytes: new Uint8Array(i === 1 ? [0, 0, 0, 1, 0x67, 0x64, 0, 0x28] : [0x41]).buffer,
      trace: { captureNs: String(i), bytes: 1, receivedAt: 1, copyFinishedAt: 2 },
    });
    expect(messages.filter(m => m.t === "trace").map(m => [m.frame.sequence, m.frame.outcome])).toEqual([
      [1, "unpainted"], [2, "unpainted"], [3, "unpainted"],
    ]);
    finish(current!, 514);
    expect(messages.at(-1)).toMatchObject({ t: "trace", frame: { sequence: 515, captureNs: "515", outcome: "painted" } });


  } finally {
    scope.onmessage?.({ data: { t: "close" } } as MessageEvent<ToWorker>);
    Object.assign(globalThis, { self: saved.self, VideoDecoder: saved.decoder, EncodedVideoChunk: saved.chunk });
  }
});
