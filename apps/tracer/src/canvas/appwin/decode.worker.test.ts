/** Exercises worker presentation through its real message/decoder callbacks without a display clock. */
import { expect, test } from "bun:test";
import type { FromWorker, ToWorker } from "./worker-protocol";

test("decoder output presents the newest admitted picture immediately and releases stale pictures", async () => {
  const saved = { self: globalThis.self, decoder: globalThis.VideoDecoder, chunk: globalThis.EncodedVideoChunk };
  const messages: FromWorker[] = [];
  const drawn: VideoFrame[] = [];
  let output: ((frame: VideoFrame) => void) | undefined;
  let scheduled = 0;
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
    constructor(options: VideoDecoderInit) { output = options.output; }
    configure() {}
    decode() {}
    close() { this.state = "closed"; }
  }
  try {
    Object.assign(globalThis, { self: scope, VideoDecoder: Decoder, EncodedVideoChunk: class {} });
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
    send({ t: "close" });
  } finally {
    Object.assign(globalThis, { self: saved.self, VideoDecoder: saved.decoder, EncodedVideoChunk: saved.chunk });
  }
});
