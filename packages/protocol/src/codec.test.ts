/** Verifies TypeScript wire behavior against the shared binary golden vectors. */

import { describe, expect, test } from "bun:test";
import {
  MAX_FRAME_LEN,
  WireDecodeError,
  decodeFrame,
  decodeMuxedFrame,
  encodeFrame,
  encodeFrameInto,
  encodeMuxedFrame,
  type WireFrame,
} from "./codec";

const manifestUrl = new URL("../../../contracts/vectors/wire/manifest.json", import.meta.url);

interface Vector {
  name: string;
  file: string;
  frame: WireFrame;
}

describe("wire protocol golden vectors", () => {
  test("encodes and decodes each frame exactly as the shared manifest describes", async () => {
    const vectors = await readVectors();
    expect(vectors.length).toBe(17);
    for (const vector of vectors) {
      const bytes = new Uint8Array(await Bun.file(new URL(vector.file, manifestUrl)).arrayBuffer());
      expect(encodeFrame(vector.frame)).toEqual(bytes);
      expect(decodeFrame(bytes).frame).toEqual(vector.frame);
      expect(decodeFrame(bytes).bytesRead).toBe(bytes.byteLength);
    }
  });

  test("returns borrowed payload views and writes into reusable buffers", () => {
    const original = encodeFrame({ type: "Input", inSeq: 42n, bytes: new Uint8Array([0x6b]) });
    const decoded = decodeFrame(original);
    if (decoded.frame.type !== "Input") {
      throw new Error("expected input frame");
    }
    expect(decoded.frame.bytes.buffer).toBe(original.buffer);

    const reusable = new Uint8Array(32);
    const written = encodeFrameInto(
      { type: "Input", inSeq: 42n, bytes: new Uint8Array([0x6b]) },
      reusable,
      3,
    );
    expect(reusable.subarray(3, 3 + written)).toEqual(original);
  });

  test("rejects oversized, non-canonical, unknown, and malformed frame bytes", () => {
    expect(() => decodeFrame(new Uint8Array([0x81, 0x80, 0x80, 0x02]))).toThrow(WireDecodeError);
    expect(() => decodeFrame(new Uint8Array([0x81, 0x00]))).toThrow(WireDecodeError);
    expect(() => decodeFrame(new Uint8Array([0x01, 0xff]))).toThrow(WireDecodeError);
    expect(() => decodeFrame(new Uint8Array([0x01, 0x08]))).toThrow(WireDecodeError);
    expect(MAX_FRAME_LEN).toBe(4 * 1024 * 1024);
  });
});

async function readVectors(): Promise<Vector[]> {
  const parsed: unknown = JSON.parse(await Bun.file(manifestUrl).text());
  const root = record(parsed, "manifest");
  const values = root["vectors"];
  if (!Array.isArray(values)) {
    throw new Error("manifest vectors must be an array");
  }
  return values.map((value: unknown) => {
    const item = record(value, "vector");
    return {
      name: stringField(item, "name"),
      file: stringField(item, "file"),
      frame: readFrame(record(item["frame"], "frame")),
    };
  });
}

function readFrame(value: Record<string, unknown>): WireFrame {
  switch (stringField(value, "type")) {
    case "Hello":
      return {
        type: "Hello",
        version: numberField(value, "version"),
        caps: BigInt(stringField(value, "caps")),
        clientInfo: stringField(value, "clientInfo"),
      };
    case "Welcome":
      return {
        type: "Welcome",
        connectionId: hexField(value, "connectionId"),
        resumeToken: hexField(value, "resumeToken"),
        resumeWindowSeconds: numberField(value, "resumeWindowSeconds"),
      };
    case "Resume":
      return {
        type: "Resume",
        connectionId: hexField(value, "connectionId"),
        resumeToken: hexField(value, "resumeToken"),
      };
    case "Ping":
      return {
        type: "Ping",
        nonce: BigInt(stringField(value, "nonce")),
        sentUs: BigInt(stringField(value, "sentUs")),
      };
    case "Pong":
      return {
        type: "Pong",
        nonce: BigInt(stringField(value, "nonce")),
        sentUs: BigInt(stringField(value, "sentUs")),
      };
    case "Close":
      return {
        type: "Close",
        code: numberField(value, "code"),
        reason: stringField(value, "reason"),
      };
    case "Input":
      return {
        type: "Input",
        inSeq: BigInt(stringField(value, "inSeq")),
        bytes: hexField(value, "bytesHex"),
      };
    case "Output":
      return {
        type: "Output",
        outSeq: BigInt(stringField(value, "outSeq")),
        bytes: hexField(value, "bytesHex"),
      };
    case "Resize":
      return {
        type: "Resize",
        cols: numberField(value, "cols"),
        rows: numberField(value, "rows"),
        pxW: numberField(value, "pxW"),
        pxH: numberField(value, "pxH"),
      };
    case "Ack":
      return { type: "Ack", inSeqAcked: BigInt(stringField(value, "inSeqAcked")) };
    case "Credit":
      return { type: "Credit", bytes: numberField(value, "bytes") };
    case "Snapshot":
      return {
        type: "Snapshot",
        outSeq: BigInt(stringField(value, "outSeq")),
        bytes: hexField(value, "bytesHex"),
      };
    case "AttachTerm":
      return {
        type: "AttachTerm",
        sessionId: hexField(value, "sessionId"),
        lastOutSeq: BigInt(stringField(value, "lastOutSeq")),
        lastInSeq: BigInt(stringField(value, "lastInSeq")),
      };
    case "Call":
      return {
        type: "Call",
        callId: numberField(value, "callId"),
        actionId: stringField(value, "actionId"),
        inputJson: new TextEncoder().encode(stringField(value, "inputJson")),
      };
    case "Result":
      return {
        type: "Result",
        callId: numberField(value, "callId"),
        ok: booleanField(value, "ok"),
        json: new TextEncoder().encode(stringField(value, "json")),
      };
    case "Subscribe":
      return {
        type: "Subscribe",
        subId: numberField(value, "subId"),
        filterJson: new TextEncoder().encode(stringField(value, "filterJson")),
      };
    case "Event":
      return {
        type: "Event",
        subId: numberField(value, "subId"),
        eventJson: new TextEncoder().encode(stringField(value, "eventJson")),
      };
    default:
      throw new Error("manifest contains an unsupported frame type");
  }
}

function record(value: unknown, label: string): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error(`${label} must be an object`);
  }
  return value as Record<string, unknown>;
}

function stringField(value: Record<string, unknown>, key: string): string {
  const field = value[key];
  if (typeof field !== "string") {
    throw new Error(`${key} must be a string`);
  }
  return field;
}

function numberField(value: Record<string, unknown>, key: string): number {
  const field = value[key];
  if (typeof field !== "number" || !Number.isInteger(field)) {
    throw new Error(`${key} must be an integer`);
  }
  return field;
}

function booleanField(value: Record<string, unknown>, key: string): boolean {
  const field = value[key];
  if (typeof field !== "boolean") {
    throw new Error(`${key} must be a boolean`);
  }
  return field;
}

function hexField(value: Record<string, unknown>, key: string): Uint8Array {
  const digits = stringField(value, key);
  if (digits.length % 2 !== 0 || !/^[0-9a-f]*$/i.test(digits)) {
    throw new Error(`${key} must be even-length hexadecimal`);
  }
  const bytes = new Uint8Array(digits.length / 2);
  for (let index = 0; index < bytes.length; index += 1) {
    const pair = digits.slice(index * 2, index * 2 + 2);
    bytes[index] = Number.parseInt(pair, 16);
  }
  return bytes;
}
