/** Implements the borrowed browser codec, mux envelope, and WebSocket stream decoder from contracts/wire.md. */

export const MAX_FRAME_LEN = 4 * 1024 * 1024;
const MAX_U32 = 0xffff_ffff;
const MAX_U64 = 0xffff_ffff_ffff_ffffn;
const MAX_VARINT_BYTES = 5;
const textEncoder = new TextEncoder();
// Keep an initial U+FEFF as data, matching Rust's strict UTF-8 string decoder.
const textDecoder = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });

export type WireFrame =
  | { type: "Hello"; version: number; caps: bigint; clientInfo: string }
  | {
      type: "Welcome";
      connectionId: Uint8Array;
      resumeToken: Uint8Array;
      resumeWindowSeconds: number;
    }
  | { type: "Resume"; connectionId: Uint8Array; resumeToken: Uint8Array }
  | { type: "Ping" | "Pong"; nonce: bigint; sentUs: bigint }
  | { type: "Close"; code: number; reason: string }
  | { type: "Input"; inSeq: bigint; bytes: Uint8Array }
  | { type: "Output"; outSeq: bigint; bytes: Uint8Array }
  | { type: "Resize"; cols: number; rows: number; pxW: number; pxH: number }
  | { type: "Ack"; inSeqAcked: bigint }
  | { type: "Credit"; bytes: number }
  | { type: "Snapshot"; outSeq: bigint; bytes: Uint8Array }
  | { type: "AttachTerm"; sessionId: Uint8Array; lastOutSeq: bigint; lastInSeq: bigint }
  | { type: "Call"; callId: number; actionId: string; inputJson: Uint8Array }
  | { type: "Result"; callId: number; ok: boolean; json: Uint8Array }
  | { type: "Subscribe"; subId: number; filterJson: Uint8Array }
  | { type: "Event"; subId: number; eventJson: Uint8Array };

export type DecodeErrorCode =
  | "incomplete"
  | "empty-frame"
  | "frame-too-large"
  | "varint-overflow"
  | "non-canonical-varint"
  | "varint-too-long"
  | "unknown-type"
  | "invalid-body"
  | "invalid-utf8";

/** Carries stable machine-readable decoder failures for untrusted wire bytes. */
export class WireDecodeError extends Error {
  readonly code: DecodeErrorCode;

  constructor(code: DecodeErrorCode, message: string) {
    super(message);
    this.name = "WireDecodeError";
    this.code = code;
  }
}

/** Carries stable machine-readable failures while encoding a wire frame. */
export class WireEncodeError extends Error {
  readonly code: "length-overflow" | "frame-too-large" | "buffer-too-small";

  constructor(code: WireEncodeError["code"], message: string) {
    super(message);
    this.name = "WireEncodeError";
    this.code = code;
  }
}

export interface DecodedFrame {
  /** Decoded fields; variable byte fields are subarray views into the input. */
  frame: WireFrame;
  /** Number of input bytes consumed by this frame. */
  bytesRead: number;
}

export interface DecodedMuxedFrame extends DecodedFrame {
  /** Unsigned 32-bit mux stream identifier. */
  streamId: number;
}

/** Decodes one complete frame and returns borrowed byte views for binary fields. */
export function decodeFrame(input: Uint8Array): DecodedFrame {
  const frameLength = readFrameLength(input, 0);
  if (frameLength.value === 0) {
    throw decodeError("empty-frame", "frame length cannot be zero");
  }
  const wireLength = frameLength.bytesRead + frameLength.value;
  if (input.byteLength < wireLength) {
    throw decodeError("incomplete", "frame body is incomplete");
  }
  const typeOffset = frameLength.bytesRead;
  const type = input[typeOffset];
  if (type === undefined) {
    throw decodeError("incomplete", "frame type is incomplete");
  }
  const body = input.subarray(typeOffset + 1, wireLength);
  return { frame: decodeBody(type, body), bytesRead: wireLength };
}

/** Decodes one varint stream id followed by one frame, borrowing payload bytes. */
export function decodeMuxedFrame(input: Uint8Array): DecodedMuxedFrame {
  const streamId = readVarint(input, 0);
  const frameStart = streamId.bytesRead;
  const decoded = decodeFrame(input.subarray(frameStart));
  return {
    streamId: streamId.value,
    frame: decoded.frame,
    bytesRead: frameStart + decoded.bytesRead,
  };
}

/** Writes a frame at `offset` in a caller-owned reusable output buffer. */
export function encodeFrameInto(frame: WireFrame, output: Uint8Array, offset = 0): number {
  const measured = measureFrame(frame);
  ensureCapacity(output, offset, measured.wireLength);
  writeFrameAt(frame, output, offset, measured);
  return measured.wireLength;
}

/** Allocates an exactly sized frame buffer for convenience at non-hot call sites. */
export function encodeFrame(frame: WireFrame): Uint8Array {
  const measured = measureFrame(frame);
  const output = new Uint8Array(measured.wireLength);
  writeFrameAt(frame, output, 0, measured);
  return output;
}

/** Writes a mux stream id and frame at `offset` in a caller-owned buffer. */
export function encodeMuxedFrameInto(
  streamId: number,
  frame: WireFrame,
  output: Uint8Array,
  offset = 0,
): number {
  const muxId = checkedU32(streamId, "stream id");
  const measured = measureFrame(frame);
  const streamPrefixLength = varintLength(muxId);
  const wireLength = streamPrefixLength + measured.wireLength;
  ensureCapacity(output, offset, wireLength);
  writeVarintAt(muxId, output, offset);
  writeFrameAt(frame, output, offset + streamPrefixLength, measured);
  return wireLength;
}

/** Allocates an exactly sized mux envelope for convenience at non-hot call sites. */
export function encodeMuxedFrame(streamId: number, frame: WireFrame): Uint8Array {
  const muxId = checkedU32(streamId, "stream id");
  const measured = measureFrame(frame);
  const streamPrefixLength = varintLength(muxId);
  const output = new Uint8Array(streamPrefixLength + measured.wireLength);
  writeVarintAt(muxId, output, 0);
  writeFrameAt(frame, output, streamPrefixLength, measured);
  return output;
}

interface Varint {
  value: number;
  bytesRead: number;
}

interface FrameMeasure {
  type: number;
  bodyLength: number;
  wireLength: number;
}

function decodeBody(type: number, body: Uint8Array): WireFrame {
  const reader = new BodyReader(type, body);
  switch (type) {
    case 0x00: {
      const version = reader.u16();
      const caps = reader.u64();
      const clientInfo = reader.varString();
      reader.ensureEnd();
      return { type: "Hello", version, caps, clientInfo };
    }
    case 0x01: {
      const connectionId = reader.fixed(16);
      const resumeToken = reader.fixed(32);
      const resumeWindowSeconds = reader.u32();
      reader.ensureEnd();
      return { type: "Welcome", connectionId, resumeToken, resumeWindowSeconds };
    }
    case 0x02: {
      const connectionId = reader.fixed(16);
      const resumeToken = reader.fixed(32);
      reader.ensureEnd();
      return { type: "Resume", connectionId, resumeToken };
    }
    case 0x08:
      return { type: "Ping", nonce: reader.u64(), sentUs: reader.u64AfterPrevious() };
    case 0x09:
      return { type: "Pong", nonce: reader.u64(), sentUs: reader.u64AfterPrevious() };
    case 0x0f: {
      const code = reader.u16();
      return { type: "Close", code, reason: reader.utf8Rest() };
    }
    case 0x10:
      return { type: "Input", inSeq: reader.u64(), bytes: reader.rest() };
    case 0x11:
      return { type: "Output", outSeq: reader.u64(), bytes: reader.rest() };
    case 0x12: {
      const cols = reader.u16();
      const rows = reader.u16();
      const pxW = reader.u16();
      const pxH = reader.u16();
      reader.ensureEnd();
      return { type: "Resize", cols, rows, pxW, pxH };
    }
    case 0x13: {
      const inSeqAcked = reader.u64();
      reader.ensureEnd();
      return { type: "Ack", inSeqAcked };
    }
    case 0x14: {
      const bytes = reader.u32();
      reader.ensureEnd();
      return { type: "Credit", bytes };
    }
    case 0x15:
      return { type: "Snapshot", outSeq: reader.u64(), bytes: reader.rest() };
    case 0x16: {
      const sessionId = reader.fixed(16);
      const lastOutSeq = reader.u64();
      const lastInSeq = reader.u64();
      reader.ensureEnd();
      return { type: "AttachTerm", sessionId, lastOutSeq, lastInSeq };
    }
    case 0x30: {
      const callId = reader.u32();
      const actionId = reader.varString();
      return { type: "Call", callId, actionId, inputJson: reader.rest() };
    }
    case 0x31: {
      const callId = reader.u32();
      const okByte = reader.u8();
      if (okByte !== 0 && okByte !== 1) {
        throw decodeError("invalid-body", "Result success byte must be zero or one");
      }
      return { type: "Result", callId, ok: okByte === 1, json: reader.rest() };
    }
    case 0x32:
      return { type: "Subscribe", subId: reader.u32(), filterJson: reader.rest() };
    case 0x33:
      return { type: "Event", subId: reader.u32(), eventJson: reader.rest() };
    default:
      throw decodeError("unknown-type", `unknown frame type 0x${type.toString(16)}`);
  }
}

class BodyReader {
  private offset = 0;
  private readonly view: DataView;

  constructor(private readonly type: number, private readonly body: Uint8Array) {
    this.view = new DataView(body.buffer, body.byteOffset, body.byteLength);
  }

  u8(): number {
    this.ensure(1);
    const value = this.body[this.offset];
    if (value === undefined) {
      throw this.invalid("field is truncated");
    }
    this.offset += 1;
    return value;
  }

  u16(): number {
    this.ensure(2);
    const value = this.view.getUint16(this.offset, true);
    this.offset += 2;
    return value;
  }

  u32(): number {
    this.ensure(4);
    const value = this.view.getUint32(this.offset, true);
    this.offset += 4;
    return value;
  }

  u64(): bigint {
    this.ensure(8);
    const value = this.view.getBigUint64(this.offset, true);
    this.offset += 8;
    return value;
  }

  u64AfterPrevious(): bigint {
    const value = this.u64();
    this.ensureEnd();
    return value;
  }

  fixed(length: number): Uint8Array {
    this.ensure(length);
    const value = this.body.subarray(this.offset, this.offset + length);
    this.offset += length;
    return value;
  }

  varString(): string {
    let length: Varint;
    try {
      length = readVarint(this.body, this.offset);
    } catch (error: unknown) {
      if (isIncomplete(error)) {
        throw this.invalid("string length prefix is truncated");
      }
      throw error;
    }
    this.offset += length.bytesRead;
    const bytes = this.fixed(length.value);
    try {
      return textDecoder.decode(bytes);
    } catch {
      throw decodeError("invalid-utf8", `frame type 0x${this.type.toString(16)} has invalid UTF-8`);
    }
  }

  utf8Rest(): string {
    const bytes = this.rest();
    try {
      return textDecoder.decode(bytes);
    } catch {
      throw decodeError("invalid-utf8", `frame type 0x${this.type.toString(16)} has invalid UTF-8`);
    }
  }

  rest(): Uint8Array {
    const value = this.body.subarray(this.offset);
    this.offset = this.body.byteLength;
    return value;
  }

  ensureEnd(): void {
    if (this.offset !== this.body.byteLength) {
      throw this.invalid("frame body has unexpected trailing bytes");
    }
  }

  private ensure(length: number): void {
    if (this.offset + length > this.body.byteLength) {
      throw this.invalid("frame body is truncated");
    }
  }

  private invalid(message: string): WireDecodeError {
    return decodeError("invalid-body", `frame type 0x${this.type.toString(16)}: ${message}`);
  }
}

function measureFrame(frame: WireFrame): FrameMeasure {
  let type: number;
  let bodyLength: number;
  switch (frame.type) {
    case "Hello":
      checkedU16(frame.version, "version");
      checkedU64(frame.caps, "caps");
      bodyLength = checkedAdd(10, stringFieldLength(frame.clientInfo));
      type = 0x00;
      break;
    case "Welcome":
      requireLength(frame.connectionId, 16, "connection id");
      requireLength(frame.resumeToken, 32, "resume token");
      checkedU32(frame.resumeWindowSeconds, "resume window");
      bodyLength = 52;
      type = 0x01;
      break;
    case "Resume":
      requireLength(frame.connectionId, 16, "connection id");
      requireLength(frame.resumeToken, 32, "resume token");
      bodyLength = 48;
      type = 0x02;
      break;
    case "Ping":
    case "Pong":
      checkedU64(frame.nonce, "nonce");
      checkedU64(frame.sentUs, "sent timestamp");
      bodyLength = 16;
      type = frame.type === "Ping" ? 0x08 : 0x09;
      break;
    case "Close":
      checkedU16(frame.code, "close code");
      bodyLength = checkedAdd(2, textEncoder.encode(frame.reason).byteLength);
      type = 0x0f;
      break;
    case "Input":
      checkedU64(frame.inSeq, "input sequence");
      bodyLength = checkedAdd(8, frame.bytes.byteLength);
      type = 0x10;
      break;
    case "Output":
      checkedU64(frame.outSeq, "output sequence");
      bodyLength = checkedAdd(8, frame.bytes.byteLength);
      type = 0x11;
      break;
    case "Resize":
      checkedU16(frame.cols, "columns");
      checkedU16(frame.rows, "rows");
      checkedU16(frame.pxW, "pixel width");
      checkedU16(frame.pxH, "pixel height");
      bodyLength = 8;
      type = 0x12;
      break;
    case "Ack":
      checkedU64(frame.inSeqAcked, "acknowledged sequence");
      bodyLength = 8;
      type = 0x13;
      break;
    case "Credit":
      checkedU32(frame.bytes, "credit bytes");
      bodyLength = 4;
      type = 0x14;
      break;
    case "Snapshot":
      checkedU64(frame.outSeq, "snapshot sequence");
      bodyLength = checkedAdd(8, frame.bytes.byteLength);
      type = 0x15;
      break;
    case "AttachTerm":
      requireLength(frame.sessionId, 16, "session id");
      checkedU64(frame.lastOutSeq, "last output sequence");
      checkedU64(frame.lastInSeq, "last input sequence");
      bodyLength = 32;
      type = 0x16;
      break;
    case "Call":
      checkedU32(frame.callId, "call id");
      bodyLength = checkedAdd(4 + stringFieldLength(frame.actionId), frame.inputJson.byteLength);
      type = 0x30;
      break;
    case "Result":
      checkedU32(frame.callId, "call id");
      bodyLength = checkedAdd(5, frame.json.byteLength);
      type = 0x31;
      break;
    case "Subscribe":
      checkedU32(frame.subId, "subscription id");
      bodyLength = checkedAdd(4, frame.filterJson.byteLength);
      type = 0x32;
      break;
    case "Event":
      checkedU32(frame.subId, "subscription id");
      bodyLength = checkedAdd(4, frame.eventJson.byteLength);
      type = 0x33;
      break;
  }

  const frameLength = bodyLength + 1;
  if (frameLength > MAX_FRAME_LEN) {
    throw new WireEncodeError("frame-too-large", `frame length ${frameLength} exceeds ${MAX_FRAME_LEN}`);
  }
  const wireLength = varintLength(frameLength) + frameLength;
  return { type, bodyLength, wireLength };
}

function writeFrameAt(frame: WireFrame, output: Uint8Array, offset: number, measured: FrameMeasure): void {
  writeVarintAt(measured.bodyLength + 1, output, offset);
  let cursor = offset + varintLength(measured.bodyLength + 1);
  output[cursor] = measured.type;
  cursor += 1;
  const view = new DataView(output.buffer, output.byteOffset, output.byteLength);
  switch (frame.type) {
    case "Hello":
      view.setUint16(cursor, frame.version, true);
      cursor += 2;
      view.setBigUint64(cursor, frame.caps, true);
      cursor += 8;
      cursor = writeStringAt(frame.clientInfo, output, cursor);
      break;
    case "Welcome":
      output.set(frame.connectionId, cursor);
      cursor += 16;
      output.set(frame.resumeToken, cursor);
      cursor += 32;
      view.setUint32(cursor, frame.resumeWindowSeconds, true);
      break;
    case "Resume":
      output.set(frame.connectionId, cursor);
      cursor += 16;
      output.set(frame.resumeToken, cursor);
      break;
    case "Ping":
    case "Pong":
      view.setBigUint64(cursor, frame.nonce, true);
      cursor += 8;
      view.setBigUint64(cursor, frame.sentUs, true);
      break;
    case "Close":
      view.setUint16(cursor, frame.code, true);
      cursor += 2;
      output.set(textEncoder.encode(frame.reason), cursor);
      break;
    case "Input":
      view.setBigUint64(cursor, frame.inSeq, true);
      cursor += 8;
      output.set(frame.bytes, cursor);
      break;
    case "Output":
      view.setBigUint64(cursor, frame.outSeq, true);
      cursor += 8;
      output.set(frame.bytes, cursor);
      break;
    case "Resize":
      view.setUint16(cursor, frame.cols, true);
      view.setUint16(cursor + 2, frame.rows, true);
      view.setUint16(cursor + 4, frame.pxW, true);
      view.setUint16(cursor + 6, frame.pxH, true);
      break;
    case "Ack":
      view.setBigUint64(cursor, frame.inSeqAcked, true);
      break;
    case "Credit":
      view.setUint32(cursor, frame.bytes, true);
      break;
    case "Snapshot":
      view.setBigUint64(cursor, frame.outSeq, true);
      cursor += 8;
      output.set(frame.bytes, cursor);
      break;
    case "AttachTerm":
      output.set(frame.sessionId, cursor);
      cursor += 16;
      view.setBigUint64(cursor, frame.lastOutSeq, true);
      cursor += 8;
      view.setBigUint64(cursor, frame.lastInSeq, true);
      break;
    case "Call":
      view.setUint32(cursor, frame.callId, true);
      cursor += 4;
      cursor = writeStringAt(frame.actionId, output, cursor);
      output.set(frame.inputJson, cursor);
      break;
    case "Result":
      view.setUint32(cursor, frame.callId, true);
      cursor += 4;
      output[cursor] = frame.ok ? 1 : 0;
      cursor += 1;
      output.set(frame.json, cursor);
      break;
    case "Subscribe":
      view.setUint32(cursor, frame.subId, true);
      output.set(frame.filterJson, cursor + 4);
      break;
    case "Event":
      view.setUint32(cursor, frame.subId, true);
      output.set(frame.eventJson, cursor + 4);
      break;
  }
}

function writeStringAt(value: string, output: Uint8Array, offset: number): number {
  const bytes = textEncoder.encode(value);
  writeVarintAt(bytes.byteLength, output, offset);
  const lengthBytes = varintLength(bytes.byteLength);
  output.set(bytes, offset + lengthBytes);
  return offset + lengthBytes + bytes.byteLength;
}

function measureString(value: string): number {
  const bytesLength = textEncoder.encode(value).byteLength;
  checkedU32(bytesLength, "UTF-8 string length");
  return checkedAdd(varintLength(bytesLength), bytesLength);
}

function stringFieldLength(value: string): number {
  return measureString(value);
}

function readFrameLength(input: Uint8Array, offset: number): Varint {
  const length = readVarint(input, offset);
  if (length.value > MAX_FRAME_LEN) {
    throw decodeError("frame-too-large", `frame length ${length.value} exceeds ${MAX_FRAME_LEN}`);
  }
  return length;
}

function readVarint(input: Uint8Array, offset: number): Varint {
  let value = 0;
  for (let index = 0; index < MAX_VARINT_BYTES; index += 1) {
    const byte = input[offset + index];
    if (byte === undefined) {
      throw decodeError("incomplete", "varint is incomplete");
    }
    const payload = byte & 0x7f;
    if (index === MAX_VARINT_BYTES - 1 && payload > 0x0f) {
      throw decodeError("varint-overflow", "varint exceeds u32");
    }
    value += payload * 2 ** (index * 7);
    if ((byte & 0x80) === 0) {
      const bytesRead = index + 1;
      if (varintLength(value) !== bytesRead) {
        throw decodeError("non-canonical-varint", "varint is not in shortest form");
      }
      return { value, bytesRead };
    }
  }
  throw decodeError("varint-too-long", "varint exceeds five bytes");
}

function varintLength(value: number): number {
  let remaining = value;
  let length = 1;
  while (remaining >= 0x80) {
    length += 1;
    remaining = Math.floor(remaining / 0x80);
  }
  return length;
}

function writeVarintAt(value: number, output: Uint8Array, offset: number): void {
  let remaining = value;
  let cursor = offset;
  while (remaining >= 0x80) {
    output[cursor] = (remaining % 0x80) | 0x80;
    remaining = Math.floor(remaining / 0x80);
    cursor += 1;
  }
  output[cursor] = remaining;
}

function ensureCapacity(output: Uint8Array, offset: number, length: number): void {
  if (!Number.isInteger(offset) || offset < 0 || offset + length > output.byteLength) {
    throw new WireEncodeError("buffer-too-small", "output buffer does not have enough writable bytes");
  }
}

function checkedAdd(left: number, right: number): number {
  const total = left + right;
  if (!Number.isSafeInteger(total)) {
    throw new WireEncodeError("length-overflow", "frame length exceeds the safe integer range");
  }
  return total;
}

function checkedU16(value: number, field: string): number {
  return checkedUnsigned(value, 0xffff, field);
}

function checkedU32(value: number, field: string): number {
  return checkedUnsigned(value, MAX_U32, field);
}

function checkedUnsigned(value: number, max: number, field: string): number {
  if (!Number.isInteger(value) || value < 0 || value > max) {
    throw new WireEncodeError("length-overflow", `${field} must be an unsigned integer no greater than ${max}`);
  }
  return value;
}

function checkedU64(value: bigint, field: string): bigint {
  if (value < 0n || value > MAX_U64) {
    throw new WireEncodeError("length-overflow", `${field} must fit in u64`);
  }
  return value;
}

function requireLength(value: Uint8Array, expected: number, field: string): void {
  if (value.byteLength !== expected) {
    throw new WireEncodeError("length-overflow", `${field} must be exactly ${expected} bytes`);
  }
}

function isIncomplete(error: unknown): boolean {
  return error instanceof WireDecodeError && error.code === "incomplete";
}

function decodeError(code: DecodeErrorCode, message: string): WireDecodeError {
  return new WireDecodeError(code, message);
}
