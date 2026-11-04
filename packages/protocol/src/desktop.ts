/** Borrowed binary desktop messages; validation mirrors the Rust codec [D12,D200,D232]. */
/**
 * The Hello capability bit for desktop video on the browser leg (leg A): bit 4 counting from zero, `1 << 4`, the same
 * value as `CAPABILITY` in the Rust protocol crate and "caps bit 4" in contracts/wire.md §9. A browser sets it in its
 * Hello to ask for app-window streams, and reads it from the server's Hello to learn they exist. (The agent's native
 * lane on leg B is a different bit, `1 << 8`, and is not used by a browser.)
 */
export const DESKTOP_VIDEO = 16n;
export const MAX_VIDEO_BYTES = 4 * 1024 * 1024 - 42;
export type VideoInput =
  | { kind: "release" }
  | { kind: "control"; active: boolean }
  | { kind: "text"; scalar: number }
  | { kind: "mouse"; x: number; y: number; button: number; state: number; modifiers: number }
  | { kind: "scroll"; x: number; y: number; dx: number; dy: number; modifiers: number }
  | { kind: "key"; keycode: number; down: boolean; modifiers: number };
export type DesktopMessage =
  | { kind: "attach"; sessionId: Uint8Array; delivery: 0 | 1 }
  | { kind: "video"; sequence: bigint; captureNs: bigint; keyframe: boolean; bytes: Uint8Array }
  | { kind: "size"; width: number; height: number; densityMilli: number }
  | { kind: "input"; input: VideoInput }
  | { kind: "repair"; lastSequence: bigint }
  | { kind: "fragment"; sessionId: Uint8Array; sequence: bigint; captureNs: bigint; keyframe: boolean; total: number; offset: number; bytes: Uint8Array };
const fail = (): never => { throw new RangeError("invalid desktop fields"); };
const integer = (n: number, max: number): boolean => Number.isSafeInteger(n) && n >= 0 && n <= max;
const u64 = (n: bigint): boolean => typeof n === "bigint" && n >= 0n && n <= 0xffff_ffff_ffff_ffffn;
/** Validates before allocating, including nested fields and fragment arithmetic. */
export function measureDesktop(message: DesktopMessage): { tag: number; length: number } {
  switch (message.kind) {
    case "attach":
      if (message.sessionId.length !== 16 || (message.delivery !== 0 && message.delivery !== 1)) fail();
      return { tag: 0x40, length: 17 };
    case "video":
      if (!u64(message.sequence) || message.sequence === 0n || !u64(message.captureNs) || typeof message.keyframe !== "boolean" || message.bytes.length === 0 || message.bytes.length > MAX_VIDEO_BYTES) fail();
      return { tag: 0x41, length: 17 + message.bytes.length };
    case "size":
      if (!integer(message.width, 4096) || !integer(message.height, 4096) || message.width < 2 || message.height < 2 || message.width % 2 || message.height % 2 || message.width * message.height > 4 * 1024 * 1024 || !integer(message.densityMilli, 4000) || message.densityMilli < 1000) fail();
      return { tag: 0x42, length: 6 };
    case "input": {
      const i = message.input;
      if(i.kind === "control") { if (typeof i.active !== "boolean") fail(); return {tag:0x43,length:2}; }
      if(i.kind === "release") return {tag:0x43,length:1};
      if (i.kind === "text") {
        if (!integer(i.scalar, 0x10ffff) || i.scalar < 32 || (i.scalar >= 127 && i.scalar <= 159) || (i.scalar >= 0xd800 && i.scalar <= 0xdfff)) fail();
        return { tag: 0x43, length: 5 };
      }
      if (!integer(i.modifiers, 15)) fail();
      if (i.kind === "key") {
        if (!integer(i.keycode, 127) || typeof i.down !== "boolean") fail();
        return { tag: 0x43, length: 5 };
      }
      if (!integer(i.x, 1_000_000) || !integer(i.y, 1_000_000)) fail();
      if (i.kind === "mouse") {
        if (!integer(i.button, 2) || !integer(i.state, 2)) fail();
        return { tag: 0x43, length: 12 };
      }
      if (i.kind !== "scroll") fail();
      if (!Number.isInteger(i.dx) || i.dx < -2147483648 || i.dx > 2147483647 || !Number.isInteger(i.dy) || i.dy < -2147483648 || i.dy > 2147483647) fail();
      return { tag: 0x43, length: 18 };
    }
    case "repair":
      if (!u64(message.lastSequence)) fail();
      return { tag: 0x44, length: 8 };
    case "fragment":
      if (message.sessionId.length !== 16 || !u64(message.sequence) || message.sequence === 0n || !u64(message.captureNs) || typeof message.keyframe !== "boolean" || !integer(message.total, MAX_VIDEO_BYTES) || message.total === 0 || !integer(message.offset, message.total) || message.bytes.length === 0 || message.offset % 1024 !== 0 || message.offset >= message.total || message.bytes.length !== Math.min(1024, message.total - message.offset)) fail();
      return { tag: 0x45, length: 41 + message.bytes.length };
  }
}
/** Writes to the outer codec's already-sized reusable output buffer. */
export function writeDesktop(m: DesktopMessage, output: Uint8Array, cursor: number): void {
  const v = new DataView(output.buffer, output.byteOffset, output.byteLength);
  switch (m.kind) {
    case "attach": output.set(m.sessionId, cursor); output[cursor+16] = m.delivery; break;
    case "video": v.setBigUint64(cursor, m.sequence, true); v.setBigUint64(cursor+8, m.captureNs, true); output[cursor+16] = Number(m.keyframe); output.set(m.bytes, cursor+17); break;
    case "size": v.setUint16(cursor, m.width, true); v.setUint16(cursor+2, m.height, true); v.setUint16(cursor+4, m.densityMilli, true); break;
    case "input": {
      const i = m.input;
      if(i.kind === "control") { output[cursor]=5; output[cursor+1]=Number(i.active); break; }
      if(i.kind === "release") {output[cursor]=3;break;}
      if (i.kind === "text") { output[cursor] = 4; v.setUint32(cursor+1, i.scalar, true); break; }
      if (i.kind === "key") { output[cursor] = 2; v.setUint16(cursor+1, i.keycode, true); output[cursor+3] = Number(i.down); output[cursor+4] = i.modifiers; }
      else {
        output[cursor] = i.kind === "mouse" ? 0 : 1;
        v.setUint32(cursor+1, i.x, true); v.setUint32(cursor+5, i.y, true);
        if (i.kind === "mouse") { output[cursor+9] = i.button; output[cursor+10] = i.state; output[cursor+11] = i.modifiers; }
        else { v.setInt32(cursor+9, i.dx, true); v.setInt32(cursor+13, i.dy, true); output[cursor+17] = i.modifiers; }
      }
      break;
    }
    case "repair": v.setBigUint64(cursor, m.lastSequence, true); break;
    case "fragment": output.set(m.sessionId, cursor); v.setBigUint64(cursor+16, m.sequence, true); v.setBigUint64(cursor+24, m.captureNs, true); output[cursor+32] = Number(m.keyframe); v.setUint32(cursor+33, m.total, true); v.setUint32(cursor+37, m.offset, true); output.set(m.bytes, cursor+41); break;
  }
}
/** Reads only bounded fixed fields and borrowed views, then validates all semantic limits. */
export function decodeDesktop(tag: number, body: Uint8Array): DesktopMessage {
  const v = new DataView(body.buffer, body.byteOffset, body.byteLength);
  const exact = (length: number): void => { if (body.length !== length) fail(); };
  const flag = (offset: number): boolean => { if (body[offset] !== 0 && body[offset] !== 1) fail(); return body[offset] === 1; };
  let m: DesktopMessage;
  switch (tag) {
    case 0x40: exact(17); m = { kind: "attach", sessionId: body.subarray(0,16), delivery: body[16] as 0|1 }; break;
    case 0x41: m = {kind:"video",sequence:v.getBigUint64(0,true),captureNs:v.getBigUint64(8,true),keyframe:flag(16),bytes:body.subarray(17)}; break;
    case 0x42: exact(6); m = {kind:"size",width:v.getUint16(0,true),height:v.getUint16(2,true),densityMilli:v.getUint16(4,true)}; break;
    case 0x43: {
      let input: VideoInput;
      switch(body[0]) {
        case 0: exact(12); input={kind:"mouse",x:v.getUint32(1,true),y:v.getUint32(5,true),button:body[9]!,state:body[10]!,modifiers:body[11]!}; break;
        case 1: exact(18); input={kind:"scroll",x:v.getUint32(1,true),y:v.getUint32(5,true),dx:v.getInt32(9,true),dy:v.getInt32(13,true),modifiers:body[17]!}; break;
        case 2: exact(5); input={kind:"key",keycode:v.getUint16(1,true),down:flag(3),modifiers:body[4]!}; break;
        case 5: exact(2); input={kind:"control",active:flag(1)}; break;
        case 4: exact(5); input={kind:"text",scalar:v.getUint32(1,true)}; break;
        case 3: exact(1); input={kind:"release"}; break;
        default: return fail();
      }
      m={kind:"input",input}; break;
    }
    case 0x44: exact(8); m={kind:"repair",lastSequence:v.getBigUint64(0,true)}; break;
    case 0x45: m={kind:"fragment",sessionId:body.subarray(0,16),sequence:v.getBigUint64(16,true),captureNs:v.getBigUint64(24,true),keyframe:flag(32),total:v.getUint32(33,true),offset:v.getUint32(37,true),bytes:body.subarray(41)}; break;
    default: return fail();
  }
  measureDesktop(m);
  return m;
}
