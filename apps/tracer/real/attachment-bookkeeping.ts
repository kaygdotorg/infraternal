/** Track explicit and server-restored PTY attachments without retaining terminal contents in fixture metadata. */
import type { WireFrame } from "../../../packages/protocol/src/codec";
const decoder = new TextDecoder();

export function recordAttachment(attached: Map<number, string[]>, stream: number, frame: WireFrame): void {
  if (stream === 0) return;
  let session: string | undefined;
  if (frame.type === "AttachTerm") session = Buffer.from(frame.sessionId).toString("hex");
  else if (frame.type === "Event" && frame.eventJson.byteLength <= 1024) {
    try {
      const event = JSON.parse(decoder.decode(frame.eventJson)) as { type?: unknown; session_id?: unknown };
      // A resumed server may restore the stream without a new AttachTerm from the browser.
      if (event.type === "terminal.replay_complete" && typeof event.session_id === "string"
        && /^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$/i.test(event.session_id)) session = event.session_id.replaceAll("-", "").toLowerCase();
    } catch { /* Invalid events establish no attachment; the browser validates them. */ }
  }
  if (session && !attached.get(stream)?.includes(session)) attached.set(stream, [...(attached.get(stream) ?? []), session]);
}
