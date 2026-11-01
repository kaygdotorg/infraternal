/** Explicit requests and authoritative restored-stream events identify the same real attachment. */
import { expect, test } from "bun:test";
import { recordAttachment } from "./attachment-bookkeeping";
const id = "00112233-4455-6677-8899-aabbccddeeff";
const event = (type: string, session_id: string) => ({ type: "Event" as const, subId: 0, eventJson: Buffer.from(JSON.stringify({ type, session_id })) });
test("server-restored streams count without a new client AttachTerm and deduplicate both paths", () => {
  const attached = new Map<number, string[]>();
  recordAttachment(attached, 1, event("terminal.replay_complete", id));
  expect(attached.get(1)).toEqual([id.replaceAll("-", "")]);
  recordAttachment(attached, 1, { type: "AttachTerm", sessionId: Buffer.from(id.replaceAll("-", ""), "hex"), lastInSeq: 0n, lastOutSeq: 0n });
  expect(attached.get(1)).toHaveLength(1);
});
test("control, malformed and unrelated events cannot invent a real attachment", () => {
  const attached = new Map<number, string[]>();
  recordAttachment(attached, 0, event("terminal.replay_complete", id));
  recordAttachment(attached, 1, event("terminal.replay_complete", "invalid"));
  recordAttachment(attached, 1, event("terminal.reconnecting", id));
  recordAttachment(attached, 1, { type: "Event", subId: 0, eventJson: Buffer.from("{") });
  expect(attached.size).toBe(0);
});
