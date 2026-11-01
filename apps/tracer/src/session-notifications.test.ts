/** Cross-tab notifications accelerate teardown but cannot turn notification failure into a failed logout (D312). */
import { expect, test } from "bun:test";
import { sessionNotifications } from "./account-lifetime";
test("notifications validate account/lifetime messages and dispose callbacks", () => {
  const original = globalThis.BroadcastChannel;
  let channel: Fake;
  class Fake {
    onmessage: ((event: { data: unknown }) => void) | null = null;
    sent: unknown[] = []; closed = false;
    constructor() { channel = this; }
    postMessage(value: unknown) { this.sent.push(value); }
    close() { this.closed = true; }
  }
  globalThis.BroadcastChannel = Fake as unknown as typeof BroadcastChannel;
  try {
    const received: unknown[] = [], notices = sessionNotifications((account, before) => received.push([account, before]));
    for (const data of [null, {}, { type: "forget", account: 1, before: 1 }, { type: "forget", account: "a", before: NaN }]) channel!.onmessage?.({ data });
    expect(received).toEqual([]);
    channel!.onmessage?.({ data: { type: "forget", account: "a", before: 123 } }); expect(received).toEqual([["a", 123]]);
    notices.forget("a"); expect(channel!.sent).toHaveLength(1);
    notices.dispose(); expect(channel!.closed).toBe(true); expect(channel!.onmessage).toBeNull();
    notices.forget("a"); expect(channel!.sent).toHaveLength(1);
  } finally { globalThis.BroadcastChannel = original; }
});
test("missing or failed notification channels do not prevent confirmed local teardown", () => {
  const original = globalThis.BroadcastChannel;
  try {
    globalThis.BroadcastChannel = class { constructor() { throw Error("unavailable"); } } as unknown as typeof BroadcastChannel;
    const missing = sessionNotifications(() => {}); expect(() => missing.forget("a")).not.toThrow(); missing.dispose();
    globalThis.BroadcastChannel = class { postMessage() { throw Error("suspended"); } close() {} } as unknown as typeof BroadcastChannel;
    const failed = sessionNotifications(() => {}); expect(() => failed.forget("a")).not.toThrow(); failed.dispose();
  } finally { globalThis.BroadcastChannel = original; }
});
