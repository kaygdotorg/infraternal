/** Exercises retained setup delivery, replay, retry and subscription cleanup without a live socket. */
// SPDX-License-Identifier: AGPL-3.0-only
import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { createSetupFeed } from "./setup-feed";
import type { SetupEvent } from "./setup-stages";

const HOST = "11111111-2222-4333-8444-555555555555";

/** A socket the test drives by hand. */
class FakeSocket {
  static all: FakeSocket[] = [];
  readyState = 0;
  sent: Array<Record<string, unknown>> = [];
  onopen?: () => void; onmessage?: (m: { data: unknown }) => void; onclose?: () => void;
  constructor(readonly url: string) { FakeSocket.all.push(this); }
  send(text: string): void { this.sent.push(JSON.parse(text) as Record<string, unknown>); }
  close(): void { this.readyState = 3; }
  open(): void { this.readyState = 1; this.onopen?.(); }
  say(value: unknown): void { this.onmessage?.({ data: JSON.stringify(value) }); }
  drop(): void { this.readyState = 3; this.onclose?.(); }
}
const wire = (sequence: number, stage: string, state: string, extra: Record<string, unknown> = {}) => ({ setup: { host_id: HOST, session_id: "s", window_id: "w", attempt: 1, sequence, stage, state, ...extra } });

const saved = { window: (globalThis as { window?: unknown }).window, location: (globalThis as { location?: unknown }).location };
beforeEach(() => {
  FakeSocket.all = [];
  Object.assign(globalThis, { window: globalThis, location: { protocol: "https:", host: "example.test" } });
});
afterEach(() => { Object.assign(globalThis, saved); });

const feed = () => createSetupFeed({ windowId: "w1", open: (url) => new FakeSocket(url) as unknown as WebSocket, backoff: [1, 1] });

describe("createSetupFeed", () => {
  test("subscribes with the host and window, then hands over events in order", () => {
    const got: SetupEvent[] = [];
    feed().subscribe(HOST, (e) => got.push(e));
    const socket = FakeSocket.all[0]!;
    expect(socket.url).toBe("wss://example.test/v1/bootstrap/setup/ws");
    socket.open();
    expect(socket.sent).toEqual([{ action: "subscribe", host_id: HOST, window_id: "w1", after: 0 }]);
    socket.say(wire(1, "install", "done"));
    socket.say(wire(2, "join", "failed", { failed_step: "join", message: "timed out" }));
    socket.say({ setup: { host_id: "someone-else" } });
    expect(got.map((e) => `${e.stage}:${e.state}`)).toEqual(["install:done", "join:failed"]);
    expect(got[1]!.failedStep).toBe("join");
  });

  test("a failure after the prompt, and a retry on the same socket", () => {
    const got: SetupEvent[] = [];
    const source = feed();
    source.subscribe(HOST, (e) => got.push(e));
    const socket = FakeSocket.all[0]!;
    socket.open();
    socket.say(wire(1, "join", "failed", { failed_step: "join" }));
    source.retry?.(HOST);
    expect(socket.sent.at(-1)).toEqual({ action: "retry", host_id: HOST });
    socket.say(wire(3, "join", "running"));
    socket.say(wire(4, "ready", "done"));
    expect(got.at(-1)).toMatchObject({ stage: "ready", state: "done" });
    // The stream ends with the setup: the socket is closed.
    expect(socket.readyState).toBe(3);
  });

  test("a dropped socket resumes after the last sequence and repeats nothing", async () => {
    const got: SetupEvent[] = [];
    feed().subscribe(HOST, (e) => got.push(e));
    FakeSocket.all[0]!.open();
    FakeSocket.all[0]!.say(wire(1, "install", "done"));
    FakeSocket.all[0]!.say(wire(2, "join", "running"));
    FakeSocket.all[0]!.drop();
    await new Promise((resolve) => setTimeout(resolve, 20));
    const again = FakeSocket.all[1]!;
    again.open();
    expect(again.sent[0]).toMatchObject({ action: "subscribe", after: 2 });
    again.say(wire(2, "join", "running"));
    again.say(wire(3, "join", "done"));
    expect(got.map((e) => e.sequence)).toEqual([1, 2, 3]);
  });

  test("a retry asked while offline is sent when the socket is back", async () => {
    const source = feed();
    source.subscribe(HOST, () => undefined);
    FakeSocket.all[0]!.open();
    FakeSocket.all[0]!.drop();
    source.retry?.(HOST);
    await new Promise((resolve) => setTimeout(resolve, 20));
    FakeSocket.all[1]!.open();
    expect(FakeSocket.all[1]!.sent.map((m) => m.action)).toEqual(["subscribe", "retry"]);
  });

  test("a resync resets the view; an error before any event reports the status lost, after one it is ignored", () => {
    const log: string[] = [];
    feed().subscribe(HOST, (e) => log.push(`${e.stage}:${e.state}`), { reset: () => log.push("reset"), lost: () => log.push("lost") });
    const socket = FakeSocket.all[0]!;
    socket.open();
    socket.say({ resync: true, host_id: HOST, window_id: "w1" });
    socket.say(wire(5, "start", "running"));
    socket.say({ error: "retry refused" });
    expect(log).toEqual(["reset", "start:running"]);

    const quiet: string[] = [];
    feed().subscribe(HOST, () => undefined, { lost: () => quiet.push("lost") });
    FakeSocket.all[1]!.open();
    FakeSocket.all[1]!.say({ error: "The host setup status is unavailable." });
    expect(quiet).toEqual(["lost"]);
  });

  test("gives up after the backoff is spent, and a release closes the socket", async () => {
    const lost: string[] = [];
    feed().subscribe(HOST, () => undefined, { lost: () => lost.push("lost") });
    for (let i = 0; i < 3; i++) { await new Promise((resolve) => setTimeout(resolve, 15)); FakeSocket.all[i]!.drop(); }
    expect(lost).toEqual(["lost"]);

    const stop = feed().subscribe(HOST, () => undefined);
    const socket = FakeSocket.all.at(-1)!;
    socket.open();
    stop();
    expect(socket.readyState).toBe(3);
  });
});

// A transport open is not evidence that a retained subscription can deliver.
test("review reconnect budget survives sockets that open then close without events", async () => {
  const lost: string[] = [];
  const stop = feed().subscribe(HOST, () => undefined, { lost: () => lost.push("lost") });
  try {
    for (let i = 0; i < 3; i++) {
      const socket = FakeSocket.all[i]!;
      socket.open();
      socket.drop();
      await new Promise((resolve) => setTimeout(resolve, 15));
    }
    expect(lost).toEqual(["lost"]);
    expect(FakeSocket.all).toHaveLength(3);
  } finally { stop(); }
});

// Automatic reconnects remain bounded; a person's eligible retry must still recover delivery.
test("review explicit retry resumes after the setup feed stops", async () => {
  const lost: string[] = [];
  const source = feed();
  const stop = source.subscribe(HOST, () => undefined, { lost: () => lost.push("lost") });
  try {
    FakeSocket.all[0]!.open();
    FakeSocket.all[0]!.say(wire(1, "join", "failed", { failed_step: "join", retry_available: true }));
    for (let i = 0; i < 3; i++) {
      FakeSocket.all[i]!.drop();
      await new Promise((resolve) => setTimeout(resolve, 15));
    }
    expect(lost).toEqual(["lost"]);
    source.retry?.(HOST);
    expect(FakeSocket.all).toHaveLength(4);
    FakeSocket.all[3]!.open();
    expect(FakeSocket.all[3]!.sent.map((message) => message.action)).toEqual(["subscribe", "retry"]);
  } finally { stop(); }
});
