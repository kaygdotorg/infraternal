/** Pins D255 host/session replay and per-window projection in the provisioning test double. */
import { expect, test } from "bun:test";
import { emitSetup, publishSetup, setupEvents } from "./setup-double";

test("setup replay preserves the published session and projects each subscriber's window", () => {
  const host = "12345678-1234-1234-1234-123456789abc";
  const session = "abcdefab-1234-1234-1234-123456789abc";
  publishSetup(host, session);
  emitSetup(host, "install", "done");
  emitSetup(host, "join", "running");
  expect(setupEvents(host, "window-one", 0).events.every((event) => event.session_id === session && event.window_id === "window-one")).toBe(true);
  expect(setupEvents(host, "window-two", 1).events).toHaveLength(1);
  expect(() => publishSetup(host, session)).toThrow();
  expect(() => setupEvents("missing", "window", 0)).toThrow();
  for (let i = 0; i < 18; i++) emitSetup(host, "join", "running");
  const replay = setupEvents(host, "window-two", 0);
  expect(replay.resync).toBe(true);
  expect(replay.events.map((event) => event.stage)).toEqual(["install", "join"]);
  expect(replay.events.every((event) => event.window_id === "window-two")).toBe(true);
  expect(replay.events[1]?.sequence).toBe(20);
});


test("late setup replay retains a failure reason and retry eligibility", () => {
  const host = "12345678-1234-1234-1234-123456789def";
  const session = "abcdefab-1234-1234-1234-123456789def";
  publishSetup(host, session);
  emitSetup(host, "install", "done");
  emitSetup(host, "join", "failed");
  const event = setupEvents(host, "late-window", 1).events[0];
  expect(event?.state).toBe("failed");
  expect(event?.failed_step).toBe("join");
  expect(event?.message).toBe("Setup needs another try.");
  expect(event?.retry_available).toBe(true);
});
