/** Action refusals retain validated resource counters while legacy and malformed replies remain safe. */
import { expect, test } from "bun:test";
import { ActionRefused, MuxConnection } from "../../connection";
import type { WireFrame } from "../../../../../packages/protocol/src/codec";

async function refusal(body: unknown): Promise<ActionRefused> {
  const connection = new MuxConnection();
  const pending = connection.call("ssh.session.open", {}).catch((error: unknown) => error);
  (connection as unknown as { control(frame: WireFrame): void }).control({ type: "Result", callId: 1, ok: false, json: new TextEncoder().encode(JSON.stringify(body)) });
  const error = await pending;
  expect(error).toBeInstanceOf(ActionRefused);
  return error as ActionRefused;
}

test("memory refusal retains the reason and current counters", async () => {
  const error = await refusal({ error: "terminal unavailable", reason: "host_memory_low", available_mib: 180, session_count: 212 });
  expect(error.reason).toBe("host_memory_low");
  expect((error as unknown as { memory: unknown }).memory).toEqual({ availableMiB: 180, sessionCount: 212 });
});

test("legacy refusals still work and malformed counters never reach the message", async () => {
  expect((await refusal({ error: "forbidden" })).reason).toBe("forbidden");
  for (const available of [-1, 1.5, "180", Number.MAX_SAFE_INTEGER + 1]) {
    const error = await refusal({ reason: "host_memory_low", available_mib: available, session_count: 212 });
    expect((error as unknown as { memory?: unknown }).memory).toBeUndefined();
  }
  const missing = await refusal({ reason: "host_memory_low", available_mib: 180 });
  expect((missing as unknown as { memory?: unknown }).memory).toBeUndefined();
});

test("product copy names the host and counters and never renders untrusted server text", async () => {
  const { terminalRefusal } = await import("../../terminal-refusal");
  expect(terminalRefusal(new ActionRefused(undefined, "unavailable"), "code")).toEqual({
    message: "code is offline or cannot reach this server. Check its network, then try again.", sessionList: false, action: "retry",
  });
  expect(terminalRefusal(await refusal({ reason: "host_memory_low", available_mib: 180, session_count: 212 }), "monitor01")).toEqual({
    message: "monitor01 is low on memory (180 MiB free, 212 sessions running). Close sessions you no longer need.", sessionList: true, action: "sessions",
  });
  expect(terminalRefusal(new ActionRefused(undefined, "internal input: do not render"), "monitor01")).toEqual({
    message: "The server could not open this terminal. Try again.", sessionList: false, action: "retry",
  });
  expect(terminalRefusal(new ActionRefused(undefined, "invalid")).sessionList).toBe(false);
});

test("a rootless server says why it cannot open a shell and what to do (#327)", async () => {
  const { terminalRefusal } = await import("../../terminal-refusal");
  const permission = terminalRefusal(await refusal({ error: "terminal unavailable", reason: "permission" }), "test");
  const noLogin = terminalRefusal(await refusal({ error: "terminal unavailable", reason: "no_login" }), "test");
  expect(permission).toEqual({
    message: "This server runs without root, so it can only open shells as its own user. Add a host to work elsewhere.",
    sessionList: false, action: "add-host",
  });
  expect(noLogin).toEqual({
    message: "This server runs without root, so it can only open shells as its own user. Add a host to work elsewhere.",
    sessionList: false, action: "add-host",
  });
  // A genuinely malformed request keeps its own wording.
  expect(terminalRefusal(await refusal({ reason: "invalid" })).message).toBe("This terminal request is not valid. Try opening a new window.");
});

test("a root host without systemd says why it opens no logins and what works instead (D354)", async () => {
  const { terminalRefusal } = await import("../../terminal-refusal");
  expect(terminalRefusal(await refusal({ error: "terminal unavailable", reason: "no_systemd" }), "build-01")).toEqual({
    message: "build-01 has no systemd, so infraternal can't open logins there as root. Reinstall infraternal there without root, or add a host with systemd.",
    sessionList: false, action: "add-host",
  });
});

test("a host too busy to start a shell says so and offers to try again", async () => {
  const { terminalRefusal } = await import("../../terminal-refusal");
  expect(terminalRefusal(await refusal({ error: "terminal unavailable", reason: "probe_timeout" }), "build-01")).toEqual({
    message: "build-01 was too busy to start a shell just now. Try again in a moment.", sessionList: false, action: "retry",
  });
});

test("a denied account is told so, with nothing to retry", async () => {
  const { terminalRefusal } = await import("../../terminal-refusal");
  for (const reason of ["forbidden", "denied"]) {
    expect(terminalRefusal(new ActionRefused(undefined, reason), "build-01")).toEqual({
      message: "You do not have access to build-01. Ask an admin for access.", sessionList: false, action: "none",
    });
  }
});

test("oversized refusal JSON is ignored before parsing", async () => {
  expect((await refusal({ reason: "host_memory_low", available_mib: 180, session_count: 212, extra: "x".repeat(32768) })).reason).toBeUndefined();
});
