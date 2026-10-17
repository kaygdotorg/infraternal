/** Keep socket close reasons readable while retries retain the specific cause. */
import { expect, test } from "bun:test";
import { CloseNotes, plainCloseReason } from "./close-reasons";

test("a missed connection response keeps a plain and stable reason", () => {
  expect(plainCloseReason("connection unresponsive")).toBe("The connection did not respond in time.");
});

test("server and host close reasons identify why a terminal reconnects, in plain words", () => {
  const named = [
    "remote stream unavailable", "input queue full", "terminal route unresponsive", "standby writer unavailable",
    "the infraternal agent ended the terminal stream", "the infraternal agent lost its connection to the server",
    "the host could not accept the terminal attachment", "terminal input exceeded the flow-control limit",
    "the terminal reader fell behind and is reconnecting", "the terminal on the host stopped responding",
    "terminal output credit exceeded its limit", "the server could not keep up with connection replies",
    "a terminal frame exceeded the size limit", "the terminal stream sent an invalid protocol frame",
    "the server refused the terminal attachment", "the server refused to resume the connection",
    "the server stopped receiving connection replies", "the server could not write to the connection",
    "the server could not continue the terminal stream",
  ];
  for (const reason of named) {
    const text = plainCloseReason(reason);
    expect(text).not.toBe("The terminal session ended.");
    expect(text).not.toMatch(/shim|reattach|queue|credit|flow.control|protocol|frame|stream|limit|\bunacknowledged\b|Connection closed:/i);
    expect(text.endsWith(".")).toBe(true);
  }
  expect(plainCloseReason("remote stream unavailable")).toBe("The infraternal agent on the host lost its connection to the server.");
});

test("routine detach and connection rotation reasons stay neutral", () => {
  expect(plainCloseReason("tracer connection rotation")).toBe("The connection is being refreshed.");
});

test("unknown close text is discarded instead of reaching the person or console", () => {
  const originalWarn = console.warn;
  let warned = false;
  console.warn = () => { warned = true; };
  try {
    expect(plainCloseReason("secret terminal text and key material")).toBe("The terminal session ended.");
    expect(plainCloseReason("constructor")).toBe("The terminal session ended.");
    expect(plainCloseReason("__proto__")).toBe("The terminal session ended.");
    expect(warned).toBe(false);
  } finally {
    console.warn = originalWarn;
  }
});

test("a storm of closes prints one line per minute and summarises the rest", () => {
  const notes = new CloseNotes();
  const lines: string[] = [];
  for (let i = 0; i < 512; i++) {
    const line = notes.note(i * 100, 1006, "constructor", i, false);
    if (line) lines.push(line);
  }
  expect(lines).toHaveLength(1);
  expect(lines[0]).toContain("reconnect failed");
  expect(lines[0]).toContain('reason "other"');
  expect(lines[0]).not.toContain("constructor");
  const next = notes.note(60_000, 4000, "connection unresponsive", 3, true);
  expect(next).toContain("511 more closes in the previous 60 s");
  expect(next).toContain('reason "connection unresponsive"');
  expect(next).toContain("code 4000");
});
