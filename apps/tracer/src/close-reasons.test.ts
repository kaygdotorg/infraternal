/** Keep socket close reasons readable while retries retain the specific cause. */
import { expect, test } from "bun:test";
import { plainCloseReason } from "./close-reasons";

test("a missed connection response keeps a plain and stable reason", () => {
  expect(plainCloseReason("connection unresponsive")).toBe("Connection closed: the server did not respond in time.");
});

test("server and host close reasons identify why a terminal reconnects", () => {
  expect(plainCloseReason("remote stream unavailable")).toBe("Connection closed: the infraternal agent lost its connection to the server.");
  expect(plainCloseReason("terminal input exceeded the flow-control limit")).toBe("Connection closed: terminal input exceeded its flow-control limit.");
  expect(plainCloseReason("the server could not keep up with connection replies")).toBe("Connection closed: the server could not keep up with connection replies.");
  expect(plainCloseReason("the host could not accept the terminal attachment")).toBe("Connection closed: the host could not accept the terminal attachment.");
  expect(plainCloseReason("the server refused to resume the connection")).toBe("Connection closed: the server refused to resume the connection.");
});

test("server-generated terminal route reasons keep their specific explanation", () => {
  expect(plainCloseReason("the terminal reader fell behind and is reconnecting")).toBe("Connection closed: the terminal reader fell behind and is reconnecting.");
  expect(plainCloseReason("the terminal on the host stopped responding")).toBe("Connection closed: the terminal on the host stopped responding.");
  expect(plainCloseReason("the stream closed repeatedly for different reasons")).toBe("Connection closed: the stream closed repeatedly for different reasons.");
});

test("routine detach and connection rotation reasons stay neutral", () => {
  expect(plainCloseReason("detached")).toBe("This window was detached from its terminal.");
  expect(plainCloseReason("tracer connection rotation")).toBe("The connection is being refreshed.");
});

test("unknown close text is discarded instead of reaching the person or console", () => {
  const originalWarn = console.warn;
  let warned = false;
  console.warn = () => { warned = true; };
  try {
    expect(plainCloseReason("secret terminal text and key material")).toBe("Connection closed: the server did not provide a safe reason.");
    expect(plainCloseReason("constructor")).toBe("Connection closed: the server did not provide a safe reason.");
    expect(plainCloseReason("__proto__")).toBe("Connection closed: the server did not provide a safe reason.");
    expect(warned).toBe(false);
  } finally {
    console.warn = originalWarn;
  }
});
