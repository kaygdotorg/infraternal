import { expect, test } from "bun:test";
import { plainCloseReason } from "../src/close-reasons";

test("every reason the server and the agent send maps to a plain sentence, and unknown ones fall back", () => {
  const sent = ["detached", "attachment ended", "reader fell behind; reattach", "connection closed", "connection ended", "terminal shim disconnected",
    "terminal command queue full; reattach and replay unacknowledged input", "shim lacks restart-safe input capability", "shim refused terminal request"];
  for (const reason of sent) {
    const text = plainCloseReason(reason);
    expect(text).not.toBe("The terminal session ended.");
    expect(text).not.toMatch(/shim|reattach|queue|\bunacknowledged\b/i);
    expect(text.endsWith(".")).toBe(true);
  }
  expect(plainCloseReason("something new")).toBe("The terminal session ended.");
  expect(plainCloseReason("")).toBe("The terminal session ended.");
  expect(plainCloseReason(undefined, "The server closed the connection.")).toBe("The server closed the connection.");
});
