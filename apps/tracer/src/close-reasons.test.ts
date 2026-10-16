/** Keep socket close reasons readable while retries retain the specific cause. */
import { expect, test } from "bun:test";
import { plainCloseReason } from "./close-reasons";

test("a missed connection response keeps a plain and stable reason", () => {
  expect(plainCloseReason("connection unresponsive")).toBe("The connection did not respond in time.");
});
