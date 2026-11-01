/** Keeps the D312 session-incarnation handshake suffix on its assigned Hello bit. */
import { expect, test } from "bun:test";
import { LAYOUT_SESSION_INCARNATION } from "./connection";

test("layout session incarnation uses Hello capability bit 4", () => {
  expect(LAYOUT_SESSION_INCARNATION).toBe(1n << 4n);
});
