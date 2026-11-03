/** D333: the device-approval review states the key lifetime the tap approves. */
import { expect, test } from "bun:test";
import { keyLifetimeLabel } from "./auth";

test("key lifetimes read as hours up to two days, then whole days", () => {
  expect(keyLifetimeLabel(3_600)).toBe("1 hour");
  expect(keyLifetimeLabel(86_400)).toBe("24 hours");
  expect(keyLifetimeLabel(36 * 3_600)).toBe("36 hours");
  expect(keyLifetimeLabel(7 * 86_400)).toBe("7 days");
  expect(keyLifetimeLabel(30 * 86_400)).toBe("30 days");
});
