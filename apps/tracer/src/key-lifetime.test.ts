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

// J154 P3-2: the requester chooses the lifetime, so the label must never read shorter than
// the key really lasts. Every leftover unit is shown, down to seconds.
test("key lifetimes are exact and never rounded down", () => {
  expect(keyLifetimeLabel(7_199)).toBe("1 hour, 59 minutes and 59 seconds");
  expect(keyLifetimeLabel(172_799)).toBe("47 hours, 59 minutes and 59 seconds");
  expect(keyLifetimeLabel(3_660)).toBe("1 hour and 1 minute");
  expect(keyLifetimeLabel(2 * 86_400 + 3_600)).toBe("2 days and 1 hour");
  expect(keyLifetimeLabel(3 * 86_400 + 1)).toBe("3 days and 1 second");
});
