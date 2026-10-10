/** Pins add-host copy to actual authentication and installation evidence (#87). */
import { expect, test } from "bun:test";
import { authLabel, guideFor } from "../src/canvas/addhost/model";

test("a user key does not imply that it was saved", () => {
  expect(authLabel({ method: "user-key" })).toBe("your key");
});

test("exhausted sign-in does not invent an available saved key", () => {
  const guide = guideFor("host", { kind: "auth", message: "refused", log_tail: [], choose_method: true });
  expect(guide.happened).not.toContain("saved key");
});

test("a failure before installation does not claim that cleanup is needed", () => {
  const guide = guideFor("host", { kind: "install", message: "SSH helper socket directory is too long", log_tail: [] });
  expect(guide.happened).not.toContain("cleanup");
  expect(guide.next).not.toContain("cleanup");
});
