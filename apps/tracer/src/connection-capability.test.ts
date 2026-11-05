/**
 * The browser negotiates app windows with the protocol package's desktop-video capability bit, not a second copy of it
 * (#146). `packages/protocol/src/desktop-capability.test.ts` holds that bit equal to the Rust server's; this holds the
 * tracer's constant equal to the package's, so the Hello, the server's reply and the Rust side all name one bit.
 */
import { expect, test } from "bun:test";
import { DESKTOP_VIDEO } from "../../../packages/protocol/src/desktop";
import { DESKTOP_VIDEO_CAP } from "./connection";

test("the tracer's desktop-video capability is the protocol package's bit", () => {
  expect(DESKTOP_VIDEO_CAP).toBe(DESKTOP_VIDEO);
  expect(DESKTOP_VIDEO_CAP).toBe(16n);
});
