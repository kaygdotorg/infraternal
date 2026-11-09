/** Tests for `linkView`: what a window's connection indicator and stale-screen icon show for each state of its link. */
import { expect, test } from "bun:test";
import { linkView, type LinkInput } from "./link";

/** A link record with every field defaulted; `over` changes what a case needs. */
const link = (over: Partial<NonNullable<LinkInput["binding"]>["link"]> = {}) => ({ everConnected: true, resumedAt: undefined, approximateAt: undefined, staleScreen: false, heldKeys: 0, ...over });
const input = (over: Partial<LinkInput> = {}): LinkInput => ({ binding: { connected: true, link: link() }, ended: false, refusal: undefined, now: 10_000, ...over });

test("a healthy attached window is connected and live", () => {
  expect(linkView(input())).toEqual({ status: "live", state: "connected", held: 0, stale: false });
});

test("the first attach is connecting; a lost link after that is reconnecting, with the keys kept meanwhile", () => {
  expect(linkView(input({ binding: { connected: false, link: link({ everConnected: false }) } }))).toMatchObject({ status: "connecting", state: "connecting", held: 0 });
  expect(linkView(input({ binding: { connected: false, link: link({ heldKeys: 4 }) } }))).toEqual({ status: "connecting", state: "reconnecting", held: 4, stale: false });
});

test("a window with no binding yet is live (nothing is known to be wrong)", () => {
  expect(linkView(input({ binding: undefined })).state).toBe("connected");
});

test("coming back is a moment: resumed for 1.8 s, a rebuilt screen for 3.2 s, then connected again", () => {
  expect(linkView(input({ binding: { connected: true, link: link({ resumedAt: 9_000 }) } })).state).toBe("resumed");
  expect(linkView(input({ binding: { connected: true, link: link({ resumedAt: 8_100 }) } })).state).toBe("connected");
  expect(linkView(input({ binding: { connected: true, link: link({ approximateAt: 7_000, resumedAt: 9_500 }) } })).state).toBe("approximate");
  expect(linkView(input({ binding: { connected: true, link: link({ approximateAt: 6_700, resumedAt: 6_800 }) } })).state).toBe("connected");
});

test("an ended session and a refused shell are offline, each in its own words, and win over the link", () => {
  expect(linkView(input({ ended: true }))).toEqual({ status: "offline", state: "offline", detail: "This session has ended.", held: 0, stale: false });
  expect(linkView(input({ refusal: "build-01 is offline." }))).toEqual({ status: "offline", state: "offline", detail: "build-01 is offline.", held: 0, stale: false });
  expect(linkView(input({ ended: true, binding: { connected: false, link: link({ heldKeys: 9 }) } })).held).toBe(0);
});

test("a screen that may be out of date shows while the link is up, and a lost link or an ended session replaces the question (D309)", () => {
  expect(linkView(input({ binding: { connected: true, link: link({ staleScreen: true }) } })).stale).toBe(true);
  // It rides along with the short moments instead of being swallowed by them.
  expect(linkView(input({ binding: { connected: true, link: link({ staleScreen: true, resumedAt: 9_000 }) } }))).toMatchObject({ state: "resumed", stale: true });
  expect(linkView(input({ binding: { connected: false, link: link({ staleScreen: true }) } })).stale).toBe(false);
  expect(linkView(input({ ended: true, binding: { connected: true, link: link({ staleScreen: true }) } })).stale).toBe(false);
});
