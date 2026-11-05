/** Every stream state says something honest and never leaves a live-looking frozen frame. */
import { expect, test } from "bun:test";
import { controlLine, describe, onConnection, permissionHint, retryable, type StreamState } from "./status";
import { parseStatus } from "./stream";

const ctx = { machine: "studio-mac", app: "Editor", screen: false };

test("a live window keeps its picture and shows nothing over it", () => {
  const v = describe({ kind: "live" }, ctx);
  expect(v).toEqual({ dot: "live", keepPicture: true });
});

test("connecting shows a spinner card and no picture", () => {
  const v = describe({ kind: "connecting" }, ctx);
  expect(v.dot).toBe("connecting");
  expect(v.keepPicture).toBe(false);
  expect(v.card?.mark).toBe("spinner");
  expect(v.card?.title).toBe("Opening Editor");
});

test("paused and reconnecting keep only a dimmed memory and say so in the pill, never in a text strip", () => {
  const paused = describe({ kind: "paused" }, ctx);
  expect(paused.dim).toBe(true);
  expect(paused.mark?.glyph).toBe("paused");
  expect(paused.mark?.tip).toContain("Editor is not drawn");
  expect(paused.keepPicture).toBe(true);
  expect(paused.card).toBeUndefined();
  const re = describe({ kind: "reconnecting" }, ctx);
  expect(re.dot).toBe("connecting");
  expect(re.dim).toBe(true);
  expect(re.keepPicture).toBe(true);
  expect(re.card).toBeUndefined();
  // No state has a text strip over the picture any more.
  expect(Object.keys(paused).concat(Object.keys(re))).not.toContain("strip");
});

test("a closed app, a missing permission, an unsupported browser and a failure each name the cause and the next step", () => {
  expect(describe({ kind: "closed" }, ctx).card).toMatchObject({ title: "Editor was closed", action: { id: "close" } });
  const perm = describe({ kind: "permission", what: "Screen Recording" }, ctx);
  expect(perm.card?.hint).toContain("System Settings, Privacy & Security, Screen Recording");
  expect(perm.card?.action?.id).toBe("retry");
  expect(describe({ kind: "unsupported", reason: "decoder" }, ctx).card?.title).toBe("This browser can't show app windows");
  expect(describe({ kind: "failed", reason: "unreachable" }, ctx).card?.title).toBe("studio-mac can't be reached");
  expect(describe({ kind: "closed" }, { ...ctx, screen: true }).card?.title).toBe("The screen is not available");
});

test("an accessibility hint says the person can still watch", () => {
  expect(permissionHint("Accessibility", "studio-mac")).toContain("You can still watch");
});

test("only a failure or a missing permission can be tried again", () => {
  const all: StreamState[] = [{ kind: "idle" }, { kind: "connecting" }, { kind: "live" }, { kind: "paused" }, { kind: "reconnecting" }, { kind: "closed" }, { kind: "permission", what: "Screen Recording" }, { kind: "unsupported", reason: "codec" }, { kind: "failed", reason: "refused" }];
  expect(all.filter(retryable).map((s) => s.kind)).toEqual(["permission", "failed"]);
});

test("a dropped connection never leaves a window looking live", () => {
  expect(onConnection({ kind: "live" }, false, true)).toEqual({ kind: "reconnecting" });
  expect(onConnection({ kind: "connecting" }, false, false)).toEqual({ kind: "connecting" });
  expect(onConnection({ kind: "reconnecting" }, true, true)).toEqual({ kind: "connecting" });
  expect(onConnection({ kind: "closed" }, true, true)).toEqual({ kind: "closed" });
  expect(onConnection({ kind: "paused" }, false, true)).toEqual({ kind: "paused" });
});

test("the control line is quiet text only when there is something to say", () => {
  expect(controlLine({ kind: "none" }, "m")).toBeUndefined();
  expect(controlLine({ kind: "controlled" }, "m")?.text).toBe("Controlled from infraternal");
  expect(controlLine({ kind: "view-only", why: "rights" }, "m")?.text).toBe("View only");
  expect(controlLine({ kind: "paused", untilMs: 1 }, "studio-mac")?.text).toBe("Paused while someone uses studio-mac");
});

test("the machine's status is read only where it says something, and bounded", () => {
  expect(parseStatus({ state: "capturing" })).toEqual({});
  expect(parseStatus({ state: "gone" })).toEqual({ gone: true });
  expect(parseStatus({ state: "permission_missing", permission: "accessibility" })).toEqual({ permission: "Accessibility" });
  expect(parseStatus({ input: { pause_remaining_ms: 1500 } })).toEqual({ inputPausedMs: 1500 });
  expect(parseStatus({ input: { pause_remaining_ms: 1e9 } })).toEqual({});
  expect(parseStatus("nonsense")).toEqual({});
});
