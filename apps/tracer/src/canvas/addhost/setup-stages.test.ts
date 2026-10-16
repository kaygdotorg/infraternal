/** Checks setup-event parsing, stage folding and failure guidance for the machine pill. */
// SPDX-License-Identifier: AGPL-3.0-only
import { describe, expect, test } from "bun:test";
import { foldSetup, freshSetup, parseSetupEvent, setupGuide, stageOfStep, type SetupEvent } from "./setup-stages";

const HOST = "11111111-2222-4333-8444-555555555555";
const ev = (stage: SetupEvent["stage"], state: SetupEvent["state"], extra: Partial<SetupEvent> = {}): SetupEvent => ({ hostId: HOST, stage, state, ...extra });

describe("parseSetupEvent", () => {
  const wire = (setup: Record<string, unknown>): unknown => ({ setup: { host_id: HOST, stage: "join", state: "running", ...setup } });
  test("reads a well-formed event", () => {
    expect(parseSetupEvent(wire({ state: "failed", failed_step: "join", message: "timed out" }))).toEqual({ hostId: HOST, stage: "join", state: "failed", failedStep: "join", message: "timed out" });
  });
  test("drops anything malformed", () => {
    for (const bad of [null, {}, wire({ host_id: "nope" }), wire({ stage: "boot" }), wire({ state: "paused" }), { setup: [] }]) expect(parseSetupEvent(bad)).toBeUndefined();
  });
  test("ignores a failed step on a non-failure and an unknown step on a failure", () => {
    expect(parseSetupEvent(wire({ failed_step: "join" }))?.failedStep).toBeUndefined();
    expect(parseSetupEvent(wire({ state: "failed", failed_step: "reboot" }))?.failedStep).toBeUndefined();
  });
});

describe("foldSetup", () => {
  test("stages before the event's are done, later ones pending", () => {
    expect(foldSetup(freshSetup(), ev("start", "running")).stages).toEqual(["done", "done", "running", "pending"]);
  });
  test("a stage that reports done alone still finishes", () => {
    expect(foldSetup(freshSetup(), ev("install", "done")).stages).toEqual(["done", "pending", "pending", "pending"]);
  });
  test("ready done completes the run", () => {
    const view = foldSetup(foldSetup(freshSetup(), ev("ready", "running")), ev("ready", "done"));
    expect(view.complete).toBe(true);
    expect(view.stages).toEqual(["done", "done", "done", "done"]);
  });
  test("a failure marks the stage its step belongs to, and a retry clears it", () => {
    const failed = foldSetup(foldSetup(freshSetup(), ev("join", "running")), ev("join", "failed", { failedStep: "join", message: "x" }));
    expect(failed.stages).toEqual(["done", "failed", "pending", "pending"]);
    expect(failed.failedStep).toBe("join");
    expect(failed.complete).toBe(false);
    const retried = foldSetup(failed, ev("join", "running"));
    expect(retried.stages).toEqual(["done", "running", "pending", "pending"]);
    expect(retried.failedStep).toBeUndefined();
  });
  test("uploading belongs to install and the readiness check to ready", () => {
    expect(stageOfStep("upload", "join")).toBe("install");
    expect(stageOfStep("readiness", "start")).toBe("ready");
    expect(foldSetup(freshSetup(), ev("start", "failed", { failedStep: "readiness" })).stages).toEqual(["done", "done", "done", "failed"]);
  });
});

describe("setupGuide", () => {
  test("says the terminal keeps working and what to do next, in plain words", () => {
    const guide = setupGuide("o2", foldSetup(freshSetup(), ev("join", "failed", { failedStep: "join" })));
    expect(guide.title).toBe("o2 couldn't join this server");
    expect(guide.effect).toContain("Your terminal keeps working.");
    expect(guide.effect).toContain("Try again in a moment.");
  });
});

// All corpus members are JSON values; none supplies executable coercion hooks.
test("review malformed setup fields are dropped without coercion errors", () => {
  const invalid = JSON.parse('{"toString":null,"valueOf":null}') as unknown;
  for (const fields of [{ state: invalid }, { state: "failed", failed_step: invalid }]) {
    expect(() => parseSetupEvent({ setup: { host_id: HOST, stage: "join", ...fields } })).not.toThrow();
  }
});
