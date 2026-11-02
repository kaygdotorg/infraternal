/** Pins add-host copy to actual authentication and installation evidence (#87). */
import { expect, test } from "bun:test";
import { authLabel, failureDiagnostics, guideFor } from "../src/canvas/addhost/model";
import type { FailureDetail } from "../src/provisioning-client";

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

test("leftovers offer one way forward in plain words, with a neutral tone", () => {
  const guide = guideFor("host", { kind: "stale_previous_attempt", message: "x", log_tail: [] });
  expect(guide.fix).toBe("start-fresh");
  expect(guide.tone).toBe("info");
  expect(guide.title).toBe("This host has leftovers from an earlier setup");
  expect(guide.happened).toBe("infraternal didn't finish setting up here before. Start fresh to remove what it left behind and continue.");
  expect(`${guide.happened} ${guide.next}`).not.toMatch(/cleanup|rollback|restore access|~\//i);
});

test("a setup already running says to wait", () => {
  const guide = guideFor("host", { kind: "setup_running", message: "x", log_tail: [] });
  expect(guide).toMatchObject({ title: "Setup is already running on this host", fix: "retry", tone: "info" });
});

test("a held setup lock identifies its machine, process, age and replacement path", () => {
  const failure = {
    kind: "setup_running",
    message: "Setup is already running on this host.",
    log_tail: [],
    setup_lock: { machine: "build-node", pid: 254, since: "2026-11-02T04:05:06Z", active: true },
  } as unknown as FailureDetail;
  const guide = guideFor("fixture host", failure);
  expect(guide.happened).toBe("Process 254 on build-node holds the setup lock since 2026-11-02T04:05:06Z.");
  expect(guide.next).toContain("replace the stuck install");
});

test("a failed upgrade offers an explicit stuck-install replacement", () => {
  const failure = {
    kind: "stale_previous_attempt",
    message: "An earlier install stopped while replacing this infraternal agent.",
    log_tail: [],
    setup_lock: { machine: "build-node", pid: 254, since: "2026-11-02T04:05:06Z", active: false },
  } as unknown as FailureDetail;
  const guide = guideFor("fixture host", failure);
  expect(guide).toMatchObject({
    title: "A stuck infraternal agent was found on fixture host",
    happened: "The failed install on build-node was last held by process 254 since 2026-11-02T04:05:06Z.",
    fix: "replace-stuck-install",
    tone: "info",
  });
  expect(guide.next).toBe("");
});

test("install advice follows the step that stopped, and never tells people to restore access", () => {
  const steps = ["connect", "upload", "install", "join", "start", "readiness"] as const;
  const advice = steps.map((failed_step) => guideFor("host", { kind: "install", message: "m", log_tail: [], failed_step }).next);
  expect(new Set(advice).size).toBe(steps.length);
  for (const line of advice) expect(line).not.toMatch(/restore access/i);
  expect(guideFor("host", { kind: "install", message: "m", log_tail: [] }).next).toBe("Try again, or open the details to see where it stopped.");
});

test("connect failure says what failed once and does not invent a dropped connection", () => {
  const guide = guideFor("host", { kind: "install", failed_step: "connect", message: "Connecting to the host failed. Check SSH access and the host service, then try again.", log_tail: ["The SSH helper could not start."] });
  expect(guide.happened).toBe("Connecting to the host failed.");
  expect(guide.next).not.toContain("dropped");
  expect(guide.happened).not.toContain("The SSH helper");
});

test("Details keep the diagnostic cause without repeating the summary or next step", () => {
  const failure = { kind: "install", failed_step: "connect", message: "Connecting to the host failed. Check SSH access and the host service, then try again.", log_tail: ["The SSH helper could not start.", "The SSH helper could not start."] } as const;
  const detail = { ...failure, log_tail: [...failure.log_tail] };
  expect(failureDiagnostics(detail, guideFor("host", detail))).toEqual(["The SSH helper could not start."]);
});
