/** Pins add-host copy to actual authentication and installation evidence (#87). */
import { expect, test } from "bun:test";
import { authLabel, failureDiagnostics, failureLine, guideFor } from "../src/canvas/addhost/model";
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

test("a held setup lock identifies its machine, attempt, process and age", () => {
  const failure = {
    kind: "setup_running",
    message: "Setup is already running on this host.",
    log_tail: [],
    setup_lock: { machine: "build-node", pid: 254, since: "2026-11-02T04:05:06Z", active: true },
  } as unknown as FailureDetail;
  const guide = guideFor("fixture host", failure);
  expect(guide.happened).toBe("Process 254 on build-node has held the setup lock since 2026-11-02T04:05:06Z.");
  // Only an upgrade journal offers a replacement; a running setup is waited for (#305).
  expect(guide.next).toBe("Wait for it to finish, then try again. A setup that stopped releases the lock within 3 minutes.");
  const named = guideFor("fixture host", { ...failure, setup_lock: { ...failure.setup_lock!, attempt: "1a2b3c4d" } } as FailureDetail);
  expect(named.happened).toBe("Setup attempt 1a2b3c4d (process 254) on build-node has held the setup lock since 2026-11-02T04:05:06Z.");
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

test("a stuck-install replacement says its open terminal sessions carry over (#305, D337)", () => {
  const lock = { machine: "build-node", pid: 254, since: "2026-11-02T04:05:06Z", active: false };
  const guide = (sessions: number) => guideFor("fixture host", {
    kind: "stale_previous_attempt", message: "x", log_tail: [], setup_lock: { ...lock, sessions },
  } as unknown as FailureDetail);
  expect(guide(0).next).toBe("No terminal sessions are open on it.");
  expect(guide(1).next).toBe("1 open terminal session will carry over.");
  expect(guide(3).next).toBe("3 open terminal sessions will carry over.");
});

test("a machine enrolled with another server asks to join as a new host (D335)", () => {
  const failure = {
    kind: "stale_previous_attempt",
    message: "x",
    log_tail: [],
    setup_lock: { machine: "code", pid: 254, since: "2026-11-02T04:05:06Z", active: false, sessions: 2, enrolled_with: "monitor01.example" },
  } as unknown as FailureDetail;
  expect(guideFor("code", failure)).toMatchObject({
    title: "code is enrolled with another server",
    happened: "It belongs to monitor01.example. Join it to this server as a new host with a new key. Its old infraternal agent is stopped, and deleted with its key once the machine has joined.",
    next: "2 open terminal sessions will end.",
    fix: "replace-stuck-install",
  });
  const unnamed = { ...failure, setup_lock: { ...failure.setup_lock!, enrolled_with: "" } } as FailureDetail;
  expect(guideFor("code", unnamed).happened).toBe("Join it to this server as a new host with a new key. Its old infraternal agent is stopped, and deleted with its key once the machine has joined.");
});

test("another server's install running with open terminals is refused by name, with no action (D337)", () => {
  const lock = { machine: "code", pid: 254, since: "2026-11-02T04:05:06Z", active: false, sessions: 2, live: true, in_use: true };
  const guide = (setup_lock: object) => guideFor("code", { kind: "stale_previous_attempt", message: "x", log_tail: [], setup_lock } as unknown as FailureDetail);
  expect(guide({ ...lock, enrolled_with: "monitor01.example" })).toMatchObject({
    title: "code is in use by another server",
    happened: "Its infraternal agent is running with 2 open terminals and may still be connected to monitor01.example.",
    next: "Prove you own monitor01.example to take it over. That isn't available yet.",
    fix: "none",
  });
  expect(guide({ ...lock, sessions: 1, enrolled_with: "" }).happened)
    .toBe("Its infraternal agent is running with 1 open terminal and may still be connected to the server that enrolled it.");
});

test("a live install says joining here disconnects it from its server, and an unread one claims no server (#305)", () => {
  const lock = { machine: "code", pid: 254, since: "2026-11-02T04:05:06Z", active: false, sessions: 0 };
  const guide = (setup_lock: object) => guideFor("code", { kind: "stale_previous_attempt", message: "x", log_tail: [], setup_lock } as unknown as FailureDetail);
  expect(guide({ ...lock, enrolled_with: "monitor01.example", live: true }).happened)
    .toStartWith("Its infraternal agent is running and may be connected to monitor01.example now. Joining it here disconnects it from that server; remove it there afterwards.");
  expect(guide({ ...lock, enrolled_with: "" }).title).toBe("code has an install this server did not enroll");
  expect(guide({ ...lock, enrolled_with: "", live: true }).happened).toContain("connected to the server that enrolled it now");
});

test("an install an earlier add-host set aside is offered back, not installed beside (#305)", () => {
  const failure = {
    kind: "stale_previous_attempt",
    message: "x",
    log_tail: [],
    setup_lock: { machine: "code", since: "unknown", active: false, set_aside: true },
  } as unknown as FailureDetail;
  expect(guideFor("code", failure)).toMatchObject({
    title: "code's infraternal agent was set aside",
    happened: "An earlier add-host set it aside and could not put it back. Nothing was deleted.",
    next: "Put it back as it was found, then add the host again to continue.",
    fix: "replace-stuck-install",
  });
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

// #394, owner on production: root add of minipc01 showed the exit-71 paragraph (two explanations, a folder
// chore, "copying didn't finish") on the page and wrapped in red in the progress row.
test("an install this server didn't make is named once, with no chore and no path outside Details", () => {
  const failure = {
    kind: "unrecognized_install",
    failed_step: "connect",
    message: "This machine already has an infraternal agent from an earlier setup, so nothing was changed. If an infraternal server still lists it, remove it there to uninstall it, then add it here again.",
    log_tail: ["Setup location: /var/lib/infraternal"],
  } as const;
  const detail = { ...failure, log_tail: [...failure.log_tail] };
  const guide = guideFor("minipc01", detail);
  expect(guide.title).toBe("minipc01 is set up elsewhere");
  expect(guide.happened).toBe(failure.message);
  for (const text of [guide.title, guide.happened, guide.next, failureLine(detail)]) {
    expect(text).not.toMatch(/\/var\/lib|Check .* folders|didn't finish|ownership or permissions/);
  }
  expect(failureDiagnostics(detail, guide)).toEqual(["Setup location: /var/lib/infraternal"]);
  expect(guide.fix).toBe("retry");
});

test("a login name with no account says so, by name, and offers the two ways forward", () => {
  const failure = { kind: "no_account", message: "This host couldn't find an account with that user name.", log_tail: [] } as const;
  const guide = guideFor("minipc01", { ...failure, log_tail: [] }, false, "kayg");
  expect(guide.title).toBe("minipc01 couldn't find an account named kayg");
  expect(guide.happened).toBe("Use an account that exists there, or add it as root.");
  expect(guideFor("minipc01", { ...failure, log_tail: [] }).title).toBe("minipc01 couldn't find the account used to sign in");
});

test("the progress row's line for every install step is one short phrase, never the server's paragraph", () => {
  for (const failed_step of ["connect", "upload", "install", "join", "start", "readiness"] as const) {
    const line = failureLine({ kind: "install", failed_step, message: "A long server sentence. Check things, then try again.", log_tail: ["The remote setup command returned a failure status."] });
    expect(line.length).toBeLessThan(48);
    expect(line).not.toContain("server sentence");
    expect(line).not.toContain("failure status");
  }
});

// J314 P2-1: the other staging refusals are not "set up elsewhere". Each cause the host named gets its own title,
// and none offers a retry that would only meet the same files.
test("each staging refusal has its own title and no retry", () => {
  const titles = new Set<string>();
  for (const refusal of ["cache", "prepared", "foreign", undefined] as const) {
    const failure: FailureDetail = { kind: "unproven_files", message: "x", log_tail: ["Setup location: /var/lib/infraternal"], ...(refusal ? { refusal } : {}) };
    const guide = guideFor("minipc01", failure);
    expect(guide.title).not.toContain("set up elsewhere");
    expect(guide.title).toContain("minipc01");
    expect(guide.fix).toBe("none");
    expect(guide.tone).toBe("info");
    titles.add(guide.title);
  }
  expect(titles.size).toBe(4);
});

// D359: a root-mode add may take a finished install of another server over. The page offers Take over only when
// the server sent the offer (its old install's id); without it the page stays a plain "try again".
test("an install of another server offers Take over only with the server's offer", () => {
  const base = { kind: "unrecognized_install", failed_step: "connect", message: "This machine already has an infraternal agent from an earlier setup that isn't one of this server's hosts. Take it over to set it up here.", log_tail: ["Setup location: /var/lib/infraternal"] } as const;
  const offered = guideFor("minipc01", { ...base, log_tail: [...base.log_tail], takeover: { install: "c10909d16e8147a3b0f2e5d4c3b2a190", live: true } });
  expect(offered.fix).toBe("take-over");
  expect(offered.tone).toBe("info");
  expect(offered.title).toBe("minipc01 is set up elsewhere");
  expect(guideFor("minipc01", { ...base, log_tail: [...base.log_tail] }).fix).toBe("retry");
});

