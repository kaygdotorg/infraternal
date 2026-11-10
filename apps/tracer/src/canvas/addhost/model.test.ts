/** Tests bounded SSH target parsing and the progress model used by the add-host flow. */
// SPDX-License-Identifier: AGPL-3.0-only
import { describe, expect, test } from "bun:test";
import { awaitingFresh, foldEvent, pendingTarget, type BootstrapEvent, type FailureKind } from "../../provisioning-client";
import { authLabel, failureDiagnostics, failureLine, guideFor, looksLikeSshConfig, matchListed, parseSshConfig, parseTarget, stagesOf } from "./model";

const event = (step: BootstrapEvent["step"], extra: Partial<BootstrapEvent> = {}): BootstrapEvent => ({ sequence: 1, target: "h", attempt: 1, step, message: `${step} message`, elapsed_ms: 1, log_tail: [], ...extra });
const fold = (...events: BootstrapEvent[]) => events.reduce(foldEvent, pendingTarget());
const states = (...events: BootstrapEvent[]) => stagesOf(fold(...events)).map((stage) => stage.state);

describe("stagesOf", () => {
  test("a host with no event is waiting everywhere", () => {
    expect(states()).toEqual(["pending", "pending", "pending", "pending", "pending"]);
  });

  test("check before sign-in is detecting how to sign in", () => {
    expect(states(event("check"))).toEqual(["running", "pending", "pending", "pending", "pending"]);
  });

  test("the sign-in report finishes detect and starts the system check", () => {
    const view = fold(event("check"), event("check", { authentication: { method: "network", network: "netbird" } }));
    const stages = stagesOf(view);
    expect(stages.map((stage) => stage.state)).toEqual(["done", "running", "pending", "pending", "pending"]);
    expect(stages[0]!.detail).toBe("Signed in with network access (NetBird)");
  });

  test("install, facts and connect map to install, enrol and first session", () => {
    const auth = event("check", { authentication: { method: "server-key" } });
    expect(states(auth, event("install"))).toEqual(["done", "done", "running", "pending", "pending"]);
    expect(states(auth, event("install"), event("facts"))).toEqual(["done", "done", "done", "running", "pending"]);
    expect(states(auth, event("install"), event("facts"), event("connect"))).toEqual(["done", "done", "done", "done", "running"]);
    expect(states(auth, event("done"))).toEqual(["done", "done", "done", "done", "done"]);
  });

  test("an auth failure before sign-in fails detect and says it in plain words, not the server's", () => {
    const failure = { kind: "auth" as const, message: "No sign-in method was accepted.", log_tail: [], choose_method: true };
    const stages = stagesOf(fold(event("check"), event("failed", { message: failure.message, failure })));
    expect(stages.map((stage) => stage.state)).toEqual(["failed", "pending", "pending", "pending", "pending"]);
    expect(stages[0]!.detail).toBe("Couldn't sign in to this host");
    expect(JSON.stringify(stages)).not.toContain("No sign-in method was accepted");
  });

  test("an unsupported host fails the system check, after sign-in", () => {
    const failure = { kind: "unsupported" as const, message: "No user systemd.", log_tail: [] };
    const states2 = states(event("check", { authentication: { method: "server-key" } }), event("failed", { failure }));
    expect(states2).toEqual(["done", "failed", "pending", "pending", "pending"]);
  });

  test("an install failure fails the install stage and keeps the earlier ones done", () => {
    const failure = { kind: "install" as const, message: "Rolled back.", log_tail: [] };
    expect(states(event("check", { authentication: { method: "password" } }), event("install"), event("failed", { failure }))).toEqual(["done", "done", "failed", "pending", "pending"]);
  });

  test("a new attempt starts over and forgets the old sign-in", () => {
    const first = fold(event("check", { authentication: { method: "password" } }), event("failed", { failure: { kind: "install", message: "x", log_tail: [] } }));
    const second = foldEvent(first, event("check", { attempt: 2, sequence: 5 }));
    expect(second.authentication).toBeUndefined();
    expect(stagesOf(second).map((stage) => stage.state)).toEqual(["running", "pending", "pending", "pending", "pending"]);
  });
});

describe("authLabel", () => {
  test("names the method and a trusted network provider only", () => {
    expect(authLabel({ method: "network" })).toBe("network access");
    expect(authLabel({ method: "network", network: "tailscale" })).toBe("network access (Tailscale)");
    expect(authLabel({ method: "server-key" })).toBe("this server's key");
    expect(authLabel({ method: "user-key" })).toBe("your key");
    expect(authLabel({ method: "password" })).toBe("your password");
  });
});

describe("guideFor", () => {
  test("installation failures never claim that incomplete cleanup succeeded", () => {
    const guide = guideFor("fixture", { kind: "install", message: "cleanup pending", log_tail: [] });
    expect(guide.happened).not.toContain("cleanup");
    expect(guide.happened).not.toContain("nothing is left half done");
    expect(guide.next).not.toContain("cleanup");
    expect(guide.fix).toBe("retry");
  });

  test("each failure kind names its fix", () => {
    const f = (kind: FailureKind, extra = {}) => guideFor("h", { kind, message: "m", log_tail: [], ...extra });
    expect(f("unreachable").fix).toBe("install-command");
    expect(f("mesh-policy").fix).toBe("retry");
    expect(f("host-key", { fingerprints: ["SHA256:abc"] }).fix).toBe("host-key");
    expect(f("host-key").fix).toBe("retry");
    expect(f("auth", { choose_method: true }).fix).toBe("choose-method");
    expect(f("unsupported").fix).toBe("none");
    expect(f("install").fix).toBe("retry");
  });

  test("mesh-policy words say possible, not certain", () => {
    expect(guideFor("pve01", { kind: "mesh-policy", message: "m", log_tail: [] }).happened).toContain("A network access rule may be blocking it");
  });
});

describe("parseTarget", () => {
  test("reads user, host and port", () => {
    expect(parseTarget("kayg@o1.example:2222")).toEqual({ user: "kayg", host: "o1.example", port: 2222 });
    expect(parseTarget("o1")).toEqual({ user: undefined, host: "o1", port: undefined });
    expect(parseTarget("root@[fe80::1]:22")?.host).toBe("[fe80::1]");
  });
  test("reads a pasted ssh command into the same fields", () => {
    expect(parseTarget("ssh user@1.2.3.4")).toEqual({ user: "user", host: "1.2.3.4", port: undefined });
    expect(parseTarget("  ssh   user@host  ")).toEqual({ user: "user", host: "host", port: undefined });
    expect(parseTarget("ssh -p 2222 user@host")).toEqual({ user: "user", host: "host", port: 2222 });
    expect(parseTarget("ssh -p2222 host")).toEqual({ user: undefined, host: "host", port: 2222 });
    expect(parseTarget("ssh -l ops -p 22 host")).toEqual({ user: "ops", host: "host", port: 22 });
    expect(parseTarget("ssh user@host:2200")).toEqual({ user: "user", host: "host", port: 2200 });
  });
  test("reads an ssh:// address", () => {
    expect(parseTarget("ssh://user@host:2222")).toEqual({ user: "user", host: "host", port: 2222 });
    expect(parseTarget("ssh://host/")).toEqual({ user: undefined, host: "host", port: undefined });
    expect(parseTarget("SSH://root@[fe80::1]:22")).toEqual({ user: "root", host: "[fe80::1]", port: 22 });
  });
  test("refuses garbage around an ssh command", () => {
    expect(parseTarget("ssh -p")).toBeUndefined();
    expect(parseTarget("ssh -p 2222")).toBeUndefined();
    expect(parseTarget("ssh -p abc host")).toBeUndefined();
    expect(parseTarget("ssh -p 99999 host")).toBeUndefined();
    expect(parseTarget("ssh -oProxyCommand=x host")).toBeUndefined();
    expect(parseTarget("ssh -p 22 host:2200")).toBeUndefined();
    expect(parseTarget("ssh user@host ls -la")).toBeUndefined();
    expect(parseTarget("ssh a@b c@d")).toBeUndefined();
    expect(parseTarget("ssh://")).toBeUndefined();
    expect(parseTarget("ssh://host/path")).toBeUndefined();
    expect(parseTarget("http://host")).toBeUndefined();
    expect(parseTarget("sshfoo user@host")).toBeUndefined();
  });
  test("refuses what cannot name a host", () => {
    expect(parseTarget("two words")).toBeUndefined();
    expect(parseTarget("host:99999")).toBeUndefined();
    expect(parseTarget("-oProxyCommand=x")).toBeUndefined();
    expect(parseTarget("")).toBeUndefined();
  });
});

describe("parseSshConfig", () => {
  const config = `
# my hosts
Host build
  HostName 10.0.0.5
  User ops
  Port 2200
Host *.internal !secret
  User nobody
Host web db
  User deploy
Match host x
  User skip
Host alias-only
Host bad name!
  HostName "weird host"
`;
  test("reads aliases with HostName, User and Port, skipping wildcards and Match", () => {
    expect(parseSshConfig(config)).toEqual(["ops@10.0.0.5:2200", "deploy@web", "deploy@db", "alias-only"]);
  });
  test("recognises config text", () => {
    expect(looksLikeSshConfig(config)).toBe(true);
    expect(looksLikeSshConfig("kayg@o1")).toBe(false);
  });
  test("a hostname that is an option is dropped", () => {
    expect(parseSshConfig("Host x\n  HostName -oProxyCommand=evil")).toEqual([]);
  });
});

describe("plain words", () => {
  test("an unknown or missing failure gets the generic sentence, never the server's text", () => {
    const generic = "Something went wrong while setting up this host. Try again.";
    expect(failureLine(undefined)).toBe(generic);
    expect(failureLine({ kind: "teapot" as never, message: "HTTP 418 ssh_exit_255", log_tail: [] })).toBe(generic);
    expect(guideFor("h", undefined).happened).not.toMatch(/ssh|HTTP|exit/i);
  });
  test("no headline carries an arrow, an id or an API noun", () => {
    for (const kind of ["unreachable", "mesh-policy", "host-key", "auth", "unsupported", "install"] as const) {
      const guide = guideFor("web", { kind, message: "m", log_tail: [] });
      for (const text of [guide.title, guide.happened, guide.next, failureLine({ kind, message: "m", log_tail: [] })]) expect(text).not.toMatch(/→|·|\bSSH\b|TCP|mesh policy|enum|\bAPI\b/);
    }
  });
});


test("only a completed canonical host identity becomes terminal authority", () => {
  const id = "11111111-2222-3333-4444-555555555555";
  expect((fold(event("done", { host_id: id } as Partial<BootstrapEvent>)) as { hostId?: string }).hostId).toBe(id);
  expect((fold(event("connect", { host_id: id } as Partial<BootstrapEvent>)) as { hostId?: string }).hostId).toBeUndefined();
  expect((fold(event("done", { host_id: "worker" } as Partial<BootstrapEvent>)) as { hostId?: string }).hostId).toBeUndefined();
  const ready = fold(event("done", { host_id: id } as Partial<BootstrapEvent>));
  expect((foldEvent(ready, event("check", { attempt: 2 })) as { hostId?: string }).hostId).toBeUndefined();
});

describe("parseTarget", () => {
  test("accepts user@host, host, user@host:port, IPv4 and bracketed IPv6 with an optional port", () => {
    expect(parseTarget("kayg@o2")).toEqual({ user: "kayg", host: "o2", port: undefined });
    expect(parseTarget("o2")).toEqual({ user: undefined, host: "o2", port: undefined });
    expect(parseTarget("kayg@o2:2222")).toEqual({ user: "kayg", host: "o2", port: 2222 });
    expect(parseTarget("10.0.0.2")).toEqual({ user: undefined, host: "10.0.0.2", port: undefined });
    expect(parseTarget("root@[fd00::2]:22")).toEqual({ user: "root", host: "[fd00::2]", port: 22 });
  });

  test("rejects partial and malformed tokens, so they wait or show the hint", () => {
    for (const token of ["kayg@", "@o2", "my host", "o2:0", "o2:70000", "kayg@@o2", ""]) expect(parseTarget(token)).toBeUndefined();
  });
});

describe("matchListed", () => {
  const hosts = [{ id: "o2", address: "10.0.0.2" }, { id: "o2-prod", address: "10.0.1.2" }, { id: "web-01", address: "10.0.0.9" }];

  test("a name that is exactly one host's id or address names that host", () => {
    expect(matchListed(parseTarget("web-01")!, hosts)).toEqual({ named: hosts[2], prefixed: false });
    expect(matchListed(parseTarget("10.0.0.9")!, hosts)).toEqual({ named: hosts[2], prefixed: false });
  });

  test("a name that is also the start of another host's name is named but still prefixed", () => {
    // Typing `o2` must not chip the first host before `o2-prod` is ruled out, so it waits for a delimiter.
    expect(matchListed(parseTarget("o2")!, hosts)).toEqual({ named: hosts[0], prefixed: true });
  });

  test("a partial name that starts several hosts names none and waits", () => {
    expect(matchListed(parseTarget("o")!, hosts)).toEqual({ named: undefined, prefixed: true });
  });

  test("a new name that starts no host is neither named nor waiting", () => {
    expect(matchListed(parseTarget("kayg@o9")!, hosts)).toEqual({ named: undefined, prefixed: false });
  });
});

test("install diagnostics name the failed step and public host error", () => {
  const failure = { kind: "install" as const, message: "Joining the host to this server failed.", failed_step: "join" as const, log_tail: ["Join DNS lookup failed: Temporary failure in name resolution."] };
  expect(failureLine(failure)).toContain("Joining");
  expect(guideFor("worker", failure).happened).toContain("Temporary failure in name resolution");
});
test("missing payload tells the operator the architecture and expected server path", () => {
  const failure = { kind: "install" as const, message: "The matching static infraternal binary is unavailable.", failed_step: "upload" as const, log_tail: [], missing_binary: { architecture: "aarch64", path: "/release/infraternal-aarch64-musl" } };
  expect(guideFor("worker", failure).happened).toContain("aarch64");
  expect(guideFor("worker", failure).happened).toContain("/release/infraternal-aarch64-musl");
});
test("an already added host says so and offers opening its existing terminal", () => {
  const failure = { kind: "install" as const, message: "This host is already added. Open its terminal from Console.", log_tail: [], already_added: true };
  expect(guideFor("worker", failure).title).toBe("worker is already added");
  expect(guideFor("worker", failure, true)).toMatchObject({ happened: "It's already in Console.", next: "" });
  // No button to press: the copy names the key instead, written for this platform (no Apple glyphs on Linux).
  expect(guideFor("worker", failure).next).toMatch(/^Find its terminal with (⌘K|Ctrl K)\.$/);
  expect(failureDiagnostics(failure, guideFor("worker", failure))).toEqual([]);
  expect(guideFor("worker", failure).fix).toBe("none");
});

test("release payload verification names the architecture step and plain reason", () => {
  const failure = { kind: "install" as const, message: "the binary does not match the signed checksum.", failed_step: "get-arm64-binary" as const, log_tail: [] };
  expect(failureLine(failure)).toBe("Download infraternal (arm64): the binary does not match the signed checksum.");
});

describe("leftovers pause (#169)", () => {
  const challenge = "3f2b8c1e-9a4d-4e6b-8c7a-1d2e3f4a5b6c";
  const pause: BootstrapEvent = {
    sequence: 2, target: "h", attempt: 1, step: "check", message: "leftovers", elapsed_ms: 1, log_tail: [],
    failure: { kind: "stale_previous_attempt", message: "x", log_tail: [] }, leftovers: { challenge, mode: "rootless", findings: ["An unfinished setup lock"] },
  };
  const signedIn: BootstrapEvent = { sequence: 1, target: "h", attempt: 1, step: "check", message: "in", elapsed_ms: 0, log_tail: [], authentication: { method: "server-key" } };

  test("a check event with leftovers pauses the running attempt; the next event clears it", () => {
    const paused = fold(signedIn, pause);
    expect(paused.state).toBe("running");
    expect(awaitingFresh(paused)).toBe(true);
    expect(paused.leftovers?.challenge).toBe(challenge);
    expect(stagesOf(paused)[1]?.state).toBe("failed");
    const resumed = foldEvent(paused, event("check", { sequence: 3, message: "removed" }));
    expect(awaitingFresh(resumed)).toBe(false);
    expect(resumed.attempt).toBe(1);
  });

  test("a pause without leftovers offers nothing to start fresh", () => {
    const { leftovers: _leftovers, ...bare } = pause;
    expect(awaitingFresh(fold(signedIn, bare))).toBe(false);
  });
});

test("early terminal publication selects only its canonical host-bound shim session", () => {
  const host = "12345678-1234-1234-1234-123456789abc";
  const session = "abcdefab-1234-1234-1234-123456789abc";
  expect(fold(event("done", { host_id: host, session_id: session })).sessionId).toBe(session);
  expect(fold(event("connect", { host_id: host, session_id: session })).sessionId).toBeUndefined();
  expect(fold(event("done", { host_id: "host", session_id: session })).sessionId).toBeUndefined();
  expect(fold(event("done", { host_id: host, session_id: "shell" })).sessionId).toBeUndefined();
});

/** #433 P3: the takeover failure page preserves the server's cause and close state. */
test("takeover failures show the trusted manager and terminal messages unchanged", () => {
  for (const [exit_status, message] of [
    [73, "This machine has an infraternal agent from an earlier setup, but Take over could not confirm that only its own terminals were using it. No terminal was closed, and the old install's files were kept. Try again."],
    [74, "Take over closed the terminals you confirmed, but could not confirm that the old infraternal agent was no longer in use. The old install's files were kept, and those terminals stay closed. Try again."],
    [75, "This install or its open terminals changed since you reviewed them, so no terminal was closed and the old install was left as it was found. Try again to review it before taking over."],
    [79, "A terminal you confirmed would not close, so Take over stopped. Some terminals may already be closed; any that closed stay closed. The old install was put back as it was. Try again."],
    [80, "The host's service manager could not stop or update the old infraternal agent's service, so Take over stopped. No terminal was closed. The old install's files were kept. Try again."],
    [81, "Take over closed the terminals you confirmed, but the host's service manager could not finish updating the old infraternal agent's service. The old install's files were kept, and those terminals stay closed. Try again."],
  ] as const) {
    const failure = { kind: "unrecognized_install" as const, message, exit_status, log_tail: [] };
    const guide = guideFor("fixture", failure);
    expect(guide.happened).toBe(message);
    expect(guide.fix).toBe("retry");
    expect(guide.title).toBe("Take over on fixture didn't finish");
    expect(failureLine(failure)).toBe("Take over didn't finish");
  }
});
