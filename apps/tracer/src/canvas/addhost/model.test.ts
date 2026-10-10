/** Tests bounded SSH target parsing and the progress model used by the add-host flow. */
// SPDX-License-Identifier: AGPL-3.0-only
import { describe, expect, test } from "bun:test";
import { foldEvent, pendingTarget, type BootstrapEvent, type FailureKind } from "../../provisioning-client";
import { authLabel, failureLine, guideFor, looksLikeSshConfig, matchListed, parseSshConfig, parseTarget, stagesOf } from "./model";

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
    expect(authLabel({ method: "user-key" })).toBe("your saved key");
    expect(authLabel({ method: "password" })).toBe("your password");
  });
});

describe("guideFor", () => {
  test("installation failures never claim that incomplete cleanup succeeded", () => {
    const guide = guideFor("fixture", { kind: "install", message: "cleanup pending", log_tail: [] });
    expect(guide.happened).toContain("cleanup may still need to finish");
    expect(guide.happened).not.toContain("nothing is left half done");
    expect(guide.next).toContain("finish cleanup before another attempt");
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
