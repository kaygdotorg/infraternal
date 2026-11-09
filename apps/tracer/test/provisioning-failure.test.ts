/** Verifies that public installation diagnostics survive the bootstrap socket decoder (#87). */
import { expect, test } from "bun:test";
import { ProvisioningRun, type BootstrapEvent } from "../src/provisioning-client";

test("already-added and missing-payload diagnostics reach the wizard through the socket", () => {
  const original = globalThis.WebSocket;
  let socket: EventTarget;
  class Socket extends EventTarget {
    constructor() { super(); socket = this; }
  }
  globalThis.WebSocket = Socket as unknown as typeof WebSocket;
  try {
    const events: BootstrapEvent[] = [];
    new ProvisioningRun({ onEvent: (event) => events.push(event) }, { url: "ws://localhost/bootstrap" });
    socket!.dispatchEvent(new MessageEvent("message", { data: JSON.stringify({ sequence: 1, target: "host", attempt: 1, step: "failed", message: "Install failed", elapsed_ms: 1,
      failure: { kind: "install", message: "This host is already added.", log_tail: [], already_added: true, failed_step: "get-arm64-binary", missing_binary: { architecture: "aarch64", path: "/release/infraternal-aarch64-musl" } } }) }));
    expect(events[0]?.failure?.already_added).toBe(true);
    expect(events[0]?.failure?.failed_step).toBe("get-arm64-binary");
    expect(events[0]?.failure?.missing_binary).toEqual({ architecture: "aarch64", path: "/release/infraternal-aarch64-musl" });
  } finally { globalThis.WebSocket = original; }
});

test("readiness failure retains its trusted step through the socket", () => {
  const original = globalThis.WebSocket;
  let socket: EventTarget;
  class Socket extends EventTarget {
    constructor() { super(); socket = this; }
  }
  globalThis.WebSocket = Socket as unknown as typeof WebSocket;
  try {
    const events: BootstrapEvent[] = [];
    new ProvisioningRun({ onEvent: (event) => events.push(event) }, { url: "ws://localhost/bootstrap" });
    socket!.dispatchEvent(new MessageEvent("message", { data: JSON.stringify({ sequence: 1, target: "host", attempt: 1, step: "failed", message: "Readiness failed", elapsed_ms: 1,
      failure: { kind: "install", message: "Check the host service.", log_tail: [], failed_step: "readiness" } }) }));
    expect(events[0]?.failure?.failed_step).toBe("readiness");
  } finally { globalThis.WebSocket = original; }
});

test("validated setup-lock coordinates reach the wizard through the socket", () => {
  const original = globalThis.WebSocket;
  let socket: EventTarget;
  class Socket extends EventTarget {
    constructor() { super(); socket = this; }
  }
  globalThis.WebSocket = Socket as unknown as typeof WebSocket;
  try {
    const events: BootstrapEvent[] = [];
    new ProvisioningRun({ onEvent: (event) => events.push(event) }, { url: "ws://localhost/bootstrap" });
    socket!.dispatchEvent(new MessageEvent("message", { data: JSON.stringify({ sequence: 1, target: "host", attempt: 1, step: "check", message: "Stuck install", elapsed_ms: 1,
      failure: { kind: "stale_previous_attempt", message: "Replace the stuck install.", log_tail: [], setup_lock: { machine: "build-node", pid: 254, since: "2026-11-02T04:05:06Z", active: false } } }) }));
    expect(events[0]?.failure?.setup_lock).toEqual({ machine: "build-node", pid: 254, since: "2026-11-02T04:05:06Z", active: false });
  } finally { globalThis.WebSocket = original; }
});

test("stuck-install sessions and the other server reach the wizard only when well formed (#305, D335)", () => {
  const original = globalThis.WebSocket;
  let socket: EventTarget;
  class Socket extends EventTarget {
    constructor() { super(); socket = this; }
  }
  globalThis.WebSocket = Socket as unknown as typeof WebSocket;
  try {
    const events: BootstrapEvent[] = [];
    new ProvisioningRun({ onEvent: (event) => events.push(event) }, { url: "ws://localhost/bootstrap" });
    const send = (extra: Record<string, unknown>) => socket!.dispatchEvent(new MessageEvent("message", { data: JSON.stringify({ sequence: events.length + 1, target: "host", attempt: 1, step: "check", message: "Stuck install", elapsed_ms: 1,
      failure: { kind: "stale_previous_attempt", message: "x", log_tail: [], setup_lock: { machine: "build-node", pid: 254, since: "2026-11-02T04:05:06Z", active: false, ...extra } } }) }));
    send({ sessions: 2, enrolled_with: "monitor01.example" });
    expect(events[0]?.failure?.setup_lock).toMatchObject({ sessions: 2, enrolled_with: "monitor01.example" });
    send({ sessions: -1, enrolled_with: "bad server" });
    expect(events[1]?.failure?.setup_lock?.sessions).toBeUndefined();
    expect(events[1]?.failure?.setup_lock?.enrolled_with).toBeUndefined();
    // D337: the in-use refusal reaches the guide; only a literal true counts.
    send({ sessions: 2, enrolled_with: "monitor01.example", live: true, in_use: true });
    expect(events[2]?.failure?.setup_lock).toMatchObject({ live: true, in_use: true });
    send({ in_use: "yes" });
    expect(events[3]?.failure?.setup_lock?.in_use).toBeUndefined();
  } finally { globalThis.WebSocket = original; }
});

test("malformed setup-lock coordinates cannot expose the replacement action", () => {
  const original = globalThis.WebSocket;
  let socket: EventTarget;
  class Socket extends EventTarget {
    constructor() { super(); socket = this; }
  }
  globalThis.WebSocket = Socket as unknown as typeof WebSocket;
  try {
    const events: BootstrapEvent[] = [];
    new ProvisioningRun({ onEvent: (event) => events.push(event) }, { url: "ws://localhost/bootstrap" });
    socket!.dispatchEvent(new MessageEvent("message", { data: JSON.stringify({ sequence: 1, target: "host", attempt: 1, step: "check", message: "Stuck install", elapsed_ms: 1,
      failure: { kind: "stale_previous_attempt", message: "Replace the stuck install.", log_tail: [], setup_lock: { machine: "bad host", pid: 0, since: "not a time", active: false } } }) }));
    expect(events[0]?.failure?.setup_lock).toBeUndefined();
  } finally { globalThis.WebSocket = original; }
});

// D359: the Take over offer names the old install's id. Only the exact public shape on its own kind survives the
// decoder; anything else is dropped, so the wizard falls back to the plain "set up elsewhere" page.
test("a Take over offer reaches the wizard only in its exact shape", () => {
  const original = globalThis.WebSocket;
  let socket: EventTarget;
  class Socket extends EventTarget {
    constructor() { super(); socket = this; }
  }
  globalThis.WebSocket = Socket as unknown as typeof WebSocket;
  try {
    const events: BootstrapEvent[] = [];
    new ProvisioningRun({ onEvent: (event) => events.push(event) }, { url: "ws://localhost/bootstrap" });
    const install = "c10909d16e8147a3b0f2e5d4c3b2a190";
    const terminal = { account: "root", program: "bash", since: 1792195200 };
    const close_challenge = "1b4e28ba-2fa1-41d2-883f-0016d3cca427";
    const offers: Array<[string, unknown]> = [
      ["unrecognized_install", { install, live: true }],
      ["unrecognized_install", { install: install.toUpperCase(), live: true }],
      ["unrecognized_install", { install: install.slice(1), live: true }],
      ["unrecognized_install", { install, live: "yes" }],
      ["install", { install, live: false }],
      ["unrecognized_install", { install, live: true, terminals: [terminal], close_challenge }],
      ["unrecognized_install", { install, live: true, terminals: [{ ...terminal, program: "bash\n" }], close_challenge }],
      ["unrecognized_install", { install, live: true, terminals: [{ ...terminal, since: 0 }], close_challenge }],
      ["unrecognized_install", { install, live: true, terminals: "unknown" }],
      ["unrecognized_install", { install, live: true, terminals: [terminal] }],
      ["unrecognized_install", { install, live: true, terminals: [terminal], close_challenge: "00000000-0000-0000-0000-000000000000" }],
    ];
    offers.forEach(([kind, takeover], index) => socket!.dispatchEvent(new MessageEvent("message", { data: JSON.stringify({ sequence: index + 1, target: "host", attempt: 1, step: "check", message: "offer", elapsed_ms: 1,
      failure: { kind, message: "x", log_tail: [], takeover } }) })));
    expect(events.map((event) => event.failure?.takeover)).toEqual([{ install, live: true }, undefined, undefined, undefined, undefined, { install, live: true, terminals: [terminal], close_challenge }, undefined, undefined, undefined, undefined, undefined]);
    // The offer pauses its attempt like leftovers do: its challenge reaches the wizard (D359).
    const leftovers = { challenge: "1b4e28ba-2fa1-41d2-883f-0016d3cca427", mode: "root", findings: ["x"] };
    socket!.dispatchEvent(new MessageEvent("message", { data: JSON.stringify({ sequence: 20, target: "host", attempt: 1, step: "check", message: "offer", elapsed_ms: 1,
      failure: { kind: "unrecognized_install", message: "x", log_tail: [], takeover: { install, live: false } }, leftovers }) }));
    socket!.dispatchEvent(new MessageEvent("message", { data: JSON.stringify({ sequence: 21, target: "host", attempt: 1, step: "check", message: "plain", elapsed_ms: 1,
      failure: { kind: "unrecognized_install", message: "x", log_tail: [] }, leftovers }) }));
    expect(events.at(-2)?.leftovers?.challenge).toBe(leftovers.challenge);
    expect(events.at(-1)?.leftovers).toBeUndefined();
  } finally { globalThis.WebSocket = original; }
});
