// SPDX-License-Identifier: AGPL-3.0-only
/** Tests the real provisioning adapters against server-shaped responses and local sockets. */
import { afterEach, describe, expect, test } from "bun:test";
import { createRealProvisioning, parseDiscovered, parseInstallCommand, parseServerKey } from "./real";
import { ProvisioningRun, type FailureDetail } from "../../provisioning-client";
import { ServiceError } from "./service";

const realFetch = globalThis.fetch;
afterEach(() => { globalThis.fetch = realFetch; });
const answer = (status: number, body: string, type = "application/json"): void => {
  globalThis.fetch = (async () => new Response(body, { status, headers: { "content-type": type } })) as unknown as typeof fetch;
};

describe("parsing the server's data", () => {
  test("a discovery row keeps only known fields and valid ids", () => {
    expect(parseDiscovered({ id: "o2", address: "10.0.0.2", sources: ["netbird", "nonsense"], reach: "ready", already_added: true, root_available: true, user: "kayg", os: "ubuntu" }))
      .toEqual({ id: "o2", address: "10.0.0.2", sources: ["netbird"], reach: "ready", alreadyAdded: true, rootAvailable: true, user: "kayg", os: "ubuntu" });
    expect(parseDiscovered({ id: "bad id", address: "x" })).toBeUndefined();
    expect(parseDiscovered({ id: "ok" })).toBeUndefined();
    expect(parseDiscovered("ok")).toBeUndefined();
  });
  test("the server key needs its public key and fingerprint", () => {
    expect(parseServerKey({ public_key: "ssh-ed25519 AAAA x", fingerprint: "SHA256:abc", locked: true })).toEqual({ publicKey: "ssh-ed25519 AAAA x", fingerprint: "SHA256:abc", locked: true });
    expect(parseServerKey({ public_key: "ssh-ed25519 AAAA x" })).toBeUndefined();
  });
  test("an install command needs a lifetime", () => {
    expect(parseInstallCommand({ command: "run", expires_in_seconds: 900 })).toEqual({ command: "run", expiresInSeconds: 900 });
    expect(parseInstallCommand({ command: "run" })).toBeUndefined();
  });
});

describe("a server that lacks an endpoint", () => {
  test("serving the web app (200, HTML) for an unknown path is 'not available'", async () => {
    answer(200, "<!doctype html><title>app</title>", "text/html");
    const service = createRealProvisioning();
    expect(await service.serverKey()).toBeUndefined();
    expect(await service.discover()).toEqual([]);
    expect(await service.installCommand("h")).toBeUndefined();
    expect(await service.mintCredential({ kind: "password", text: "fixture-input" }, "host", "host")).toMatch(/^[0-9a-f-]{36}$/);
  });
  test("404 discovery is an empty list; 500 discovery is an error to show", async () => {
    answer(404, "{}");
    expect(await createRealProvisioning().discover()).toEqual([]);
    answer(500, "{}");
    await expect(createRealProvisioning().discover()).rejects.toBeInstanceOf(ServiceError);
  });
  test("private sign-in stays local until a target-bound socket start", async () => {
    let calls = 0;
    globalThis.fetch = (async () => { calls++; throw new Error("unexpected HTTP"); }) as unknown as typeof fetch;
    const service = createRealProvisioning();
    const reference = await service.mintCredential({ kind: "password", text: "fixture-input" }, "one", "one");
    expect(calls).toBe(0);
    const run = service.open({ onEvent() {} }, { url: "ws://fixture.invalid" });
    run.start([{ id: "one", address: { kind: "manual", value: "one" }, credential: reference }]);
    Socket.last.open();
    const command = JSON.parse(Socket.last.sent[0]!);
    expect(command.auth_once[0].target).toBe("one");
    expect(command.auth_once[0].auth.password === "fixture-input").toBe(true);
    expect("credential" in command.targets[0]).toBe(false);
    expect(() => run.start([{ id: "one", address: { kind: "manual", value: "one" }, credential: reference }])).toThrow("expired");
    run.close();
  });
  test("a wrong target consumes the reference without sending private input", async () => {
    const service = createRealProvisioning();
    const reference = await service.mintCredential({ kind: "password", text: "fixture-input" }, "one", "one");
    const run = service.open({ onEvent() {} }, { url: "ws://fixture.invalid" });
    expect(() => run.start([{ id: "two", address: { kind: "manual", value: "two" }, credential: reference }])).toThrow("another host");
    expect(Socket.last.sent.length).toBe(0);
    run.close();
  });
  test("a local reference cannot change SSH address while keeping the target id", async () => {
    const service = createRealProvisioning();
    const reference = await service.mintCredential({ kind: "password", text: "fixture-input" }, "one", "one:22");
    const run = service.open({ onEvent() {} }, { url: "ws://fixture.invalid" });
    expect(() => run.start([{ id: "one", address: { kind: "manual", value: "two:22" }, credential: reference }])).toThrow("another host");
    expect(Socket.last.sent.length).toBe(0);
    run.close();
  });
  test("closing before open discards queued sign-in even if a late open fires", () => {
    const run = new ProvisioningRun({ onEvent() {} }, { url: "ws://fixture.invalid", takeAuth: () => ({ password: "fixture-input" }) });
    run.start([{ id: "one", address: { kind: "manual", value: "one" } }]);
    run.close();
    Socket.last.open();
    expect(Socket.last.sent.length).toBe(0);
  });
  test("pre-open commands stay bounded and events after close cannot revive a run", () => {
    let events = 0;
    const run = new ProvisioningRun({ onEvent() { events++; } }, { url: "ws://fixture.invalid" });
    for (let i = 0; i < 8; i++) run.replay();
    expect(() => run.replay()).toThrow("busy");
    run.close();
    Socket.last.message({ sequence: 1, target: "one", attempt: 1, step: "done", message: "ready", elapsed_ms: 1, log_tail: [] });
    expect(events).toBe(0);
  });
  test("trust waits for the exact acknowledgement, and ignores another target", async () => {
    const run = new ProvisioningRun({ onEvent() {} }, { url: "ws://fixture.invalid" });
    Socket.last.open();
    let confirmed = false;
    const promise = run.confirmHostKey("one", "challenge", "SHA256:fixture").then(() => { confirmed = true; });
    Socket.last.message({ host_key_confirmed: { target: "two", fingerprint: "SHA256:fixture" } });
    await Promise.resolve();
    expect(confirmed).toBe(false);
    Socket.last.message({ host_key_confirmed: { target: "one", fingerprint: "SHA256:fixture" } });
    await promise;
    expect(confirmed).toBe(true);
    run.close();
  });
});

describe("trusting a host key more than once (#449)", () => {
  /** Opens a run, shows it a host-key failure for `host`, and returns the service and the one fingerprint offered. */
  function observed(host: string): { service: ReturnType<typeof createRealProvisioning>; print: string } {
    const service = createRealProvisioning();
    const print = `SHA256:${"a".repeat(43)}`;
    const run = service.open({ onEvent() {} }, { url: "ws://fixture.invalid" });
    Socket.last.open();
    run.start([{ id: "one", address: { kind: "manual", value: host } }]);
    Socket.last.message({ sequence: 1, target: "one", attempt: 1, step: "failed", message: "Check the host key.", elapsed_ms: 1, log_tail: [],
      failure: { kind: "host-key", message: "Check the host key.", log_tail: [], fingerprints: [print], host_key_challenge: "challenge" } });
    return { service, print };
  }
  const confirmations = (): number => Socket.last.sent.filter((text) => text.includes("confirm-host-key")).length;
  const acknowledge = (print: string): void => Socket.last.message({ host_key_confirmed: { target: "one", fingerprint: print } });

  test("a second trust while the first is in flight joins it: one request, both resolve", async () => {
    const { service, print } = observed("one.lab");
    const first = service.trustHostKey("one.lab", print);
    const second = service.trustHostKey("one.lab", print);
    const third = service.trustHostKey("one.lab", print);
    acknowledge(print);
    await Promise.all([first, second, third]);
    expect(confirmations()).toBe(1);
  });
  test("a trust repeated after it succeeded resolves without asking again", async () => {
    const { service, print } = observed("one.lab");
    const first = service.trustHostKey("one.lab", print);
    acknowledge(print);
    await first;
    await service.trustHostKey("one.lab", print);
    expect(confirmations()).toBe(1);
  });
  test("a newer observation of the same host never joins an older trust, and the older one does not delete it", async () => {
    const service = createRealProvisioning();
    const print = `SHA256:${"a".repeat(43)}`;
    const show = (challenge: string): void => Socket.last.message({ sequence: 1, target: "one", attempt: 1, step: "failed", message: "Check the host key.", elapsed_ms: 1, log_tail: [],
      failure: { kind: "host-key", message: "Check the host key.", log_tail: [], fingerprints: [print], host_key_challenge: challenge } });
    const begin = (): { socket: Socket } => {
      const run = service.open({ onEvent() {} }, { url: "ws://fixture.invalid" });
      Socket.last.open();
      run.start([{ id: "one", address: { kind: "manual", value: "one.lab" } }]);
      return { socket: Socket.last };
    };
    const older = begin();
    show("old-challenge");
    const first = service.trustHostKey("one.lab", print);
    const newer = begin();
    show("new-challenge");
    const second = service.trustHostKey("one.lab", print);
    expect(newer.socket.sent.filter((text) => text.includes("new-challenge"))).toHaveLength(1);
    older.socket.message({ host_key_confirmed: { target: "one", fingerprint: print } });
    await first;
    // The older trust finished; the newer observation must still be there to confirm for real.
    newer.socket.message({ host_key_confirmed: { target: "one", fingerprint: print } });
    await second;
    expect(older.socket.sent.filter((text) => text.includes("confirm-host-key"))).toHaveLength(1);
    expect(newer.socket.sent.filter((text) => text.includes("confirm-host-key"))).toHaveLength(1);
  });
  test("a different fingerprint is still refused, before or after a trust", async () => {
    const { service, print } = observed("one.lab");
    const other = `SHA256:${"b".repeat(43)}`;
    await expect(service.trustHostKey("one.lab", other)).rejects.toBeInstanceOf(ServiceError);
    const first = service.trustHostKey("one.lab", print);
    acknowledge(print);
    await first;
    await expect(service.trustHostKey("one.lab", other)).rejects.toBeInstanceOf(ServiceError);
    await expect(service.trustHostKey("never-seen.lab", print)).rejects.toBeInstanceOf(ServiceError);
    expect(confirmations()).toBe(1);
  });
});

describe("bootstrap failure parsing", () => {
  test("an already-added failure keeps its existing host id", () => {
    let failure: FailureDetail | undefined;
    const run = new ProvisioningRun({ onEvent(event) { failure = event.failure; } }, { url: "ws://fixture.invalid" });
    Socket.last.message({
      sequence: 1,
      target: "one",
      attempt: 1,
      step: "failed",
      message: "This host is already added.",
      elapsed_ms: 1,
      log_tail: [],
      failure: {
        kind: "install",
        message: "This host is already added.",
        log_tail: [],
        already_added: true,
        host_id: "00000000-0000-0000-0000-00000000002a",
      },
    });
    expect(failure?.host_id).toBe("00000000-0000-0000-0000-00000000002a");
    run.close();
  });

  test("host ids are ignored on other failures and when malformed", () => {
    const failures: (FailureDetail | undefined)[] = [];
    const run = new ProvisioningRun({ onEvent(event) { failures.push(event.failure); } }, { url: "ws://fixture.invalid" });
    for (const [sequence, failure] of [
      [1, { kind: "auth", message: "Sign in again.", log_tail: [], host_id: "00000000-0000-0000-0000-00000000002a" }],
      [2, { kind: "install", message: "This host is already added.", log_tail: [], already_added: true, host_id: "not-a-host-id" }],
    ] as const) {
      Socket.last.message({
        sequence,
        target: "one",
        attempt: 1,
        step: "failed",
        message: failure.message,
        elapsed_ms: sequence,
        log_tail: [],
        failure,
      });
    }
    expect(failures).toHaveLength(2);
    expect(failures[0]?.host_id).toBeUndefined();
    expect(failures[1]?.host_id).toBeUndefined();
    run.close();
  });
});

/** Socket events remain explicit so the cancellation test can deliver open after close. */
class Socket extends EventTarget {
  static CONNECTING = 0;
  static OPEN = 1;
  static last: Socket;
  readyState = 0;
  sent: string[] = [];
  constructor(_url: string) { super(); Socket.last = this; }
  send(text: string): void { this.sent.push(text); }
  close(): void { this.readyState = 3; }
  open(): void { this.readyState = 1; this.dispatchEvent(new Event("open")); }
  message(value: unknown): void { this.dispatchEvent(new MessageEvent("message", { data: JSON.stringify(value) })); }
}
const realSocket = globalThis.WebSocket;
import { beforeEach } from "bun:test";
beforeEach(() => { globalThis.WebSocket = Socket as unknown as typeof WebSocket; });
afterEach(() => { globalThis.WebSocket = realSocket; });
