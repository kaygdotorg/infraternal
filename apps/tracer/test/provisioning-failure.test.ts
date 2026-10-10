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
      failure: { kind: "install", message: "This host is already added.", log_tail: [], already_added: true, missing_binary: { architecture: "aarch64", path: "/release/infraternal-aarch64-musl" } } }) }));
    expect(events[0]?.failure?.already_added).toBe(true);
    expect(events[0]?.failure?.missing_binary).toEqual({ architecture: "aarch64", path: "/release/infraternal-aarch64-musl" });
  } finally { globalThis.WebSocket = original; }
});
