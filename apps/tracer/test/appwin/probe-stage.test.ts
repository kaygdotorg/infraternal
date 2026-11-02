/** Role: keep reconnect diagnostics restricted to public control-probe coordinates (#146). */
import { expect, test } from "bun:test";
import { probeStage } from "../../real/server";
import type { WireFrame } from "../../../../packages/protocol/src/codec";

test("control probe receipts project only their explicit numeric identity", () => {
  const ping = { type: "Ping", nonce: 3n, sentUs: 1250n, privateFixtureText: "discard-this-fixture-text" } as WireFrame;
  const pong = { ...ping, type: "Pong" } as WireFrame;
  expect(probeStage("browser_ping", 7, 0, ping, 10)).toEqual({ phase: "browser_ping", socket: 7, nonce: "3", sentUs: "1250", at: 10 });
  expect(probeStage("server_pong", 7, 0, pong, 11)).toEqual({ phase: "server_pong", socket: 7, nonce: "3", sentUs: "1250", at: 11 });
  expect(JSON.stringify(probeStage("browser_ping", 7, 0, ping, 10))).not.toContain("discard-this-fixture-text");
});

test("stream probes and unrelated control frames never enter probe receipts", () => {
  const ping: WireFrame = { type: "Ping", nonce: 1n, sentUs: 1n };
  const pong: WireFrame = { type: "Pong", nonce: 1n, sentUs: 1n };
  expect(probeStage("browser_ping", 1, 3, ping, 1)).toBeUndefined();
  expect(probeStage("server_pong", 1, 3, pong, 1)).toBeUndefined();
  expect(probeStage("browser_ping", 1, 0, pong, 1)).toBeUndefined();
  expect(probeStage("server_pong", 1, 0, ping, 1)).toBeUndefined();
  expect(probeStage("browser_ping", 1, 0, { type: "Call", callId: 1, actionId: "fixture.private", inputJson: new TextEncoder().encode("discard-this-fixture-text") }, 1)).toBeUndefined();
});
