/** Keeps query replies independent of the release-6 viewer visibility capability (#244, D307). */
import { expect, test } from "bun:test";
import { MuxConnection } from "./connection";
import type { WireFrame } from "../../../packages/protocol/src/codec";

for (const caps of [0n, 4n, 8n, 12n]) test(`query replies negotiate independently with Hello caps ${caps}`, () => {
  const connection = Object.create(MuxConnection.prototype) as {
    terminalQueryReplies: boolean;
    serverVisibility: boolean;
    capListeners: Set<(caps: bigint) => void>;
    control(frame: WireFrame): void;
  };
  connection.capListeners = new Set();
  connection.control({ type: "Hello", version: 1, caps, clientInfo: "capability-test" });
  expect(connection.terminalQueryReplies).toBe((caps & 8n) !== 0n);
  expect(connection.serverVisibility).toBe((caps & 4n) !== 0n);
});
