/** Independent ordering regression for failures from Mesh refreshes superseded by authoritative resync [D164]. */
import { expect, test } from "bun:test";
import { MeshClient, type MeshClientEvent, type MeshSnapshot, type MeshSubscriptionEvent, type MeshTransport } from "./mesh";

const snapshot = (revision: number): MeshSnapshot => ({ revision, nodes: [], tags: [], grants: [] });

test("review superseded refresh failure cannot replace authoritative resync", async () => {
  let deliver: ((event: MeshSubscriptionEvent) => void) | undefined;
  let refuse: (() => void) | undefined;
  const transport: MeshTransport = {
    call: <TOutput>() => new Promise<TOutput>((_resolve, reject) => {
      refuse = () => reject(new Error("mesh unavailable"));
    }),
    subscribe: (_filter, listener) => { deliver = listener; return () => {}; },
  };
  const events: MeshClientEvent[] = [];
  const stop = new MeshClient(transport).watch({}, event => events.push(event));
  deliver?.({ type: "snapshot", snapshot: snapshot(0) });
  deliver?.({ type: "changed", revision: 1 });
  // The server has already supplied a complete, newer state when the
  // old refresh fails. Its failure cannot invalidate that newer state.
  deliver?.({ type: "resync", snapshot: snapshot(2) });
  refuse?.();
  await new Promise<void>(resolve => setTimeout(resolve, 0));
  stop();
  expect(events).toEqual([
    { type: "snapshot", snapshot: snapshot(0) },
    { type: "snapshot", snapshot: snapshot(2) },
  ]);
});

/** New change work survives an older refusal after authoritative replacement. */
test("superseded failure preserves a newer pending refresh", async () => {
  let deliver: ((event: MeshSubscriptionEvent) => void) | undefined;
  let refuse: (() => void) | undefined;
  let completeLatest: (() => void) | undefined;
  let calls = 0;
  const transport: MeshTransport = {
    call: <TOutput>() => new Promise<TOutput>((resolve, reject) => {
      calls++;
      if (calls === 1) refuse = () => reject(new Error("mesh unavailable"));
      else completeLatest = () => resolve(snapshot(3) as TOutput);
    }),
    subscribe: (_filter, listener) => { deliver = listener; return () => {}; },
  };
  const events: MeshClientEvent[] = [];
  const stop = new MeshClient(transport).watch({}, event => events.push(event));
  deliver?.({ type: "snapshot", snapshot: snapshot(0) });
  deliver?.({ type: "changed", revision: 1 });
  deliver?.({ type: "resync", snapshot: snapshot(2) });
  deliver?.({ type: "changed", revision: 3 });
  refuse?.();
  await new Promise<void>(resolve => setTimeout(resolve, 0));
  expect(calls).toBe(2);
  expect(events).toEqual([
    { type: "snapshot", snapshot: snapshot(0) },
    { type: "snapshot", snapshot: snapshot(2) },
  ]);
  completeLatest?.();
  await new Promise<void>(resolve => setTimeout(resolve, 0));
  stop();
  expect(events).toEqual([
    { type: "snapshot", snapshot: snapshot(0) },
    { type: "snapshot", snapshot: snapshot(2) },
    { type: "snapshot", snapshot: snapshot(3) },
  ]);
});
