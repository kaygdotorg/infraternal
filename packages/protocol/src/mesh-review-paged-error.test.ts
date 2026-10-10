/** Independent ordering check for an earlier paged snapshot failure after a newer refresh [D164, #108]. */
import { expect, test } from "bun:test";
import { MeshClient, type MeshClientEvent, type MeshSnapshotPage, type MeshSubscriptionEvent, type MeshTransport } from "./mesh";

const snapshot = (revision: number): MeshSnapshotPage => ({ revision, nodes: [], tags: [], grants: [] });

test("review earlier snapshot continuation failure cannot replace a newer complete refresh", async () => {
  let deliver: ((event: MeshSubscriptionEvent) => void) | undefined;
  const pending: { resolve: (page: MeshSnapshotPage) => void; reject: () => void }[] = [];
  const transport: MeshTransport = {
    call: <TOutput>() => new Promise<TOutput>((resolve, reject) => {
      pending.push({ resolve: page => resolve(page as TOutput), reject: () => reject(new Error("mesh unavailable")) });
    }),
    subscribe: (_filter, listener) => { deliver = listener; return () => {}; },
  };
  const events: MeshClientEvent[] = [];
  const stop = new MeshClient(transport).watch({}, event => events.push(event));
  deliver?.({ type: "snapshot", snapshot: snapshot(0) });
  deliver?.({ type: "resync", snapshot: {
    ...snapshot(1), tags: [{ name: "prod", members: [] }], next_cursor: { revision: 1, offset: 1 },
  } });
  const oldContinuation = pending.shift();
  deliver?.({ type: "changed", revision: 2 });
  pending.shift()?.resolve(snapshot(2));
  await new Promise<void>(resolve => setTimeout(resolve, 0));
  expect(events.at(-1)).toEqual({ type: "snapshot", snapshot: snapshot(2) });
  oldContinuation?.reject();
  await new Promise<void>(resolve => setTimeout(resolve, 0));
  stop();
  expect(events).toEqual([
    { type: "snapshot", snapshot: snapshot(0) },
    { type: "snapshot", snapshot: snapshot(2) },
  ]);
});

test("review earlier snapshot continuation cannot overwrite a delivered revision", async () => {
  let deliver: ((event: MeshSubscriptionEvent) => void) | undefined;
  const pending: ((page: MeshSnapshotPage) => void)[] = [];
  const transport: MeshTransport = {
    call: <TOutput>() => new Promise<TOutput>(resolve => {
      pending.push(page => resolve(page as TOutput));
    }),
    subscribe: (_filter, listener) => { deliver = listener; return () => {}; },
  };
  const events: MeshClientEvent[] = [];
  const stop = new MeshClient(transport).watch({}, event => events.push(event));
  deliver?.({ type: "snapshot", snapshot: snapshot(0) });
  deliver?.({ type: "resync", snapshot: {
    ...snapshot(1), tags: [{ name: "old", members: [] }], next_cursor: { revision: 1, offset: 1 },
  } });
  const oldContinuation = pending.shift();
  deliver?.({ type: "changed", revision: 2 });
  const node = {
    node: { id: 1, public_key: Array<number>(32).fill(1), host: "host-1", tags: [] },
    live: false, last_seen: 1_800_000_000, last_rtt_us: 1000,
  };
  const current = { ...snapshot(2), nodes: [node] };
  pending.shift()?.(current);
  await new Promise<void>(resolve => setTimeout(resolve, 0));
  expect(events.at(-1)).toEqual({ type: "snapshot", snapshot: current });
  // A stale cursor legitimately restarts at the server's current revision.
  // This older list response must not replace a view already delivered at 2.
  oldContinuation?.({ ...snapshot(2), nodes: [{ ...node, live: true }] });
  await new Promise<void>(resolve => setTimeout(resolve, 0));
  stop();
  expect(events).toEqual([
    { type: "snapshot", snapshot: snapshot(0) },
    { type: "snapshot", snapshot: current },
  ]);
});

test("a newer paged event owns publication before an earlier refresh resumes", async () => {
  let deliver: ((event: MeshSubscriptionEvent) => void) | undefined;
  const pending: ((page: MeshSnapshotPage) => void)[] = [];
  const transport: MeshTransport = {
    call: <TOutput>() => new Promise<TOutput>(resolve => pending.push(page => resolve(page as TOutput))),
    subscribe: (_filter, listener) => { deliver = listener; return () => {}; },
  };
  const events: MeshClientEvent[] = [];
  const stop = new MeshClient(transport).watch({}, event => events.push(event));
  deliver!({ type: "changed", revision: 2 });
  pending[0]!(snapshot(2));
  // The first list has completed assembly, but its parent await has not resumed.
  queueMicrotask(() => deliver!({ type: "resync", snapshot: {
    ...snapshot(3), tags: [{ name: "current", members: [] }], next_cursor: { revision: 3, offset: 1 },
  } }));
  await new Promise(resolve => setTimeout(resolve, 0));
  const beforeCompletion = [...events];
  pending[1]!(snapshot(3));
  await new Promise(resolve => setTimeout(resolve, 0));
  stop();
  expect(beforeCompletion).toEqual([]);
  expect(events.map(event => event.type === "snapshot" ? event.snapshot.revision : event.type)).toEqual([3]);
});
