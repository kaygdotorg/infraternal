/** Bounded Mesh pages assemble a single authorized revision before reaching a view [D170]. */
import { expect, test } from "bun:test";
import { MeshClient, type MeshSnapshotPage, type MeshSubscriptionEvent, type MeshTransport, type MeshClientEvent } from "./mesh";

const page = (revision: number, name: string, offset?: number): MeshSnapshotPage => ({
  revision, nodes: [], tags: [{ name, members: [] }], grants: [],
  ...(offset === undefined ? {} : { next_cursor: { revision, offset } }),
});

test("list assembles bounded pages using the same filter", async () => {
  const inputs: unknown[] = [];
  const replies = [page(1, "prod", 1), page(1, "private")];
  const transport: MeshTransport = {
    call: async <TOutput>(_action: unknown, input: unknown) => { inputs.push(input); return replies.shift() as TOutput; },
    subscribe: () => () => {},
  };
  const snapshot = await new MeshClient(transport).list({ tag: "prod" });
  expect(snapshot.tags.map(tag => tag.name)).toEqual(["prod", "private"]);
  expect(inputs).toEqual([{ tag: "prod" }, { tag: "prod", cursor: { revision: 1, offset: 1 } }]);
});

test("a changed revision discards earlier pages before assembling its restart", async () => {
  const replies = [page(1, "old", 1), page(2, "new", 1), page(2, "tail")];
  const transport: MeshTransport = {
    call: async <TOutput>() => replies.shift() as TOutput,
    subscribe: () => () => {},
  };
  expect(await new MeshClient(transport).list()).toEqual({
    revision: 2, nodes: [], tags: [{ name: "new", members: [] }, { name: "tail", members: [] }], grants: [],
  });
});

for (const cursor of [{ revision: 1, offset: 0 }, { revision: 2, offset: 1 }, { revision: 1, offset: 2 }]) {
  test(`malformed continuation is refused: ${JSON.stringify(cursor)}`, async () => {
    let calls = 0;
    const transport: MeshTransport = {
      call: async <TOutput>() => { calls++; return { ...page(1, "prod"), next_cursor: cursor } as TOutput; },
      subscribe: () => () => {},
    };
    let refused = false;
    try { await new MeshClient(transport).list(); } catch { refused = true; }
    expect(refused).toBe(true);
    expect(calls).toBe(1);
  });
}

for (const withdraw of [false, true]) {
  test(`watch never publishes a partial page; withdrawn=${withdraw}`, async () => {
    let deliver: ((event: MeshSubscriptionEvent) => void) | undefined;
    let finish: ((value: unknown) => void) | undefined;
    const transport: MeshTransport = {
      call: <TOutput>() => new Promise<TOutput>(resolve => { finish = value => resolve(value as TOutput); }),
      subscribe: (_filter, listener) => { deliver = listener; return () => {}; },
    };
    const events: MeshClientEvent[] = [];
    const stop = new MeshClient(transport).watch({}, event => events.push(event));
    deliver?.({ type: "snapshot", snapshot: page(1, "prod", 1) });
    expect(events).toHaveLength(0);
    if (withdraw) deliver?.({ type: "error", error: "forbidden" });
    finish?.(page(1, "private"));
    await new Promise<void>(resolve => setTimeout(resolve, 0));
    expect(events).toHaveLength(1);
    expect(events[0]?.type).toBe(withdraw ? "error" : "snapshot");
    if (!withdraw && events[0]?.type === "snapshot") expect(events[0].snapshot.tags).toHaveLength(2);
    stop();
  });
}

test("a superseding equal-revision resync wins over pending page assembly", async () => {
  let deliver: ((event: MeshSubscriptionEvent) => void) | undefined;
  let finish: ((value: unknown) => void) | undefined;
  const transport: MeshTransport = {
    call: <TOutput>() => new Promise<TOutput>(resolve => { finish = value => resolve(value as TOutput); }),
    subscribe: (_filter, listener) => { deliver = listener; return () => {}; },
  };
  const events: MeshClientEvent[] = [];
  const stop = new MeshClient(transport).watch({}, event => events.push(event));
  deliver?.({ type: "snapshot", snapshot: page(1, "old", 1) });
  deliver?.({ type: "resync", snapshot: page(1, "current") });
  finish?.(page(1, "tail"));
  await new Promise<void>(resolve => setTimeout(resolve, 0));
  expect(events).toEqual([{ type: "snapshot", snapshot: page(1, "current") }]);
  stop();
});
