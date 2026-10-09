/** Independent regressions for continuation work after Mesh publication is withdrawn [D164, D187, #108]. */
import { expect, test } from "bun:test";
import { MeshClient, type MeshClientEvent, type MeshSnapshotPage, type MeshSubscriptionEvent, type MeshTransport } from "./mesh";

const page = (name: string, offset?: number): MeshSnapshotPage => ({
  revision: 1, nodes: [], tags: [{ name, members: [] }], grants: [],
  ...(offset === undefined ? {} : { next_cursor: { revision: 1, offset } }),
});

for (const withdrawal of ["stop", "forbidden", "superseded"] as const) {
  test(`review continuation stops after ${withdrawal}`, async () => {
    let deliver: ((event: MeshSubscriptionEvent) => void) | undefined;
    const pending: ((value: MeshSnapshotPage) => void)[] = [];
    let calls = 0;
    const transport: MeshTransport = {
      call: <TOutput>() => {
        calls++;
        return new Promise<TOutput>(resolve => pending.push(value => resolve(value as TOutput)));
      },
      subscribe: (_filter, listener) => { deliver = listener; return () => {}; },
    };
    const events: MeshClientEvent[] = [];
    const stop = new MeshClient(transport).watch({}, event => events.push(event));
    deliver?.({ type: "snapshot", snapshot: page("first", 1) });
    expect(calls).toBe(1);
    if (withdrawal === "stop") stop();
    else if (withdrawal === "forbidden") deliver?.({ type: "error", error: "forbidden" });
    else deliver?.({ type: "resync", snapshot: page("current") });
    // The outstanding response is allowed to complete, but its next cursor
    // must not create a new request for a stopped or superseded assembly.
    pending.shift()?.(page("second", 2));
    await new Promise<void>(resolve => setTimeout(resolve, 0));
    stop();
    expect(events.length).toBe(withdrawal === "stop" ? 0 : 1);
    expect(calls).toBe(1);
  });
}
