/** Reproduce a revoked Mesh view being republished by a previously started refresh. */
import { expect, test } from "bun:test";
import { MeshClient, type MeshSnapshot, type MeshTransport, type MeshSubscriptionEvent, type MeshClientEvent } from "./mesh";

test("review forbidden event cancels pending snapshot publication", async () => {
  let deliver: ((event: MeshSubscriptionEvent) => void) | undefined;
  let finish: ((value: unknown) => void) | undefined;
  const transport: MeshTransport = {
    call: <TOutput>() => new Promise<TOutput>(resolve => { finish = value => resolve(value as TOutput); }),
    subscribe: (_filter, listener) => { deliver = listener; return () => {}; },
  };
  const events: MeshClientEvent[] = [];
  const client = new MeshClient(transport);
  const stop = client.watch({}, event => events.push(event));
  const snapshot: MeshSnapshot = {revision:0,nodes:[],tags:[],grants:[]};
  deliver?.({type:"snapshot",snapshot});
  deliver?.({type:"changed",revision:1});
  deliver?.({type:"error",error:"forbidden"});
  finish?.({...snapshot,revision:1});
  await new Promise<void>(resolve => setTimeout(resolve,0));
  stop();
  expect(events.at(-1)).toEqual({type:"error",error:"forbidden"});
});


for (const error of ["forbidden", "not found", "invalid input", "mesh unavailable"]) {
  test(`subscription ${error} ends delivery before a late refresh rejection`, async () => {
    let deliver: ((event: MeshSubscriptionEvent) => void) | undefined;
    let reject: ((reason: Error) => void) | undefined;
    let calls = 0;
    let releases = 0;
    const transport: MeshTransport = {
      call: <TOutput>() => { calls++; return new Promise<TOutput>((_resolve, refuse) => { reject = refuse; }); },
      subscribe: (_filter, listener) => { deliver = listener; return () => { releases++; }; },
    };
    const events: MeshClientEvent[] = [];
    const stop = new MeshClient(transport).watch({}, event => events.push(event));
    deliver?.({type:"changed",revision:1});
    deliver?.({type:"error",error});
    deliver?.({type:"snapshot",snapshot:{revision:2,nodes:[],tags:[],grants:[]}});
    deliver?.({type:"changed",revision:3});
    reject?.(new Error("late refresh refusal"));
    await new Promise<void>(resolve => setTimeout(resolve,0));
    stop();
    expect(events).toEqual([{type:"error",error}]);
    expect(calls).toBe(1);
    expect(releases).toBe(1);
  });
}

test("synchronous subscription refusal releases the transport exactly once", () => {
  let releases = 0;
  const events: MeshClientEvent[] = [];
  const transport: MeshTransport = {
    call: <TOutput>() => Promise.reject<TOutput>(new Error("unexpected list")),
    subscribe: (_filter, listener) => { listener({type:"error",error:"forbidden"}); return () => { releases++; }; },
  };
  const stop = new MeshClient(transport).watch({}, event => events.push(event));
  stop();
  stop();
  expect(releases).toBe(1);
  expect(events).toEqual([{type:"error",error:"forbidden"}]);
});
