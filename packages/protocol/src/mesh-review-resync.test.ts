/** Reproduce loss of authoritative same-revision liveness snapshots on reconnect. */
import { expect, test } from "bun:test";
import { MeshClient, type MeshSnapshot, type MeshTransport, type MeshSubscriptionEvent, type MeshClientEvent } from "./mesh";

test("review watch applies same-revision authoritative resync", () => {
  let deliver: ((event: MeshSubscriptionEvent) => void) | undefined;
  const transport: MeshTransport = {
    call: <TOutput>() => Promise.reject<TOutput>(new Error("unexpected list")),
    subscribe: (_filter, listener) => { deliver = listener; return () => {}; },
  };
  const client = new MeshClient(transport);
  const events: MeshClientEvent[] = [];
  const stop = client.watch({}, event => events.push(event));
  const online: MeshSnapshot = { revision:7, tags:[], grants:[], nodes:[{node:{id:1,host:"host",public_key:new Array(32).fill(1),tags:[]},live:true,last_seen:1800000000,last_rtt_us:1000}] };
  deliver?.({type:"snapshot", snapshot: online});
  deliver?.({type:"resync", snapshot:{...online,nodes:[{...online.nodes[0]!,live:false}]}});
  stop();
  expect(events).toHaveLength(2);
  expect(events[1]).toMatchObject({type:"snapshot",snapshot:{nodes:[{live:false}]}});
});


test("authoritative resync keeps priority over an equal-revision pending list", async () => {
  let deliver: ((event: MeshSubscriptionEvent) => void) | undefined;
  let finish: ((value: unknown) => void) | undefined;
  const transport: MeshTransport = {
    call: <TOutput>() => new Promise<TOutput>(resolve => { finish = value => resolve(value as TOutput); }),
    subscribe: (_filter, listener) => { deliver = listener; return () => {}; },
  };
  const events: MeshClientEvent[] = [];
  const stop = new MeshClient(transport).watch({}, event => events.push(event));
  const node = {node:{id:1,host:"host",public_key:new Array(32).fill(1),tags:[]},live:true,last_seen:1800000000,last_rtt_us:1000};
  deliver?.({type:"snapshot",snapshot:{revision:7,nodes:[node],tags:[],grants:[]}});
  deliver?.({type:"changed",revision:8});
  deliver?.({type:"resync",snapshot:{revision:8,nodes:[{...node,live:false}],tags:[],grants:[]}});
  finish?.({revision:8,nodes:[node],tags:[],grants:[]});
  await new Promise<void>(resolve => setTimeout(resolve,0));
  deliver?.({type:"resync",snapshot:{revision:6,nodes:[node],tags:[],grants:[]}});
  stop();
  expect(events).toHaveLength(2);
  expect(events.at(-1)).toMatchObject({type:"snapshot",snapshot:{revision:8,nodes:[{live:false}]}});
});
