/** Regression tests for the typed Mesh API client and live revision refreshes. */

import { expect, test } from "bun:test";
import {
  MeshClient,
  type MeshActionId,
  type MeshClientEvent,
  type MeshSnapshot,
  type MeshSubscriptionEvent,
  type MeshTransport,
} from "./mesh";

class DeferredTransport implements MeshTransport {
  calls: Array<{ action: MeshActionId; input: unknown }> = [];
  listeners: Array<(event: MeshSubscriptionEvent) => void> = [];
  private pending: Array<(value: unknown) => void> = [];

  call<TOutput>(action: MeshActionId, input: unknown): Promise<TOutput> {
    this.calls.push({ action, input });
    return new Promise((resolve) => {
      this.pending.push((value) => resolve(value as TOutput));
    });
  }

  subscribe(
    _filter: { topic: "mesh"; tag?: string },
    listener: (event: MeshSubscriptionEvent) => void,
  ): () => void {
    this.listeners.push(listener);
    return () => {
      this.listeners = this.listeners.filter((current) => current !== listener);
    };
  }

  emit(event: MeshSubscriptionEvent): void {
    for (const listener of this.listeners) {
      listener(event);
    }
  }

  resolveNext(value: unknown): void {
    const resolve = this.pending.shift();
    if (resolve === undefined) {
      throw new Error("no pending Mesh transport call");
    }
    resolve(value);
  }
}

class RecordingTransport implements MeshTransport {
  calls: Array<{ action: MeshActionId; input: unknown }> = [];

  call<TOutput>(action: MeshActionId, input: unknown): Promise<TOutput> {
    this.calls.push({ action, input });
    return Promise.resolve({ revision: 1 } as TOutput);
  }

  subscribe(
    _filter: { topic: "mesh"; tag?: string },
    _listener: (event: MeshSubscriptionEvent) => void,
  ): () => void {
    return () => {};
  }
}

function inventory(revision: number): MeshSnapshot {
  return { revision, nodes: [], tags: [], grants: [] };
}

async function nextTurn(): Promise<void> {
  await new Promise<void>((resolve) => setTimeout(resolve, 0));
}

test("Mesh actions map to their typed action IDs and JSON inputs", async () => {
  const transport = new RecordingTransport();
  const client = new MeshClient(transport);

  await client.list({ tag: "prod" });
  await client.enrollNode({ name: "db-1", public_key: new Array(32).fill(1) });
  await client.observeNode({ node_id: 1, last_rtt_us: 1234 });
  await client.renameNode({ node_id: 1, name: "db-2" });
  await client.deleteNode(1);
  await client.createTag("prod");
  await client.renameTag("prod", "production");
  await client.deleteTag("prod");
  await client.addTagMember("prod", 1);
  await client.removeTagMember("prod", 1);
  await client.createGrant({
    name: "web",
    from: { Tag: "prod" },
    to: { Node: 1 },
    both_ways: false,
  });
  await client.moveGrant({ name: "web", side: "to", endpoint: { Tag: "frontend" } });
  await client.deleteGrant("web");
  await client.renameGrant("web", "web-prod");
  await client.defineRole({ name: "prod-grants", actions: ["mesh.manage_grants"], scopes: ["prod"] });
  await client.assignRole({ user_id: "user-1", role: "prod-grants" });

  expect(transport.calls).toEqual([
    { action: "mesh.list", input: { tag: "prod" } },
    { action: "mesh.node.enroll", input: { name: "db-1", public_key: new Array(32).fill(1) } },
    { action: "mesh.node.observe", input: { node_id: 1, last_rtt_us: 1234 } },
    { action: "mesh.node.rename", input: { node_id: 1, name: "db-2" } },
    { action: "mesh.node.delete", input: { node_id: 1 } },
    { action: "mesh.tag.create", input: { name: "prod" } },
    { action: "mesh.tag.rename", input: { name: "prod", new_name: "production" } },
    { action: "mesh.tag.delete", input: { name: "prod" } },
    { action: "mesh.tag.member.add", input: { tag: "prod", node_id: 1 } },
    { action: "mesh.tag.member.remove", input: { tag: "prod", node_id: 1 } },
    {
      action: "mesh.grant.create",
      input: { name: "web", from: { Tag: "prod" }, to: { Node: 1 }, both_ways: false },
    },
    { action: "mesh.grant.move", input: { name: "web", side: "to", endpoint: { Tag: "frontend" } } },
    { action: "mesh.grant.delete", input: { name: "web" } },
    { action: "mesh.grant.rename", input: { name: "web", new_name: "web-prod" } },
    {
      action: "mesh.role.define",
      input: { name: "prod-grants", actions: ["mesh.manage_grants"], scopes: ["prod"] },
    },
    { action: "mesh.role.assign", input: { user_id: "user-1", role: "prod-grants" } },
  ]);
});

test("Mesh watch coalesces change bursts and never publishes an older revision", async () => {
  const transport = new DeferredTransport();
  const client = new MeshClient(transport);
  const events: MeshClientEvent[] = [];
  const stop = client.watch({ tag: "prod" }, (event) => events.push(event));

  transport.emit({ type: "snapshot", snapshot: inventory(0) });
  transport.emit({ type: "changed", revision: 1 });
  transport.emit({ type: "changed", revision: 2 });
  await nextTurn();
  expect(transport.calls).toEqual([{ action: "mesh.list", input: { tag: "prod" } }]);

  transport.resolveNext(inventory(2));
  await nextTurn();
  expect(transport.calls.length).toBe(1);
  expect(events).toEqual([
    { type: "snapshot", snapshot: inventory(0) },
    { type: "snapshot", snapshot: inventory(2) },
  ]);
  transport.emit({ type: "changed", revision: 1 });
  await nextTurn();
  expect(transport.calls.length).toBe(1);
  stop();
});

test("Mesh watch forwards server errors and stops delivering after unsubscribe", () => {
  const transport = new DeferredTransport();
  const client = new MeshClient(transport);
  const events: MeshClientEvent[] = [];
  const stop = client.watch({}, (event) => events.push(event));

  transport.emit({ type: "error", error: "forbidden" });
  stop();
  transport.emit({ type: "snapshot", snapshot: inventory(1) });

  expect(events).toEqual([{ type: "error", error: "forbidden" }]);
  expect(transport.listeners.length).toBe(0);
});
