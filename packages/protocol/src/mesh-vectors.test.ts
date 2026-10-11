/** Checks the typed Mesh client and subscription adapter against shared JSON contract vectors. */

import { expect, test } from "bun:test";
import {
  MeshClient,
  type MeshActionId,
  type MeshClientEvent,
  type MeshFilter,
  type MeshSnapshot,
  type MeshSubscriptionEvent,
  type MeshTransport,
} from "./mesh";

interface ActionVector {
  action: MeshActionId;
  input: Record<string, unknown>;
}

interface ResultVector {
  action: MeshActionId;
  value: unknown;
}

interface SubscriptionVector {
  filter: { topic: "mesh"; tag?: string };
  event: MeshSubscriptionEvent;
}

interface MeshManifest {
  actions: ActionVector[];
  results: ResultVector[];
  subscriptions: SubscriptionVector[];
}

class GoldenTransport implements MeshTransport {
  calls: Array<{ action: MeshActionId; input: unknown }> = [];
  filters: Array<{ topic: "mesh"; tag?: string }> = [];

  constructor(
    private readonly results: ReadonlyMap<string, unknown> = new Map(),
    private readonly event?: MeshSubscriptionEvent,
  ) {}

  call<TOutput>(action: MeshActionId, input: unknown): Promise<TOutput> {
    this.calls.push({ action, input });
    return Promise.resolve((this.results.get(action) ?? { revision: 1 }) as TOutput);
  }

  subscribe(
    filter: { topic: "mesh"; tag?: string },
    listener: (event: MeshSubscriptionEvent) => void,
  ): () => void {
    this.filters.push(filter);
    if (this.event !== undefined) {
      listener(this.event);
    }
    return () => {};
  }
}

const manifestUrl = new URL("../../../contracts/vectors/mesh/manifest.json", import.meta.url);

async function readManifest(): Promise<MeshManifest> {
  return JSON.parse(await Bun.file(manifestUrl).text()) as MeshManifest;
}

async function invoke(client: MeshClient, vector: ActionVector): Promise<void> {
  const input = vector.input;
  switch (vector.action) {
    case "mesh.list":
      await client.list(input as MeshFilter);
      break;
    case "mesh.node.enroll":
      await client.enrollNode(input as unknown as Parameters<MeshClient["enrollNode"]>[0]);
      break;
    case "mesh.node.observe":
      await client.observeNode(input as unknown as Parameters<MeshClient["observeNode"]>[0]);
      break;
    case "mesh.node.rename":
      await client.renameNode(input as unknown as Parameters<MeshClient["renameNode"]>[0]);
      break;
    case "mesh.node.delete":
      await client.deleteNode(input.node_id as number);
      break;
    case "mesh.tag.create":
      await client.createTag(input.name as string);
      break;
    case "mesh.tag.rename":
      await client.renameTag(input.name as string, input.new_name as string);
      break;
    case "mesh.tag.delete":
      await client.deleteTag(input.name as string);
      break;
    case "mesh.tag.member.add":
      await client.addTagMember(input.tag as string, input.node_id as number);
      break;
    case "mesh.tag.member.remove":
      await client.removeTagMember(input.tag as string, input.node_id as number);
      break;
    case "mesh.grant.create":
      await client.createGrant(input as unknown as Parameters<MeshClient["createGrant"]>[0]);
      break;
    case "mesh.grant.move":
      await client.moveGrant(input as unknown as Parameters<MeshClient["moveGrant"]>[0]);
      break;
    case "mesh.grant.delete":
      await client.deleteGrant(input.name as string);
      break;
    case "mesh.grant.rename":
      await client.renameGrant(input.name as string, input.new_name as string);
      break;
    case "mesh.role.define":
      await client.defineRole(input as unknown as Parameters<MeshClient["defineRole"]>[0]);
      break;
    case "mesh.role.assign":
      await client.assignRole(input as unknown as Parameters<MeshClient["assignRole"]>[0]);
      break;
    case "mesh.default.get":
      await client.getDefault();
      break;
    case "mesh.default.preview":
      await client.previewDefault(input as unknown as Parameters<MeshClient["previewDefault"]>[0]);
      break;
    case "mesh.default.set":
      await client.setDefault(input as unknown as Parameters<MeshClient["setDefault"]>[0]);
      break;
  }
}

async function nextTurn(): Promise<void> {
  await new Promise<void>((resolve) => setTimeout(resolve, 0));
}

test("every shared Mesh action vector passes through the typed client unchanged", async () => {
  const manifest = await readManifest();
  const results = new Map(manifest.results.map(({ action, value }) => [action, value]));
  const transport = new GoldenTransport(results);
  const client = new MeshClient(transport);

  for (const vector of manifest.actions) {
    await invoke(client, vector);
  }

  expect(transport.calls).toEqual(manifest.actions);
});

test("shared Mesh event vectors drive the typed watch adapter", async () => {
  const manifest = await readManifest();
  const snapshot = manifest.subscriptions.find(({ event }) => event.type === "resync")?.event;
  if (snapshot?.type !== "resync") {
    throw new Error("Mesh vectors require a resync snapshot");
  }
  const refreshed = snapshot.snapshot;

  for (const vector of manifest.subscriptions) {
    const transport = new GoldenTransport(
      new Map([["mesh.list", refreshed]]),
      vector.event,
    );
    const client = new MeshClient(transport);
    const received: MeshClientEvent[] = [];
    const filter: MeshFilter = vector.filter.tag === undefined ? {} : { tag: vector.filter.tag };
    const stop = client.watch(filter, (event) => received.push(event));
    await nextTurn();
    stop();

    expect(transport.filters).toEqual([vector.filter]);
    switch (vector.event.type) {
      case "snapshot":
      case "resync":
        expect(received).toEqual([{ type: "snapshot", snapshot: vector.event.snapshot }]);
        break;
      case "changed":
        expect(transport.calls).toEqual([{ action: "mesh.list", input: filter }]);
        expect(received).toEqual([{ type: "snapshot", snapshot: refreshed as MeshSnapshot }]);
        break;
      case "error":
        expect(received).toEqual([{ type: "error", error: vector.event.error }]);
        break;
    }
  }
});
