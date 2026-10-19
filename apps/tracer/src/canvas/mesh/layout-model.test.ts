/** Per-view shared pin snapshots invalidate geometry without sharing mutable node models (#243, D180). */
import { expect, test } from "bun:test";
import { createLayoutModel } from "./layout-model";
import { metricsFor } from "../layout/geometry";
import type { MeshData } from "./source";
const metrics = metricsFor(1440, 900, false);
const data: MeshData = { version: 1, nodes: new Map([["host", { id: 1, name: "host", tags: [], state: "online", rttMs: undefined, os: undefined, address: undefined, path: undefined, via: undefined }]]), tags: {}, pins: new Map() };
test("a pin moved by another device invalidates a same-count pin cache", () => {
  let pins = { host: { x: 40, y: 80 } };
  const layout = createLayoutModel({ data: () => data }, () => pins);
  expect(layout(metrics).nodes[0]).toMatchObject({ x: 40, y: 80, pinned: true });
  pins = { host: { x: 200, y: 300 } };
  expect(layout(metrics).nodes[0]).toMatchObject({ x: 200, y: 300 });
});
test("a recovered graph owns its node positions independently", () => {
  const a = createLayoutModel({ data: () => data }, () => ({ host: { x: 40, y: 80 } }));
  const b = createLayoutModel({ data: () => data }, () => ({ host: { x: 200, y: 300 } }));
  const first = a(metrics).nodes[0]!, second = b(metrics).nodes[0]!;
  expect(first).not.toBe(second); expect(first.x).toBe(40); expect(second.x).toBe(200);
});
