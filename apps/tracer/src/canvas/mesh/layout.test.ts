import { expect, test } from "bun:test";
import { layoutMesh, type LayoutHost } from "./layout";

const W = 208, H = 104;
const hosts = (n: number, tags = 20): LayoutHost[] => Array.from({ length: n }, (_, i) => ({ id: `host-${String(i).padStart(4, "0")}`, tags: i % 7 === 0 ? [] : [`t${i % tags}`, `u${i % 3}`] }));
const tagNames = (tags = 20): string[] => [...Array.from({ length: tags }, (_, i) => `t${i}`), "u0", "u1", "u2"];

test("a small mesh keeps the approved arrangement: tags down the left, hosts two to a row", () => {
  const out = layoutMesh({ hosts: [{ id: "build-01", tags: ["ci"] }, { id: "edge-arm", tags: [] }, { id: "nix-cache", tags: [] }, { id: "studio-mac", tags: ["ops"] }], tags: ["ops", "ci"], pins: {}, nodeW: W, nodeH: H });
  const at = (id: string) => out.nodes.find((n) => n.id === id)!;
  expect([at("tag:ci").x, at("tag:ci").y]).toEqual([30, 40]);
  expect([at("tag:ops").x, at("tag:ops").y]).toEqual([30, 40 + 210]);
  expect([at("build-01").x, at("build-01").y]).toEqual([340, 40]);
  expect([at("edge-arm").x, at("edge-arm").y]).toEqual([650, 40]);
  expect([at("studio-mac").x, at("studio-mac").y]).toEqual([650, 250]);
  expect(out.size.w).toBe(650 + W + 30);
});

test("the layout is deterministic and does not depend on input order", () => {
  const h = hosts(300);
  const a = layoutMesh({ hosts: h, tags: tagNames(), pins: {}, nodeW: W, nodeH: H });
  const b = layoutMesh({ hosts: [...h].reverse(), tags: [...tagNames()].reverse(), pins: {}, nodeW: W, nodeH: H });
  expect(b.nodes.map((n) => [n.id, n.x, n.y])).toEqual(a.nodes.map((n) => [n.id, n.x, n.y]));
});

test("no two cards overlap, and every card lies inside the graph", () => {
  const out = layoutMesh({ hosts: hosts(1000), tags: tagNames(), pins: {}, nodeW: W, nodeH: H });
  expect(out.nodes.length).toBe(1000 + 23);
  const cell = new Set<string>();
  for (const n of out.nodes) {
    expect(n.x).toBeGreaterThanOrEqual(0); expect(n.y).toBeGreaterThanOrEqual(0);
    expect(n.x + W).toBeLessThanOrEqual(out.size.w); expect(n.y + H).toBeLessThanOrEqual(out.size.h);
    const key = `${n.x},${n.y}`;
    expect(cell.has(key)).toBe(false);
    cell.add(key);
  }
  // Cards of one cluster are inside the cluster's frame.
  for (const c of out.clusters) for (const n of out.nodes.filter((p) => p.cluster === c.id)) {
    expect(n.x).toBeGreaterThanOrEqual(c.x); expect(n.x + W).toBeLessThanOrEqual(c.x + c.w);
    expect(n.y).toBeGreaterThanOrEqual(c.y); expect(n.y + H).toBeLessThanOrEqual(c.y + c.h);
  }
});

test("the sheet is wider than tall, roughly 16:10", () => {
  const { size } = layoutMesh({ hosts: hosts(1000), tags: tagNames(), pins: {}, nodeW: W, nodeH: H });
  expect(size.w / size.h).toBeGreaterThan(1.1);
  expect(size.w / size.h).toBeLessThan(2.4);
});

test("a pinned node stays where it was put and the others do not move", () => {
  const h = hosts(200);
  const free = layoutMesh({ hosts: h, tags: tagNames(), pins: {}, nodeW: W, nodeH: H });
  const pinned = layoutMesh({ hosts: h, tags: tagNames(), pins: { "host-0005": { x: 40, y: 50 } }, nodeW: W, nodeH: H });
  const get = (l: typeof free, id: string) => l.nodes.find((n) => n.id === id)!;
  expect(get(pinned, "host-0005")).toMatchObject({ x: 40, y: 50, pinned: true });
  for (const n of free.nodes) if (n.id !== "host-0005") expect([get(pinned, n.id).x, get(pinned, n.id).y]).toEqual([n.x, n.y]);
});

test("a pin beyond the sheet grows the graph", () => {
  const out = layoutMesh({ hosts: hosts(50), tags: tagNames(), pins: { "host-0001": { x: 99_000, y: 5 } }, nodeW: W, nodeH: H });
  expect(out.size.w).toBeGreaterThanOrEqual(99_000 + W);
});

test("a host's other tags do not move it; a tag nobody carries still has its node", () => {
  const out = layoutMesh({ hosts: [{ id: "a", tags: ["z", "m"] }], tags: ["z", "m", "empty"], pins: {}, nodeW: W, nodeH: H });
  expect(out.nodes.find((n) => n.id === "a")!.cluster).toBe("m");
  expect(out.nodes.some((n) => n.id === "tag:empty")).toBe(true);
});

test("1,000 nodes lay out in a few milliseconds", () => {
  const h = hosts(1000), t = tagNames();
  layoutMesh({ hosts: h, tags: t, pins: {}, nodeW: W, nodeH: H }); // warm
  const t0 = performance.now();
  for (let i = 0; i < 10; i++) layoutMesh({ hosts: h, tags: t, pins: {}, nodeW: W, nodeH: H });
  expect((performance.now() - t0) / 10).toBeLessThan(25);
});
