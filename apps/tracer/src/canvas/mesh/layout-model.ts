/**
 * Turns the mesh the source holds (`MeshSource.data`) into what the Mesh view draws: node models at their laid-out
 * places, the graph's size and its clusters. It is part of the Mesh view's own code (loaded on demand, `mesh.on-demand.ts`):
 * the source, which the rest of the canvas needs to know whether to offer the view, carries no layout.
 *
 * The same `NodeModel` object stands for the same node across layouts, because cards and arrows hold it by identity.
 * The result is cached until the data (or the card size) changes.
 */
import type { Metrics } from "../layout/geometry";
import type { NodeModel } from "../model/types";
import { layoutMesh, type Cluster } from "./layout";
import type { WireNode } from "./protocol";
import { tagNodeId, type MeshData, type MeshLayout, type MeshSource } from "./source";

const subOf = (n: WireNode): string => {
  if (n.state === "offline") return "offline";
  if (n.state === "behind") return "not up to date";
  const path = n.path === "relay" ? `via ${n.via ?? "another host"}` : n.path === "direct" ? "direct" : "";
  const rtt = n.rttMs === undefined ? "" : `${Math.round(n.rttMs)} ms`;
  return [path, rtt].filter(Boolean).join(" · ") || "online";
};

export function createLayoutModel(source: Pick<MeshSource, "data">, ownPins?: () => Readonly<Record<string, { x: number; y: number }>> | undefined): (m: Metrics) => MeshLayout {
  const objects = new Map<string, NodeModel>();
  let cache: { key: string; layout: MeshLayout; pins: unknown } | undefined;
  return (m) => {
    const data: MeshData = source.data();
    const { nodes, tags } = data;
    const pinned = ownPins?.();
    const pins = pinned ?? Object.fromEntries(data.pins);
    const key = `${data.version}:${m.nodeW}x${m.nodeH}:${pinned ? Object.keys(pinned).length : data.pins.size}`;
    if (cache?.key === key && cache.pins === pinned) return cache.layout;
    const memberOf = new Map<string, string[]>();
    for (const [tag, members] of Object.entries(tags)) for (const h of members) (memberOf.get(h) ?? memberOf.set(h, []).get(h)!).push(tag);
    const placed = layoutMesh({
      hosts: [...nodes.keys()].map((id) => ({ id, tags: memberOf.get(id) ?? [] })),
      tags: Object.keys(tags),
      pins,
      nodeW: m.nodeW, nodeH: m.nodeH,
    });
    const out: NodeModel[] = [];
    for (const p of placed.nodes) {
      const w = p.kind === "host" ? nodes.get(p.id) : undefined;
      const members = p.kind === "tag" ? tags[p.id.slice(4)] ?? [] : [];
      const fields = p.kind === "host" && w
        ? { label: w.name, detail: w.address ?? (memberOf.get(w.name)?.map((t) => tagNodeId(t)).join(", ") || "no tags"), sub: subOf(w), state: w.state, ...(w.os ? { os: w.os } : {}), ...(!w.address && memberOf.get(w.name)?.length ? { tagList: memberOf.get(w.name)!.map((t) => tagNodeId(t)) } : {}) }
        : { label: p.id, detail: `${members.length} member${members.length === 1 ? "" : "s"}`, sub: members.slice(0, 3).join(", ") };
      let n = objects.get(p.id);
      if (!n) { n = { id: p.id, kind: p.kind, x: p.x, y: p.y, ...fields } as NodeModel; objects.set(p.id, n); }
      else { Object.assign(n, fields); n.x = p.x; n.y = p.y; if (!("os" in fields)) delete n.os; if (!("state" in fields)) delete n.state; if (!("tagList" in fields)) delete n.tagList; }
      if (p.pinned) n.pinned = true; else delete n.pinned;
      out.push(n);
    }
    const live = new Set(placed.nodes.map((p) => p.id));
    for (const id of [...objects.keys()]) if (!live.has(id)) objects.delete(id);
    const clusters: Cluster[] = placed.clusters;
    // With nothing to draw the view keeps a usable size for its loading, empty and error states.
    const layout: MeshLayout = { nodes: out, size: out.length ? placed.size : { w: 880, h: 400 }, clusters };
    cache = { key, layout, pins: pinned };
    return layout;
  };
}
