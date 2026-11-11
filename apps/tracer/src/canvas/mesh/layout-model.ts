/**
 * Turns the mesh the source holds (`MeshSource.data`) into what the Mesh view draws: node models at their laid-out
 * places, the graph's size and its clusters. It is part of the Mesh view's own code (loaded on demand, `mesh.on-demand.ts`):
 * the source, which the rest of the canvas needs to know whether to offer the view, carries no layout.
 *
 * The same `NodeModel` object stands for the same node across layouts, because cards and arrows hold it by identity.
 * The result is cached until the data (or the card size) changes.
 *
 * Pins are stored where the person put the card and may be negative (left of or above the auto layout). A graph's size
 * cannot say that, so the model draws everything shifted right/down by `origin`: the least whole number of grid cells
 * that brings the leftmost/topmost pinned card to zero. The shift is derived from the pins on every read, never written
 * back, so a drop writes one pin (the moved card's) and no other pin changes (D180).
 */
import { CELL, type Metrics } from "../layout/geometry";
import type { NodeModel } from "../model/types";
import { layoutMesh, type Cluster } from "./layout";
import type { WireNode } from "./protocol";
import { tagNodeId, type MeshData, type MeshLayout, type MeshSource } from "./source";

/**
 * What a host card says under its name, in plain words. `restoreSafe === false` means the host runs an infraternal agent that
 * cannot yet tell which peers a restored server database no longer allows (it predates the authority epoch, #382). The one
 * thing a person can do about it is update that agent, so the card says "needs an update" and nothing more: the reason
 * (what could go wrong after a restore) belongs in the operations guide, not in a line that has to fit a card. A host that is
 * behind already says "not up to date", which is the same advice, and one that is offline cannot be updated until it is back,
 * so the note is only added to a host that is online.
 */
const subOf = (n: WireNode): string => {
  if (n.state === "offline") return "offline";
  if (n.state === "behind") return "not up to date";
  const path = n.path === "relay" ? `via ${n.via ?? "another host"}` : n.path === "direct" ? "direct" : "";
  const rtt = n.rttMs === undefined ? "" : `${Math.round(n.rttMs)} ms`;
  const note = n.restoreSafe === false ? "needs an update" : "";
  return [path, rtt, note].filter(Boolean).join(" · ") || "online";
};

/** Build a cached, positioned Mesh layout while preserving card identity and stored pin coordinates. */
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
    let minX = 0, minY = 0;
    for (const p of placed.nodes) if (p.pinned) { minX = Math.min(minX, p.x); minY = Math.min(minY, p.y); }
    const origin = { x: minX < 0 ? Math.ceil(-minX / CELL) * CELL : 0, y: minY < 0 ? Math.ceil(-minY / CELL) * CELL : 0 };
    for (const p of placed.nodes) {
      const w = p.kind === "host" ? nodes.get(p.id) : undefined;
      const members = p.kind === "tag" ? tags[p.id.slice(4)] ?? [] : [];
      const fields = p.kind === "host" && w
        ? { label: w.name, detail: w.address ?? (memberOf.get(w.name)?.map((t) => tagNodeId(t)).join(", ") || "no tags"), sub: subOf(w), state: w.state, restoreSafe: w.restoreSafe, ...(w.os ? { os: w.os } : {}), ...(!w.address && memberOf.get(w.name)?.length ? { tagList: memberOf.get(w.name)!.map((t) => tagNodeId(t)) } : {}) }
        : { label: p.id, detail: `${members.length} member${members.length === 1 ? "" : "s"}`, sub: members.slice(0, 3).join(", ") };
      let n = objects.get(p.id);
      if (!n) { n = { id: p.id, kind: p.kind, x: p.x + origin.x, y: p.y + origin.y, ...fields } as NodeModel; objects.set(p.id, n); }
      else { Object.assign(n, fields); n.x = p.x + origin.x; n.y = p.y + origin.y; if (!("os" in fields)) delete n.os; if (!("state" in fields)) delete n.state; if (!("tagList" in fields)) delete n.tagList; }
      if (p.pinned) n.pinned = true; else delete n.pinned;
      out.push(n);
    }
    const live = new Set(placed.nodes.map((p) => p.id));
    for (const id of [...objects.keys()]) if (!live.has(id)) objects.delete(id);
    const clusters: Cluster[] = origin.x || origin.y ? placed.clusters.map((k) => ({ ...k, x: k.x + origin.x, y: k.y + origin.y })) : placed.clusters;
    // With nothing to draw the view keeps a usable size for its loading, empty and error states.
    const layout: MeshLayout = { nodes: out, size: out.length ? { w: placed.size.w + origin.x, h: placed.size.h + origin.y } : { w: 880, h: 400 }, clusters, origin };
    cache = { key, layout, pins: pinned };
    return layout;
  };
}
