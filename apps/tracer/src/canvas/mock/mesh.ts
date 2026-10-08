/** Mockup Mesh: an in-memory `MeshSource` over the test double's hosts, tags and grants. */
import type { Metrics } from "../layout/geometry";
import type { MeshSource } from "../mesh/source";
import type { Grant, NodeModel } from "../model/types";
import { TAGS } from "./data";
import type { MockWorld } from "./world";

export function createMockMesh(world: MockWorld): MeshSource {
  const listeners = new Set<() => void>();
  const changed = (): void => { for (const l of listeners) l(); };
  let serial = 100;
  const pinned = new Map<string, { x: number; y: number }>();
  return {
    layout(m: Metrics) {
      const nw = m.nodeW, nh = m.nodeH;
      const gx = [30, 340, 650], gy = [40, 250];
      const base: NodeModel[] = [
        { id: "tag:ops", kind: "tag", label: "tag:ops", x: gx[0]!, y: gy[0]!, detail: "1 member", sub: "studio-mac" },
        { id: "build-01", kind: "host", label: "build-01", x: gx[1]!, y: gy[0]!, detail: "10.69.69.71", sub: "direct · 42 ms", os: "ubuntu" },
        { id: "edge-arm", kind: "host", label: "edge-arm", x: gx[2]!, y: gy[0]!, detail: "10.69.69.72", sub: "via fra-relay · 188 ms", os: "debian" },
        { id: "tag:ci", kind: "tag", label: "tag:ci", x: gx[0]!, y: gy[1]!, detail: "1 member", sub: "build-01" },
        { id: "nix-cache", kind: "host", label: "nix-cache", x: gx[1]!, y: gy[1]!, detail: "10.69.69.73", sub: "direct · 31 ms", os: "nixos" },
        { id: "studio-mac", kind: "host", label: "studio-mac", x: gx[2]!, y: gy[1]!, detail: "100.86.4.21", sub: "direct · 58 ms", os: "apple" },
      ];
      const nodes = base.map((n) => ({ ...n, ...(pinned.get(n.id) ?? {}) }));
      return { nodes, size: { w: gx[2]! + nw + 30, h: gy[1]! + nh + 30 } };
    },
    grants: () => world.grants,
    tags: () => TAGS,
    canEdit: () => world.role === "operator",
    addGrant(from, to): Grant { const g = { id: `g${++serial}`, from, to }; world.grants.push(g); changed(); return g; },
    moveGrant(grant, to) { if (to.to) grant.to = to.to; if (to.from) grant.from = to.from; changed(); },
    removeGrant(grant) { world.grants.splice(world.grants.indexOf(grant), 1); changed(); },
    pin(id, x, y) { pinned.set(id, { x, y }); },
    onChange(l) { listeners.add(l); return () => { listeners.delete(l); }; },
  };
}
