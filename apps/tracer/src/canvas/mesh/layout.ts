/**
 * Automatic layout of the Mesh graph, pure (no DOM): where each node sits, and the clusters the far zoom shows.
 *
 * Rules (D180: graph nodes are laid out automatically; nodes the person drags are pinned and saved):
 * - **Stable.** The same mesh always lays out the same way: ordering is by name, never by arrival, so a status
 *   change moves nothing and one new host moves only what comes after it in its cluster.
 * - **Pins win.** A pinned node sits exactly where the person put it; the rest are laid out as if it were not
 *   there. (A pin is the person's, so the layout never nudges it.)
 * - **Clusters.** A host belongs to the first tag (by name) it carries, or to "untagged". A cluster is its tag
 *   node followed by its hosts in a grid; clusters are packed in rows into a roughly 16:10 sheet. The far zoom
 *   draws one chip per cluster instead of its cards, so a large mesh stays cheap to draw.
 * - **Small meshes** (a handful of hosts) keep the plain arrangement the design was approved with: tags down the
 *   left, hosts in two columns beside them. Clusters would only add frames around a few cards.
 *
 * The cost is linear in the node count (a sort and one pass), so 1,000 nodes lay out in a few milliseconds.
 */
import { tagNodeId } from "./source";

/** A host as the layout sees it: its id and the tags it carries. */
export interface LayoutHost { id: string; tags: readonly string[] }
/** What the layout needs: the hosts, the tag names, the pinned positions and the card size. */
export interface LayoutInput {
  /** Hosts, in any order. */
  hosts: readonly LayoutHost[];
  /** Tag names (without the prefix), including tags nobody carries yet. */
  tags: readonly string[];
  pins: Readonly<Record<string, { x: number; y: number }>>;
  nodeW: number;
  nodeH: number;
}
/** One node placed by the layout. `pinned` nodes sit where the person put them; `cluster` names the tag cluster the node belongs to. */
export interface Placed { id: string; kind: "host" | "tag"; x: number; y: number; pinned: boolean; cluster: string }
/** A tag and its hosts: the frame's rectangle, the host ids (not the tag's own node), and the tag node when the cluster has one. */
export interface Cluster { id: string; label: string; x: number; y: number; w: number; h: number; /** Host ids (not the tag's own node). */ hosts: string[]; tagNode?: string }
/** The result: every node placed, the size of the whole sheet, and the clusters. */
export interface Layout { nodes: Placed[]; size: { w: number; h: number }; clusters: Cluster[] }

/**
 * Layout spacing in pixels: `GAP_X` and `GAP_Y` between cards, `FRAME` around a cluster's cards, `EDGE` around the sheet. `SMALL_HOSTS` is the
 * largest count of hosts (and of tags) that keeps the plain two-column arrangement. `UNTAGGED` names the cluster of hosts with no tag.
 */
const GAP_X = 24, GAP_Y = 24, FRAME = 28, EDGE = 30, SMALL_HOSTS = 8, UNTAGGED = "untagged";
/** Orders strings by plain comparison, so the layout never depends on arrival order. */
const byName = (a: string, b: string): number => (a < b ? -1 : a > b ? 1 : 0);

/**
 * Places the nodes and builds the clusters. Pure and stable: the same input always gives the same output, pinned nodes keep their
 * position, and a pin outside the sheet makes the sheet larger. A small mesh keeps the plain arrangement; a larger one is packed in clusters.
 */
export function layoutMesh(input: LayoutInput): Layout {
  const { nodeW, nodeH, pins } = input;
  const tags = [...input.tags].sort(byName);
  const hosts = [...input.hosts].sort((a, b) => byName(a.id, b.id));
  const tagSet = new Set(tags);
  const primary = (h: LayoutHost): string => h.tags.filter((t) => tagSet.has(t)).sort(byName)[0] ?? UNTAGGED;
  const members = new Map<string, string[]>();
  for (const h of hosts) { const k = primary(h); (members.get(k) ?? members.set(k, []).get(k)!).push(h.id); }

  const placed: Placed[] = [];
  const clusters: Cluster[] = [];
  const pin = (p: Placed): Placed => { const at = pins[p.id]; return at ? { ...p, x: at.x, y: at.y, pinned: true } : p; };

  if (hosts.length <= SMALL_HOSTS && tags.length <= SMALL_HOSTS) {
    // Tags down the left, hosts two to a row beside them.
    const rows = Math.max(tags.length, Math.ceil(hosts.length / 2));
    const px = nodeW + 102, py = nodeH + 106, x0 = 30, y0 = 40;
    tags.forEach((t, i) => placed.push(pin({ id: tagNodeId(t), kind: "tag", x: x0, y: y0 + i * py, pinned: false, cluster: t })));
    hosts.forEach((h, i) => placed.push(pin({ id: h.id, kind: "host", x: x0 + px * (1 + (i % 2)), y: y0 + Math.floor(i / 2) * py, pinned: false, cluster: primary(h) })));
    const w = x0 + px * (hosts.length > 1 || !tags.length ? 2 : tags.length ? 1 : 0) + nodeW + 30;
    const size = { w: Math.max(w, x0 + nodeW + 30), h: y0 + Math.max(0, rows - 1) * py + nodeH + 30 };
    for (const [id, ids] of members) clusters.push({ id, label: id === UNTAGGED ? "No tag" : id, x: 0, y: 0, w: 0, h: 0, hosts: ids, ...(id === UNTAGGED ? {} : { tagNode: tagNodeId(id) }) });
    return { nodes: placed, size: fit(placed, size, nodeW, nodeH), clusters };
  }

  // Clusters in name order, "untagged" last. Each is its tag node (when it has one) then its hosts, in a grid whose
  // cells are about as wide as tall on screen.
  const order = [...new Set([...tags, ...members.keys()].filter((k) => k !== UNTAGGED))].sort(byName);
  if (members.has(UNTAGGED)) order.push(UNTAGGED);
  const px = nodeW + GAP_X, py = nodeH + GAP_Y;
  interface Block { id: string; ids: string[]; cols: number; rows: number; w: number; h: number; withTag: boolean }
  const blocks: Block[] = order.map((id) => {
    const ids = members.get(id) ?? [];
    const withTag = id !== UNTAGGED;
    const cells = ids.length + (withTag ? 1 : 0);
    const cols = Math.max(1, Math.min(cells, Math.ceil(Math.sqrt(cells * (py / px)))));
    const rows = Math.ceil(cells / cols);
    return { id, ids, cols, rows, withTag, w: cols * px - GAP_X + FRAME * 2, h: rows * py - GAP_Y + FRAME * 2 };
  });
  // Pack into rows ("shelves") of a 16:10 sheet.
  const area = blocks.reduce((sum, b) => sum + (b.w + GAP_X) * (b.h + GAP_Y), 0);
  const sheetW = Math.max(Math.sqrt(area * 1.6), ...blocks.map((b) => b.w));
  let x = 0, y = 0, shelfH = 0, maxX = 0;
  for (const b of blocks) {
    if (x > 0 && x + b.w > sheetW) { x = 0; y += shelfH + GAP_Y; shelfH = 0; }
    const originX = EDGE + x, originY = EDGE + y;
    const cells = b.withTag ? [tagNodeId(b.id), ...b.ids] : b.ids;
    cells.forEach((id, i) => {
      placed.push(pin({ id, kind: id.startsWith("tag:") && b.withTag && i === 0 ? "tag" : "host", x: originX + FRAME + (i % b.cols) * px, y: originY + FRAME + Math.floor(i / b.cols) * py, pinned: false, cluster: b.id }));
    });
    clusters.push({ id: b.id, label: b.id === UNTAGGED ? "No tag" : b.id, x: originX, y: originY, w: b.w, h: b.h, hosts: b.ids, ...(b.withTag ? { tagNode: tagNodeId(b.id) } : {}) });
    x += b.w + GAP_X;
    shelfH = Math.max(shelfH, b.h);
    maxX = Math.max(maxX, x - GAP_X);
  }
  const size = { w: EDGE * 2 + maxX, h: EDGE * 2 + y + shelfH };
  return { nodes: placed, size: fit(placed, size, nodeW, nodeH), clusters };
}

/** A pin beyond the sheet grows it, so a pinned node is never outside the graph's frame. */
function fit(nodes: readonly Placed[], size: { w: number; h: number }, nodeW: number, nodeH: number): { w: number; h: number } {
  let { w, h } = size;
  for (const n of nodes) { if (n.pinned) { w = Math.max(w, n.x + nodeW + EDGE); h = Math.max(h, n.y + nodeH + EDGE); } }
  return { w: Math.ceil(w), h: Math.ceil(h) };
}
