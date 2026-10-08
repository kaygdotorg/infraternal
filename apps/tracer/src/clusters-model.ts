/**
 * Data and geometry for the clusters concept mockup (`?proto=clusters`, issue #89).
 *
 * One infinite canvas holds *views* (internally "clusters"). Each view is a tidy tiled group
 * of windows: columns side by side, each column a vertical stack that scrolls on its own. The
 * Topology view is the exception: it lays small node cards out as a graph. This module is pure
 * (no DOM) so the placement rules can be tested on their own:
 *
 * - A view's *box* is its content plus a fixed margin, rounded up to whole grid cells.
 * - Boxes sit on a coarse grid (`CELL`) and never overlap. Dropping one on another pushes the
 *   other aside along the axis of least overlap, and that one pushes its neighbours in turn.
 * - Which views exist for a person is decided by their grants, never by what they created.
 *
 * Everything here is mock data (the test double); nothing is persisted.
 */
import type { HostPlatform } from "../../../packages/ui/src/host-icons";

export const CELL = 120;
/** Space inside a box around the content: left, top (room for the view label), right, bottom. */
export const MARGIN = { l: 48, t: 96, r: 48, b: 48 };
export const COLUMN_GAP = 12;

export type WindowKind = "terminal" | "containers" | "logs" | "node";
export type ViewId = "console" | "containers" | "topology";
export type Role = "viewer" | "operator" | "new";

export interface WindowModel {
  id: string;
  kind: WindowKind;
  /** Host (or tag) name shown in the pill. */
  host: string;
  session?: string;
  user?: string;
  os?: HostPlatform;
  /** Fixed height in px; a window without one shares its column's height equally. */
  h?: number;
  lines?: string[];
}

export interface ColumnModel { id: string; w: number; wins: WindowModel[] }

export interface NodeModel { id: string; kind: "host" | "tag"; label: string; x: number; y: number; detail: string; sub: string; os?: HostPlatform }

export interface Grant { id: string; from: string; to: string; via?: string }

export interface ViewModel {
  id: ViewId;
  name: string;
  layout: "tiled" | "graph";
  cols: ColumnModel[];
  nodes: NodeModel[];
  /** Content size of a graph view. */
  graph?: { w: number; h: number };
  x: number;
  y: number;
}

export interface Metrics { colW: number; clh: number; narrow: boolean; nodeW: number; nodeH: number }

/**
 * Sizes follow the viewport so a snapped view fills it: on a phone a column is the safe-area width minus a
 * sliver for each neighbour to peek in; on a desktop three columns fill the width; a column is always as tall
 * as the viewport (D119: windows tile the pane).
 */
export const metricsFor = (width: number, height: number, coarse: boolean): Metrics => {
  const narrow = coarse || width < 720;
  const colW = narrow ? Math.max(260, Math.min(520, Math.round(width - 28))) : Math.max(400, Math.min(640, Math.round((width - 24) / 3)));
  const clh = Math.max(360, Math.round(height));
  return { colW, clh, narrow, nodeW: narrow ? 200 : 208, nodeH: 104 };
};

/** Size of the content (the tiled columns, or the graph canvas). */
export function contentSize(view: ViewModel, m: Metrics): { w: number; h: number } {
  if (view.layout === "graph") return view.graph ?? { w: 880, h: 400 };
  const n = Math.max(1, view.cols.length);
  const w = view.cols.length ? view.cols.reduce((sum, c) => sum + c.w, 0) + COLUMN_GAP * (n - 1) : m.colW;
  return { w, h: view.cols.length ? m.clh : Math.round(m.clh * 0.7) };
}

export interface Box { id: string; x: number; y: number; w: number; h: number }

export function boxOf(view: ViewModel, m: Metrics): Box {
  const c = contentSize(view, m);
  const w = Math.ceil((c.w + MARGIN.l + MARGIN.r) / CELL) * CELL;
  const h = Math.ceil((c.h + MARGIN.t + MARGIN.b) / CELL) * CELL;
  return { id: view.id, x: view.x, y: view.y, w, h };
}

export const snapToGrid = (v: number): number => Math.round(v / CELL) * CELL;

const overlaps = (a: Box, b: Box): boolean => a.x < b.x + b.w && b.x < a.x + a.w && a.y < b.y + b.h && b.y < a.y + a.h;

/**
 * Returns every box's position after `fixedId` is held where it is and the others that it
 * overlaps are pushed aside. A pushed box pushes the boxes it now overlaps (never the fixed
 * one). Each push is a whole number of cells because every box edge sits on the grid.
 */
export function resolve(boxes: Box[], fixedId: string): Map<string, { x: number; y: number }> {
  const at = new Map(boxes.map((b) => [b.id, { ...b }]));
  const fixed = new Set([fixedId]);
  const queue = [fixedId];
  for (let guard = 0; queue.length && guard < 64; guard++) {
    const pusher = at.get(queue.shift()!)!;
    for (const other of at.values()) {
      if (other.id === pusher.id || fixed.has(other.id) || !overlaps(pusher, other)) continue;
      const options = [
        { dx: pusher.x + pusher.w - other.x, dy: 0 },
        { dx: -(other.x + other.w - pusher.x), dy: 0 },
        { dx: 0, dy: pusher.y + pusher.h - other.y },
        { dx: 0, dy: -(other.y + other.h - pusher.y) },
      ];
      // Least travel wins; on a tie prefer moving away to the right or down.
      const best = options.reduce((a, b) => (Math.abs(b.dx) + Math.abs(b.dy) < Math.abs(a.dx) + Math.abs(a.dy) ? b : a));
      other.x += best.dx;
      other.y += best.dy;
      queue.push(other.id);
    }
  }
  return new Map([...at.values()].map((b) => [b.id, { x: b.x, y: b.y }]));
}

// ---- mock people, grants and content -------------------------------------------------------------

export const HOST_NAMES = ["build-01", "edge-arm", "nix-cache", "studio-mac"] as const;
/** Hosts a viewer's grants cover. */
export const VIEWER_HOSTS = ["build-01", "nix-cache"];

export const TAGS: Record<string, string[]> = { "tag:ops": ["studio-mac"], "tag:ci": ["build-01"] };

export const INITIAL_GRANTS: Grant[] = [
  { id: "g1", from: "build-01", to: "nix-cache" },
  { id: "g2", from: "build-01", to: "edge-arm", via: "fra-relay" },
  { id: "g3", from: "nix-cache", to: "studio-mac" },
  { id: "g4", from: "edge-arm", to: "nix-cache" },
  { id: "g5", from: "tag:ops", to: "build-01" },
  { id: "g6", from: "tag:ops", to: "nix-cache" },
  { id: "g7", from: "tag:ci", to: "nix-cache" },
];

/** Hosts a node (a host or a tag) stands for. */
export const hostsOf = (id: string): string[] => (id.startsWith("tag:") ? TAGS[id] ?? [] : [id]);

/** Hosts that `host` can reach through the grants, with the relay when the route needs one. */
export function reach(host: string, grants: Grant[]): Array<{ host: string; via?: string }> {
  const out = new Map<string, { host: string; via?: string }>();
  for (const g of grants) {
    if (!hostsOf(g.from).includes(host)) continue;
    for (const t of hostsOf(g.to)) if (t !== host && !out.has(t)) out.set(t, { host: t, ...(g.via ? { via: g.via } : {}) });
  }
  return [...out.values()];
}

export interface ContainerRow { name: string; image: string; state: "running" | "restarting" | "exited"; cpu: string }
export const CONTAINERS: ContainerRow[] = [
  { name: "web-api", image: "nginx:1.27", state: "running", cpu: "0.4%" },
  { name: "postgres", image: "postgres:16", state: "running", cpu: "1.2%" },
  { name: "cache", image: "redis:7.4", state: "running", cpu: "0.1%" },
  { name: "worker", image: "registry.local/worker:41", state: "restarting", cpu: "12.8%" },
  { name: "proxy", image: "traefik:v3.2", state: "exited", cpu: "0%" },
];

export const LOG_LINES = [
  "11:02:13  web-api  GET /healthz 200 1ms",
  "11:02:14  web-api  GET /v1/hosts 200 8ms",
  "11:02:14  web-api  GET /v1/hosts/build-01 200 5ms",
  "11:02:15  web-api  POST /v1/sessions 201 21ms",
  "11:02:19  web-api  GET /healthz 200 1ms",
  "11:02:22  web-api  GET /v1/mesh/grants 200 6ms",
  "11:02:24  web-api  upstream worker: connection reset",
  "11:02:24  web-api  retrying upstream worker (1/3)",
  "11:02:25  web-api  upstream worker: ok",
  "11:02:29  web-api  GET /healthz 200 1ms",
  "11:02:33  web-api  GET /v1/sessions 200 4ms",
  "11:02:39  web-api  GET /healthz 200 1ms",
];

export const shellLines = (user: string, host: string, extra: string): string[] => [
  `${user}@${host}:~$ ${extra}`,
  "",
  `${user}@${host}:~$ uptime`,
  " 11:06:51 up 18 days,  6:42,  1 user,  load average: 0.42, 0.38, 0.31",
  "",
  `${user}@${host}:~$ `,
];

/** Builds the views a person with this role sees. Hosts come from the test double. */
export function buildViews(role: Role, m: Metrics, screens: Map<string, { os: HostPlatform; user: string; screen: string[] }>, omit: string[] = []): ViewModel[] {
  const hostWin = (name: string, h?: number): WindowModel => {
    const s = screens.get(name);
    return { id: `w-${name}`, kind: "terminal", host: name, user: s?.user ?? "kayg", os: s?.os ?? "unknown", ...(h ? { h } : {}), lines: s?.screen ?? [`kayg@${name}:~$ `] };
  };
  const names = role === "viewer" ? VIEWER_HOSTS : role === "new" ? [] : HOST_NAMES.filter((n) => !omit.includes(n));
  const col = (id: string, wins: WindowModel[], w = m.colW): ColumnModel => ({ id, w, wins });
  const cols: ColumnModel[] = [];
  if (role === "viewer") {
    cols.push(col("c1", [hostWin("build-01")]), col("c2", [hostWin("nix-cache")]));
  } else if (names.length) {
    // Three columns, the middle one taller than the view so it scrolls.
    const pick = (n: string) => (names.includes(n) ? [n] : []);
    const c1 = pick("build-01"), c2 = [...pick("nix-cache"), ...pick("edge-arm")], c3 = pick("studio-mac");
    const tall = 0.62; // of the column's height (a ratio, so a resize keeps it)
    if (c1.length) cols.push(col("c1", c1.map((n) => hostWin(n))));
    if (c2.length) cols.push(col("c2", c2.map((n) => hostWin(n, c2.length > 1 ? tall : undefined))));
    if (c3.length) cols.push(col("c3", c3.map((n) => hostWin(n))));
  }
  const console_: ViewModel = { id: "console", name: "Console", layout: "tiled", cols, nodes: [], x: 0, y: 0 };
  if (role !== "operator") return [console_];

  const listW = Math.round(m.colW * 0.9), logsW = Math.round(m.colW * 1.25);
  const containers: ViewModel = {
    id: "containers", name: "Containers", layout: "tiled", x: 0, y: 0,
    cols: [
      col("l", [{ id: "w-containers", kind: "containers", host: "build-01", session: "containers" }], listW),
      col("g", [{ id: "w-logs", kind: "logs", host: "build-01", session: "logs · web-api", lines: LOG_LINES }], logsW),
    ],
    nodes: [],
  };
  const nw = m.nodeW, nh = m.nodeH;
  const gx = [30, 340, 650], gy = [40, 250];
  const topology: ViewModel = {
    id: "topology", name: "Topology", layout: "graph", cols: [], x: 0, y: 0,
    graph: { w: gx[2]! + nw + 30, h: gy[1]! + nh + 30 },
    nodes: [
      { id: "tag:ops", kind: "tag", label: "tag:ops", x: gx[0]!, y: gy[0]!, detail: "1 member", sub: "studio-mac" },
      { id: "build-01", kind: "host", label: "build-01", x: gx[1]!, y: gy[0]!, detail: "10.69.69.71", sub: "direct · 42 ms", os: "ubuntu" },
      { id: "edge-arm", kind: "host", label: "edge-arm", x: gx[2]!, y: gy[0]!, detail: "10.69.69.72", sub: "via fra-relay · 188 ms", os: "debian" },
      { id: "tag:ci", kind: "tag", label: "tag:ci", x: gx[0]!, y: gy[1]!, detail: "1 member", sub: "build-01" },
      { id: "nix-cache", kind: "host", label: "nix-cache", x: gx[1]!, y: gy[1]!, detail: "10.69.69.73", sub: "direct · 31 ms", os: "nixos" },
      { id: "studio-mac", kind: "host", label: "studio-mac", x: gx[2]!, y: gy[1]!, detail: "100.86.4.21", sub: "direct · 58 ms", os: "apple" },
    ],
  };
  // Desktop: Console top left, Containers under it, Topology to the right. Phone: one stack.
  // Console first; the others are placed by their real sizes (a view is as tall as the viewport).
  const box = (v: ViewModel) => boxOf(v, m);
  containers.y = box(console_).h;
  if (m.narrow) topology.y = containers.y + box(containers).h;
  else topology.x = box(console_).w + CELL;
  const out = [console_, containers, topology];
  // Console may grow wider than its default box; keep the order stable and the starts on the grid.
  return out;
}
