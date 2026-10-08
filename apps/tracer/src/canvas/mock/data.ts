/**
 * Mock people, hosts, grants and content for the mockup scenes (`?mock=1&proto=clusters`). Test-double data only:
 * nothing here may be imported by the product path (the product reads hosts, sessions and grants through the
 * adapters in `sessions/` and `mesh/`).
 */
import type { HostPlatform } from "../../../../../packages/ui/src/host-icons";
import { CELL, boxOf, type Metrics } from "../layout/geometry";
import { buildSettingsView } from "../views/settings";
import type { ColumnModel, Grant, ViewModel, WindowModel } from "../model/types";

/** Who is signed in: grants decide the views. "asha" is a second person with a viewer's grants (two hosts). */
export type Role = "viewer" | "operator" | "new" | "asha";
/** The username the role stands for (the owner is kayg; names are never shortened). */
export const usernameOf = (role: Role): string => (role === "asha" ? "asha" : "kayg");
export const PEOPLE = ["kayg", "asha", "ravi"];
export const GROUPS: Record<string, string[]> = { ops: ["kayg", "asha"], sre: ["ravi", "asha"] };

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
export function buildViews(roleIn: Role, m: Metrics, screens: Map<string, { os: HostPlatform; user: string; screen: string[] }>, omit: string[] = [], withIncident = false): ViewModel[] {
  const role: Exclude<Role, "asha"> = roleIn === "asha" ? "viewer" : roleIn;
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
  const settings = buildSettingsView(role === "operator", m);
  if (role !== "operator") { settings.x = boxOf(console_, m).w + CELL; return [console_, settings]; }

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
  const mesh: ViewModel = {
    id: "mesh", name: "Mesh", layout: "graph", cols: [], x: 0, y: 0,
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
  // Desktop: Console top left, Containers under it, Mesh to the right. Phone: one stack.
  // Console first; the others are placed by their real sizes (a view is as tall as the viewport).
  const box = (v: ViewModel) => boxOf(v, m);
  containers.y = box(console_).h;
  if (m.narrow) mesh.y = containers.y + box(containers).h;
  else mesh.x = box(console_).w + CELL;
  const incident = withIncident ? incidentView(m, screens) : undefined;
  if (incident) {
    if (m.narrow) incident.y = mesh.y + boxOf(mesh, m).h; else { incident.x = mesh.x; incident.y = boxOf(mesh, m).h; }
  }
  const above = incident ?? mesh;
  if (m.narrow) settings.y = above.y + boxOf(above, m).h; else { settings.x = mesh.x; settings.y = above.y + boxOf(above, m).h; }
  const out = [console_, containers, mesh, ...(incident ? [incident] : []), settings];
  // Console may grow wider than its default box; keep the order stable and the starts on the grid.
  return out;
}


/** The sender's own working view for the sharing scene: two shells and a log, one of them on a host asha's grants do not cover. */
export function incidentView(m: Metrics, screens: Map<string, { os: HostPlatform; user: string; screen: string[] }>): ViewModel {
  const term = (host: string, id: string): WindowModel => {
    const sc = screens.get(host);
    return { id, kind: "terminal", host, user: sc?.user ?? "kayg", os: sc?.os ?? "unknown", lines: sc?.screen ?? [`kayg@${host}:~$ `] };
  };
  return {
    id: "incident", name: "Incident", layout: "tiled", nodes: [], x: 0, y: 0,
    cols: [
      { id: "i1", w: m.colW, wins: [term("build-01", "i-build-01")] },
      { id: "i2", w: m.colW, wins: [term("edge-arm", "i-edge-arm"), { id: "i-logs", kind: "logs", host: "build-01", session: "logs · web-api", lines: LOG_LINES, h: 0.4 }] },
    ],
  };
}

/** A copy of a view as the recipient gets it: their own, with hosts outside their grants shown as "no access". */
export function copyForRecipient(snapshot: ViewModel, from: string, allowedHosts: readonly string[], idSuffix: string): ViewModel {
  const copy: ViewModel = JSON.parse(JSON.stringify(snapshot)) as ViewModel;
  copy.id = `${snapshot.id}-from-${from}-${idSuffix}`;
  copy.name = `${snapshot.name} (from ${from})`;
  copy.from = from;
  for (const col of copy.cols) for (const w of col.wins) {
    w.id = `${copy.id}:${w.id}`;
    if (w.kind === "terminal" && !allowedHosts.includes(w.host)) { w.noAccess = true; w.lines = []; }
  }
  return copy;
}