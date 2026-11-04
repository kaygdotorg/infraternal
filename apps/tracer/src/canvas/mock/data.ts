/**
 * Mock people, hosts, grants and content for the mockup scenes (`?mock=1&proto=clusters`). Test-double data only:
 * nothing here may be imported by the product path (the product reads hosts, sessions and grants through the
 * adapters in `sessions/` and `mesh/`).
 */
import type { HostPlatform } from "../../../../../packages/ui/src/host-icons";
import { CELL, boxOf, type Metrics } from "../layout/geometry";
import { buildSettingsView } from "../views/settings";
import { meshView } from "../mesh/view";
import type { MeshSource } from "../mesh/source";
import type { ColumnModel, ContainerRow, Grant, ViewModel, WindowModel } from "../model/types";

/** Who is signed in: grants decide the views. "asha" is a second person with a viewer's grants (two hosts). */
export type Role = "viewer" | "operator" | "new" | "asha";
/** The username the role stands for (the owner is kayg; names are never shortened). */
export const usernameOf = (role: Role): string => (role === "asha" ? "asha" : "kayg");
/** The people the test double knows, for the sharing directory. */
export const PEOPLE = ["kayg", "asha", "ravi"];
/** The groups the test double knows, with their members. */
export const GROUPS: Record<string, string[]> = { ops: ["kayg", "asha"], sre: ["ravi", "asha"] };

/** The hosts of the test double's world. */
export const HOST_NAMES = ["build-01", "edge-arm", "nix-cache", "studio-mac"] as const;
/** Hosts a viewer's grants cover. */
export const VIEWER_HOSTS = ["build-01", "nix-cache"];

/** The tags of the test double's world, each with the hosts that carry it. */
export const TAGS: Record<string, string[]> = { "tag:ops": ["studio-mac"], "tag:ci": ["build-01"] };

/** The Mesh grants the test double starts with. A grant with `via` goes through that relay host. */
export const INITIAL_GRANTS: Grant[] = [
  { id: "g1", from: "build-01", to: "nix-cache" },
  { id: "g2", from: "build-01", to: "edge-arm", via: "fra-relay" },
  { id: "g3", from: "nix-cache", to: "studio-mac" },
  { id: "g4", from: "edge-arm", to: "nix-cache" },
  { id: "g5", from: "tag:ops", to: "build-01" },
  { id: "g6", from: "tag:ops", to: "nix-cache" },
  { id: "g7", from: "tag:ci", to: "nix-cache" },
];


/** The container rows the test double's containers window shows. */
export const CONTAINERS: ContainerRow[] = [
  { name: "web-api", image: "nginx:1.27", state: "running", cpu: "0.4%" },
  { name: "postgres", image: "postgres:16", state: "running", cpu: "1.2%" },
  { name: "cache", image: "redis:7.4", state: "running", cpu: "0.1%" },
  { name: "worker", image: "registry.local/worker:41", state: "restarting", cpu: "12.8%" },
  { name: "proxy", image: "traefik:v3.2", state: "exited", cpu: "0%" },
];

/** A varied, repeatable stream of web-api log lines: mostly requests, now and then a warning or an error. */
const PATHS = ["/v1/hosts", "/v1/hosts/build-01", "/v1/hosts/nix-cache", "/v1/sessions", "/v1/sessions/shell", "/v1/mesh/grants", "/v1/mesh/status", "/v1/containers", "/v1/layouts/default", "/v1/devices", "/healthz"];
/** Formats a time as `HH:MM:SS` in local time. */
const hhmmss = (t: number): string => { const d = new Date(t); return [d.getHours(), d.getMinutes(), d.getSeconds()].map((n) => String(n).padStart(2, "0")).join(":"); };
/** The `n`th line of the stream (n = 0, 1, 2, ...), stamped `t`. The same `n` always gives the same text. */
export const logLine = (n: number, t: number): string => {
  const r = (Math.imul(n + 1, 2654435761) >>> 0) / 2 ** 32; // a repeatable spread in [0, 1)
  const r2 = (Math.imul(n + 7, 40503) >>> 0) % 1000;
  const stamp = `${hhmmss(t)}  web-api  `;
  if (n % 61 === 17) return `${stamp}ERROR upstream worker: connection reset (attempt ${1 + (n % 3)} of 3)`;
  if (n % 23 === 5) return `${stamp}WARN slow request: GET ${PATHS[n % 7]} took ${180 + (r2 % 420)}ms`;
  if (n % 47 === 30) return `${stamp}WARN session ${["shell", "journal", "release"][n % 3]} has 2 viewers; resize paused`;
  if (n % 29 === 11) return `${stamp}upstream worker: ok`;
  const path = PATHS[Math.floor(r * PATHS.length)]!;
  if (path === "/healthz") return `${stamp}GET /healthz 200 1ms`;
  const post = r2 % 9 === 0;
  return `${stamp}${post ? "POST" : "GET"} ${path} ${post ? 201 : r2 % 41 === 3 ? 304 : 200} ${1 + (r2 % 38)}ms`;
};
/** A backlog of `count` lines ending at `now`, a second or two apart, oldest first. */
export const logBacklog = (count: number, now: number): string[] => Array.from({ length: count }, (_, i) => logLine(i, now - (count - i) * 1400));
/** How many lines the backlog starts with: enough to fill the tallest window on a big screen several times over. */
export const LOG_BACKLOG = 240;
/** The initial backlog of log lines, ending now. */
export const LOG_LINES = logBacklog(LOG_BACKLOG, Date.now());

/** The lines a fake shell window starts with: a prompt for `user` on `host` showing the command `extra`, then output. */
export const shellLines = (user: string, host: string, extra: string): string[] => [
  `${user}@${host}:~$ ${extra}`,
  "",
  `${user}@${host}:~$ uptime`,
  " 11:06:51 up 18 days,  6:42,  1 user,  load average: 0.42, 0.38, 0.31",
  "",
  `${user}@${host}:~$ `,
];


/** Builds the views a person with this role sees. Hosts come from the test double. */
export function buildViews(roleIn: Role, m: Metrics, meshSource: MeshSource, screens: Map<string, { os: HostPlatform; user: string; screen: string[] }>, omit: string[] = [], withIncident = false, sessionOf?: (host: string) => { id: string; name: string } | undefined): ViewModel[] {
  const role: Exclude<Role, "asha"> = roleIn === "asha" ? "viewer" : roleIn;
  const hostWin = (name: string, h?: number): WindowModel => {
    const s = screens.get(name);
    const named = sessionOf?.(name);
    return { id: `w-${name}`, kind: "terminal", host: name, user: s?.user ?? "kayg", os: s?.os ?? "unknown", ...(named ? { session: named.name, sessionId: named.id } : {}), ...(h ? { h } : {}), lines: s?.screen ?? [`kayg@${name}:~$ `] };
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
  const mesh = meshView(meshSource, m);
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
