/**
 * Test-double session inventory for the gated sessions mockup (`?mock=1&proto=sessions`, D127, D178, D183).
 * The shapes are in `src/sessions-contract.ts`. This table never touches a PTY.
 */
import type { DeviceInfo, SessionRecord } from "../src/canvas/sessions/inventory";
import { forDocs } from "../docs-dataset";
import { docsSessionHosts } from "./docs-fixtures";

const prompt = (user: string, host: string, path = "~"): string => `${user}@${host}:${path}$`;

const plainSessionHosts: Array<{ id: string; sessions: SessionRecord[] }> = [
  {
    id: "live",
    sessions: [
      { id: "shell", name: "SSH shell", pinned: false, state: "open", lastOutput: "infraternal-dev:~$", age: "now", viewers: 1, size: "112×34", frecency: 9, screen: [] },
      { id: "htop", name: "htop", pinned: false, state: "detached", running: "htop", lastOutput: "Load average: 0.42 0.38 0.31", age: "22m", viewers: 0, size: "112×34", frecency: 4, activity: "output",
        screen: ["  CPU[|||||||||||                 31.2%]   Tasks: 118, 402 thr; 2 running", "  Mem[|||||||||||||||||||     5.82G/15.6G]   Load average: 0.42 0.38 0.31", "  Swp[                          0K/2.00G]   Uptime: 18 days, 06:42:11"] },
    ],
  },
  {
    id: "build-01",
    sessions: [
      { id: "deploy", name: "deploy", pinned: true, state: "open", running: "vim", lastOutput: "Reviewing release notes in vim", age: "now", viewers: 1, size: "84×30", frecency: 8, screen: [] },
      { id: "journal", name: "journal", pinned: false, state: "detached", running: "journalctl -f", lastOutput: "Started infraternal-agent.service", age: "5h", viewers: 0, size: "84×30", frecency: 5, activity: "output",
        screen: [`${prompt("kayg", "build-01")} journalctl -u infraternal-agent -f`, "Oct 08 09:02:13 build-01 infraternal-agent[991]: Connected to server", "Oct 08 09:02:13 build-01 infraternal-agent[991]: Session shim ready", "Oct 08 09:02:14 build-01 infraternal-agent[991]: Metrics snapshot sent", "Oct 08 09:05:40 build-01 infraternal-agent[991]: Reconnecting relay stream", "Oct 08 09:05:41 build-01 infraternal-agent[991]: Relay stream resumed", "Oct 08 09:11:07 build-01 infraternal-agent[991]: Started infraternal-agent.service"] },
      { id: "release", name: "release", pinned: false, state: "detached", lastOutput: "Finished release profile in 2m 14s", age: "12m", viewers: 0, size: "84×30", frecency: 6, activity: "ok",
        screen: [`${prompt("kayg", "build-01", "~/src/infraternal")} make release`, "   Compiling infraternal-protocol v0.1.0", "   Compiling infraternal-server v0.1.0", "    Finished release profile [optimized] target(s) in 2m 14s", "", `${prompt("kayg", "build-01", "~/src/infraternal")} _`] },
      { id: "tests", name: "cargo test", pinned: false, state: "detached", lastOutput: "test result: FAILED. 41 passed; 2 failed", age: "47m", viewers: 0, size: "84×30", frecency: 3, activity: "fail",
        screen: [`${prompt("kayg", "build-01", "~/src/infraternal")} cargo test -p infraternal-protocol`, "running 43 tests", "test codec::roundtrip_resume ... ok", "test codec::reject_oversize ... FAILED", "test stream::flow_control ... FAILED", "", "failures:", "    codec::reject_oversize", "    stream::flow_control", "", "test result: FAILED. 41 passed; 2 failed; 0 ignored", "", `${prompt("kayg", "build-01", "~/src/infraternal")} _`] },
      { id: "bench", name: "bench", pinned: true, state: "exited", lastOutput: "p99 echo 11.8 ms", age: "3h", viewers: 0, size: "84×30", frecency: 2, exit: { code: 0 },
        screen: [`${prompt("kayg", "build-01", "~/src/infraternal")} scripts/bench echo`, "echo p50  4.1 ms", "echo p99 11.8 ms", "budget    16.7 ms  ok"] },
      { id: "migrate", name: "migrate", pinned: false, state: "exited", lastOutput: "ERROR: relation \"sessions\" already exists", age: "1d", viewers: 0, size: "84×30", frecency: 1, exit: { code: 1 },
        screen: [`${prompt("kayg", "build-01", "~/src/infraternal")} sqlx migrate run`, "Applied 0001/migrate sessions (4.2 ms)", "ERROR: relation \"sessions\" already exists", "", "Error: while executing migration 2"] },
    ],
  },
  {
    id: "edge-arm",
    sessions: [
      { id: "apt-watch", name: "apt upgrade", pinned: false, state: "open", running: "apt upgrade", lastOutput: "Unpacking linux-image-arm64 …", age: "now", viewers: 2, size: "132×40", frecency: 7, screen: [] },
      { id: "edge-shell", name: "shell", pinned: false, state: "detached", lastOutput: "Last login: Wed Oct 8 11:06:42", age: "1h", viewers: 0, size: "132×40", frecency: 3,
        screen: [`${prompt("ops", "edge-arm")} df -h /`, "Filesystem      Size  Used Avail Use% Mounted on", "/dev/root        58G   21G   35G  38% /", "", `${prompt("ops", "edge-arm")} _`] },
    ],
  },
  {
    id: "nix-cache",
    sessions: [
      { id: "flake-dev", name: "flake-dev", pinned: true, state: "open", running: "nix develop", lastOutput: "devShell ready · nix develop", age: "now", viewers: 1, size: "100×32", frecency: 6, screen: [] },
    ],
  },
  {
    id: "studio-mac",
    sessions: [
      { id: "release-notes", name: "release-notes", pinned: false, state: "open", lastOutput: "working tree clean", age: "now", viewers: 1, size: "120×36", frecency: 5, screen: [] },
      { id: "local-api", name: "local-api", pinned: false, state: "detached", running: "node server.js", lastOutput: "listening on 127.0.0.1:4100", age: "7h", viewers: 0, size: "120×36", frecency: 2,
        screen: [`${prompt("mira", "studio-mac")} lsof -iTCP:4100 -sTCP:LISTEN`, "COMMAND  PID USER  FD  TYPE  NAME", "node    812 mira  21u IPv4  TCP localhost:4100 (LISTEN)", "", `${prompt("mira", "studio-mac")} _`] },
    ],
  },
];

/** The account's other devices: the one that typed last decides a shared session's size (D183). */
export const sessionDevices: DeviceInfo[] = [
  { id: "mbp", name: "MacBook Pro", kind: "laptop" },
  { id: "phone", name: "iPhone", kind: "phone" },
];

/** What the double serves: these sessions, or the docs' own when the double runs for the docs' figures (docs-dataset.ts). */
export const sessionHosts: Array<{ id: string; sessions: SessionRecord[] }> = process.env.TRACER_DATASET === "docs" ? forDocs(docsSessionHosts(plainSessionHosts)) : plainSessionHosts;
