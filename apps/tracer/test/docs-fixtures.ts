// SPDX-License-Identifier: AGPL-3.0-only
/**
 * What the test double serves when it runs for the docs' figures (`TRACER_DATASET=docs`, #302): the same hosts and sessions as
 * the mockups, with the plain names of docs-dataset.ts (applied to every JSON answer by `sendJson`) and sessions that read
 * like a person's own: "backups", "website", "notes". The shell screens are short, ordinary and free of anything internal.
 *
 * The double's other answers (the owner, the instance's host name) change in mock-server.ts under the same switch.
 */
import type { PrototypeHostFixture } from "./prototype-fixtures";

/** A session as the docs show it, found by the id the fixtures already use. */
interface DocsSession { name: string; lastOutput: string; busyProgram?: string; screen: string[] }

const prompt = (user: string, host: string, path = "~"): string => `${user}@${host}:${path}$`;

/** By session id (they stay as the fixtures have them; only what a reader sees changes). */
const SESSIONS: Record<string, DocsSession> = {
  deploy: {
    name: "backups", lastOutput: "Backed up 2,418 files (14.2 GB)", busyProgram: "rsync",
    screen: [`${prompt("maya", "home-server")} rsync -a --info=progress2 ~/photos media-server:/backups/photos`, "      9.84G  69%   182.40MB/s    0:00:24", "      14.2G 100%   179.77MB/s    0:01:15 (xfr#2418, to-chk=0/2419)", "", `${prompt("maya", "home-server")} `],
  },
  journal: {
    name: "website", lastOutput: "Listening on http://localhost:8080",
    screen: [`${prompt("maya", "home-server", "~/website")} npm run dev`, "", "> website@1.0.0 dev", "> vite", "", "  ready in 312 ms", "  Local:   http://localhost:8080/"],
  },
  "apt-watch": {
    name: "updates", lastOutput: "Setting up linux-image-rpi …", busyProgram: "apt",
    screen: [`${prompt("pi", "raspberry-pi")} sudo apt upgrade`, "Reading package lists... Done", "The following packages will be upgraded:", "  linux-image-rpi libssl3 openssh-server", "Setting up linux-image-rpi ..."],
  },
  "edge-shell": {
    name: "shell", lastOutput: "Last login: Sun Nov 1 09:12:04",
    screen: [`${prompt("pi", "raspberry-pi")} df -h /`, "Filesystem      Size  Used Avail Use% Mounted on", "/dev/root        58G   21G   35G  38% /", "", `${prompt("pi", "raspberry-pi")} `],
  },
  "flake-dev": {
    name: "photos", lastOutput: "Indexed 18,422 photos",
    screen: [`${prompt("maya", "media-server")} photoprism index`, "indexing originals...", "Indexed 18,422 photos in 4m 12s", "", `${prompt("maya", "media-server")} `],
  },
  "gc-check": {
    name: "cleanup", lastOutput: "Freed 3.1 GB",
    screen: [`${prompt("maya", "media-server")} docker system prune -f`, "Total reclaimed space: 3.1GB", "", `${prompt("maya", "media-server")} `],
  },
  "release-notes": {
    name: "notes", lastOutput: "Nothing to commit",
    screen: [`${prompt("sam", "work-laptop")} git status`, "On branch main", "nothing to commit, working tree clean", "", `${prompt("sam", "work-laptop")} `],
  },
  "local-api": {
    name: "api", lastOutput: "Listening on 127.0.0.1:4100",
    screen: [`${prompt("sam", "work-laptop")} node server.js`, "Listening on 127.0.0.1:4100"],
  },
};

/** Applies the docs' sessions to the hosts of the windows fixture. */
export function docsPrototypeHosts(hosts: PrototypeHostFixture[]): PrototypeHostFixture[] {
  return hosts.map((host) => ({ ...host, sessions: host.sessions.map((session) => {
    const docs = SESSIONS[session.id];
    return docs ? { ...session, name: docs.name, lastOutput: docs.lastOutput, ...(docs.busyProgram ? { busyProgram: docs.busyProgram } : {}), screen: docs.screen } : session;
  }) }));
}

interface InventorySession { id: string; name: string; lastOutput: string; running?: string; screen: string[] }
/** Applies the docs' sessions to the session inventory (the sessions list of each window). */
export function docsSessionHosts<T extends { id: string; sessions: InventorySession[] }>(hosts: T[]): T[] {
  return hosts.map((host) => ({ ...host, sessions: host.sessions.map((session) => {
    const docs = SESSIONS[session.id];
    return docs ? { ...session, name: docs.name, lastOutput: docs.lastOutput, ...(docs.busyProgram ? { running: docs.busyProgram } : {}), screen: docs.screen } : session;
  }) }));
}
