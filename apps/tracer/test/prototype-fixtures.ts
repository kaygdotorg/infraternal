/** Test-double host and terminal data for the gated windows and add-host prototypes. */
import type { AddHostFixture } from "../src/add-host-contract";
import { forDocs } from "../docs-dataset";
import { docsPrototypeHosts } from "./docs-fixtures";

export interface PrototypeSessionFixture {
  id: string;
  name: string;
  lastOutput: string;
  age: string;
  viewers: number;
  size: string;
  fresh: boolean;
  busyProgram?: string;
  started: string;
  scrollback: string;
  screen: string[];
}

export interface PrototypeHostFixture {
  id: string;
  user: string;
  name: string;
  os: "ubuntu" | "debian" | "nixos" | "apple";
  osName: string;
  version: string;
  architecture: string;
  model: string;
  cpu: string;
  cores: number;
  memory: number;
  disk: number;
  uptime: string;
  load: string;
  kernel: string;
  init: string;
  virtualization: string;
  shell: string;
  locale: string;
  ips: string[];
  engines: string[];
  mode: "rootless" | "root";
  status: "live" | "reconnecting";
  connection: {
    route: string;
    transport: string;
    mesh: string;
    certificate: string;
    roundTrip: string;
    bytes: string;
    reconnects: number;
  };
  sessions: PrototypeSessionFixture[];
}

/** Static install snapshots and plausible host-local terminal output stay in the test double. */
const plainPrototypeHosts: PrototypeHostFixture[] = [
  {
    id: "build-01", user: "kayg", name: "build-01", os: "ubuntu", osName: "Ubuntu",
    version: "24.04.2 LTS", architecture: "x86_64", model: "ThinkCentre M90q Gen 3",
    cpu: "Intel Core i5-12500T", cores: 12, memory: 71, disk: 48, uptime: "18 days, 06:42",
    load: "0.42 · 0.38 · 0.31", kernel: "6.8.0-58-generic", init: "systemd 255.4",
    virtualization: "KVM guest", shell: "/usr/bin/zsh", locale: "en_US.UTF-8",
    ips: ["10.69.69.71", "192.168.1.31"], engines: ["Podman 5.0", "BuildKit 0.16"], mode: "root", status: "live",
    connection: { route: "relay · Frankfurt → host", transport: "WebSocket · TLS 1.3", mesh: "NetBird · connected", certificate: "valid for 71 days", roundTrip: "42 ms", bytes: "18.4 MiB in · 6.2 MiB out", reconnects: 1 },
    sessions: [
      { id: "deploy", name: "deploy", lastOutput: "Reviewing release notes in vim", age: "2h 14m", viewers: 1, size: "84 KB", fresh: true, busyProgram: "vim", started: "Today at 09:42", scrollback: "1,842 lines", screen: ["Ubuntu 24.04.2 LTS · GNU/Linux 6.8.0-58-generic", "", "kayg@build-01:~$ systemctl --failed", "  UNIT  LOAD  ACTIVE  SUB  DESCRIPTION", "", "0 loaded units listed.", "", "kayg@build-01:~$ printf '\\e[3mitalic\\e[0m'", "\u001b[3mitalic\u001b[0m regular \u001b[1mbold\u001b[0m \u001b[3mslanted\u001b[0m", "", "kayg@build-01:~$ cd ~/src/infraternal", "kayg@build-01:~/src/infraternal$ git status --short", " M apps/tracer/src/core-screen.ts", "", "kayg@build-01:~/src/infraternal$ vim docs/release.md", "" ] },
      { id: "journal", name: "journal", lastOutput: "Started infraternal-agent.service", age: "5h 08m", viewers: 0, size: "216 KB", fresh: false, started: "Today at 06:48", scrollback: "4,910 lines", screen: ["kayg@build-01:~$ journalctl -u infraternal-agent -n 5 --no-pager", "Oct 07 11:02:13 build-01 infraternal-agent[991]: Connected to server", "Oct 07 11:02:13 build-01 infraternal-agent[991]: Session shim ready", "Oct 07 11:02:14 build-01 infraternal-agent[991]: Metrics snapshot sent", "Oct 07 11:05:40 build-01 infraternal-agent[991]: Reconnecting relay stream", "Oct 07 11:05:41 build-01 infraternal-agent[991]: Relay stream resumed", "", "kayg@build-01:~$ _"] },
    ],
  },
  {
    id: "edge-arm", user: "ops", name: "edge-arm", os: "debian", osName: "Debian GNU/Linux",
    version: "12.8 (bookworm)", architecture: "aarch64", model: "Raspberry Pi 5 Model B Rev 1.0",
    cpu: "Cortex-A76", cores: 4, memory: 62, disk: 37, uptime: "3 days, 11:18",
    load: "1.12 · 0.86 · 0.73", kernel: "6.1.0-31-arm64", init: "systemd 252.31",
    virtualization: "Bare metal", shell: "/bin/bash", locale: "en_GB.UTF-8",
    ips: ["10.69.69.72", "192.168.1.72"], engines: ["Podman 4.3"], mode: "rootless", status: "reconnecting",
    connection: { route: "relay · Frankfurt → host", transport: "WebSocket · TLS 1.3", mesh: "Tailscale · connected", certificate: "valid for 28 days", roundTrip: "188 ms", bytes: "4.8 MiB in · 2.1 MiB out", reconnects: 3 },
    sessions: [
      { id: "apt-watch", name: "apt-upgrade", lastOutput: "Unpacking linux-image-arm64 …", age: "38m", viewers: 2, size: "126 KB", fresh: true, busyProgram: "apt", started: "Today at 11:18", scrollback: "2,106 lines", screen: ["Linux edge-arm 6.1.0-31-arm64 aarch64", "", "ops@edge-arm:~$ sudo apt-get upgrade", "Reading package lists... Done", "Building dependency tree... Done", "The following packages will be upgraded:", "  linux-image-arm64 openssl openssh-client", "", "Unpacking linux-image-arm64 (6.1.128-1) ...", "Progress: [=====================>         ] 64%", "", "ops@edge-arm:~$ _"] },
      { id: "edge-shell", name: "shell", lastOutput: "Last login: Tue Oct 7 11:06:42", age: "1h 02m", viewers: 0, size: "18 KB", fresh: false, started: "Today at 10:54", scrollback: "392 lines", screen: ["Linux edge-arm 6.1.0-31-arm64 aarch64", "", "ops@edge-arm:~$ df -h /", "Filesystem      Size  Used Avail Use% Mounted on", "/dev/root        58G   21G   35G  38% /", "", "ops@edge-arm:~$ _"] },
    ],
  },
  {
    id: "nix-cache", user: "kayg", name: "nix-cache", os: "nixos", osName: "NixOS",
    version: "25.05.20261004.8ec4a36", architecture: "x86_64-linux", model: "AMD Ryzen 7 5700G",
    cpu: "AMD Ryzen 7 5700G", cores: 16, memory: 44, disk: 63, uptime: "42 days, 02:17",
    load: "0.21 · 0.31 · 0.29", kernel: "6.12.48", init: "systemd 257.7",
    virtualization: "KVM host", shell: "/run/current-system/sw/bin/zsh", locale: "en_US.UTF-8",
    ips: ["10.69.69.73", "192.168.1.83"], engines: ["Nix 2.28", "Podman 5.4"], mode: "rootless", status: "live",
    connection: { route: "direct · NetBird peer", transport: "WebSocket · TLS 1.3", mesh: "NetBird · connected", certificate: "valid for 84 days", roundTrip: "31 ms", bytes: "52.2 MiB in · 11.8 MiB out", reconnects: 0 },
    sessions: [
      { id: "flake-dev", name: "flake-dev", lastOutput: "devShell ready · nix develop", age: "1h 46m", viewers: 1, size: "62 KB", fresh: true, started: "Today at 10:10", scrollback: "1,208 lines", screen: ["NixOS 25.05 · x86_64-linux", "", "kayg@nix-cache:~$ cd ~/src/infraternal", "kayg@nix-cache:~/src/infraternal$ nix develop", "warning: Git tree '/home/kayg/src/infraternal' is dirty", "", "devShell ready · rustc 1.91.0 · bun 1.3.8", "", "kayg@nix-cache:~/src/infraternal$ cargo check -q", "Finished `dev` profile [unoptimized + debuginfo]", "", "kayg@nix-cache:~/src/infraternal$ _"] },
      { id: "gc-check", name: "gc-check", lastOutput: "store paths: 18,422 · 126.8 GiB", age: "6h 12m", viewers: 0, size: "44 KB", fresh: false, started: "Today at 05:44", scrollback: "760 lines", screen: ["kayg@nix-cache:~$ nix-store --gc --print-live", "live paths: 18,422", "live size: 126.8 GiB", "", "kayg@nix-cache:~$ _"] },
    ],
  },
  {
    id: "studio-mac", user: "mira", name: "studio-mac", os: "apple", osName: "macOS",
    version: "Sequoia 15.1", architecture: "arm64", model: "MacBook Pro 14-inch (2023)",
    cpu: "Apple M2 Pro", cores: 10, memory: 58, disk: 52, uptime: "6 days, 19:25",
    load: "1.04 · 0.92 · 0.87", kernel: "Darwin 24.1.0", init: "launchd",
    virtualization: "Virtualization.framework", shell: "/bin/zsh", locale: "en_GB.UTF-8",
    ips: ["100.86.4.21", "192.168.1.44"], engines: ["OrbStack 1.9"], mode: "root", status: "live",
    connection: { route: "relay · Frankfurt → host", transport: "WebSocket · TLS 1.3", mesh: "Tailscale · connected", certificate: "valid for 56 days", roundTrip: "58 ms", bytes: "8.1 MiB in · 3.7 MiB out", reconnects: 1 },
    sessions: [
      { id: "release-notes", name: "release-notes", lastOutput: "working tree clean", age: "4h 24m", viewers: 1, size: "38 KB", fresh: true, started: "Today at 07:32", scrollback: "804 lines", screen: ["macOS Sequoia 15.1 · arm64", "", "mira@studio-mac:~/src/infraternal$ git status --short", "", "mira@studio-mac:~/src/infraternal$ git log -1 --oneline", "cecc7ec fix(tracer): hide the iOS native caret", "", "mira@studio-mac:~/src/infraternal$ xcodebuild -version", "Xcode 16.1", "Build version 16B40", "", "mira@studio-mac:~/src/infraternal$ _"] },
      { id: "local-api", name: "local-api", lastOutput: "listening on 127.0.0.1:4100", age: "7h 03m", viewers: 0, size: "72 KB", fresh: false, started: "Today at 04:53", scrollback: "1,460 lines", screen: ["mira@studio-mac:~$ lsof -iTCP:4100 -sTCP:LISTEN", "COMMAND  PID USER  FD  TYPE  NAME", "node    812 mira  21u IPv4  TCP localhost:4100 (LISTEN)", "", "mira@studio-mac:~$ _"] },
    ],
  },
];

/** Discovery and SSH-only probe outcomes used by the add-host mock, with no login attempt. */
const plainAddHostFixtures: AddHostFixture[] = [
  {
    id: "build-01", user: "ops", address: "10.69.69.71", operatingSystem: "Ubuntu 24.04",
    architecture: "x86_64", sources: ["netbird", "ssh-config"], reachability: "ready",
    evidence: "SSH answers on port 22.", alreadyAdded: true, rootAvailable: true,
    credentialRequired: false, authentication: "accepted",
  },
  {
    id: "edge-arm", user: "ops", address: "10.69.69.72", operatingSystem: "Debian 12",
    architecture: "aarch64", sources: ["tailscale", "known-hosts"], reachability: "ready",
    evidence: "SSH answers on port 22.", alreadyAdded: false, rootAvailable: true,
    credentialRequired: false, authentication: "accepted",
  },
  {
    id: "nix-cache", user: "builder", address: "10.69.69.73", operatingSystem: "RHEL 9.5",
    architecture: "x86_64", sources: ["ssh-config"], reachability: "ready",
    evidence: "SSH answers on port 22.", alreadyAdded: false, rootAvailable: true,
    credentialRequired: true, authentication: "refused",
  },
  {
    id: "pve01", user: "root", address: "10.69.69.74", operatingSystem: "Proxmox VE 8.4",
    architecture: "x86_64", sources: ["netbird"], reachability: "mesh-policy",
    evidence: "The mesh peer is connected, but its policy denies TCP 22.", alreadyAdded: false,
    rootAvailable: false, credentialRequired: false, authentication: "accepted",
  },
  {
    id: "rhel-build", user: "builder", address: "10.69.69.75", operatingSystem: "RHEL 9.5",
    architecture: "x86_64", sources: ["known-hosts", "ssh-config"], reachability: "ready",
    evidence: "SSH answers on port 22.", alreadyAdded: false, rootAvailable: true,
    credentialRequired: false, authentication: "accepted",
  },
  {
    id: "o1", user: "kayg", address: "10.69.69.41", operatingSystem: "Ubuntu 24.04",
    architecture: "aarch64", sources: ["netbird"], reachability: "ready",
    evidence: "SSH answers on port 22.", alreadyAdded: false, rootAvailable: true,
    credentialRequired: false, authentication: "accepted",
  },
  {
    id: "o2", user: "kayg", address: "10.69.69.52", operatingSystem: "Ubuntu 24.04",
    architecture: "aarch64", sources: ["netbird", "ssh-config"], reachability: "ready",
    evidence: "SSH answers on port 22.", alreadyAdded: false, rootAvailable: false,
    credentialRequired: false, authentication: "accepted",
  },
  {
    id: "remoternal", user: "kayg", address: "10.69.69.60", operatingSystem: "Debian 13",
    architecture: "x86_64", sources: ["tailscale", "known-hosts"], reachability: "ready",
    evidence: "SSH answers on port 22.", alreadyAdded: false, rootAvailable: true,
    credentialRequired: false, authentication: "accepted",
  },
  {
    id: "db-01", user: "ops", address: "10.69.69.81", operatingSystem: "RHEL 9.4",
    architecture: "x86_64", sources: ["ssh-config"], reachability: "ready",
    evidence: "SSH answers on port 22.", alreadyAdded: false, rootAvailable: true,
    credentialRequired: false, authentication: "accepted",
  },
  {
    id: "web-01", user: "deploy", address: "10.69.69.82", operatingSystem: "Ubuntu 22.04",
    architecture: "x86_64", sources: ["known-hosts"], reachability: "ready",
    evidence: "SSH answers on port 22.", alreadyAdded: false, rootAvailable: false,
    credentialRequired: false, authentication: "accepted",
  },
  {
    id: "mon-02", user: "ops", address: "10.69.69.83", operatingSystem: "Debian 12",
    architecture: "x86_64", sources: ["netbird", "known-hosts"], reachability: "ready",
    evidence: "SSH answers on port 22.", alreadyAdded: false, rootAvailable: true,
    credentialRequired: false, authentication: "accepted",
  },
  {
    id: "archive-01", user: "ops", address: "10.69.69.76", operatingSystem: "Debian 12",
    architecture: "x86_64", sources: ["known-hosts"], reachability: "unreachable",
    evidence: "A TCP connection to port 22 timed out; no login was attempted.",
    alreadyAdded: false, rootAvailable: false, credentialRequired: false, authentication: "accepted",
  },
];

/** What the double serves: these fixtures, or the docs' own when the double runs for the docs' figures (docs-dataset.ts). */
export const prototypeHosts: PrototypeHostFixture[] = process.env.TRACER_DATASET === "docs" ? forDocs(docsPrototypeHosts(plainPrototypeHosts)) : plainPrototypeHosts;
export const addHostFixtures: AddHostFixture[] = forDocs(plainAddHostFixtures);
