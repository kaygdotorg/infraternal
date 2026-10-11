/** Mockup details source (#127): reads fake host and inventory data after a window pill is pressed. */
import type { DetailsSource } from "../windows/details-source";
import { detailsFacts } from "../windows/details-facts";
import { readExtendedInfo } from "../windows/extended-info";
import type { HostFactsSnapshot } from "../windows/details-source";
import type { SessionInventory } from "../sessions/inventory";
import type { MockWorld } from "./world";

const ADDRESS: Record<string, string> = { "build-01": "10.69.69.71", "edge-arm": "10.69.69.72", "nix-cache": "10.69.69.73", "studio-mac": "100.86.4.21" };
const REACH: Record<string, string> = { "edge-arm": "Through the relay fra-relay" };
const DELAY: Record<string, number> = { "build-01": 42, "edge-arm": 188, "nix-cache": 31, "studio-mac": 58 };

const OS_REPORTED: Record<string, { os: string; version: string }> = {
  ubuntu: { os: "Ubuntu", version: "24.04" }, debian: { os: "Debian GNU/Linux", version: "13" }, nixos: { os: "NixOS", version: "25.05" },
  apple: { os: "macOS", version: "15.1" }, redhat: { os: "Red Hat Enterprise Linux", version: "9.4" }, proxmox: { os: "Proxmox VE", version: "8.2" },
};

/** What a machine reports, invented for the mockups. Its system name follows the host's platform so the header and the rows agree. */
function factsFor(platform: string): HostFactsSnapshot {
  return {
    ...(OS_REPORTED[platform] ?? { os: "Linux", version: "" }),
    kernel: "6.12.43-amd64", architecture: "x86_64", cpuModel: "AMD EPYC 7B13", logicalCpus: 8,
    memory: { usedBytes: 3.1 * 1024 ** 3, totalBytes: 16 * 1024 ** 3 }, rootDisk: { usedBytes: 41 * 1024 ** 3, totalBytes: 120 * 1024 ** 3 },
    uptimeSeconds: 1_209_600 + 7_200, loadAverage: [0.42, 0.37, 0.31], mode: "embedded", executionUid: 1000, engines: ["Docker"],
    init: "systemd", virtualization: "KVM", shell: "/bin/zsh", locale: "en_US.UTF-8",
  };
}

export function createMockDetails(world: MockWorld, inventory: SessionInventory): DetailsSource {
  return {
    facts(rec) {
      if (rec.model.kind !== "terminal") return undefined;
      const h = rec.model.host;
      const screen = world.screens.get(h);
      const record = rec.model.sessionId ? inventory.get(h, rec.model.sessionId) : undefined;
      const other = rec.model.sessionId ? inventory.sizedFor(h, rec.model.sessionId) : undefined;
      const os = rec.model.os ?? screen?.os ?? "unknown";
      return detailsFacts({
        extended: readExtendedInfo(),
        host: { facts: factsFor(os), name: h, user: rec.model.user ?? screen?.user ?? "kayg", os, address: ADDRESS[h] ?? "", reach: REACH[h] ?? "Directly" },
        connection: { state: "connected", delayMs: DELAY[h] ?? 40, encrypted: true },
        session: { name: rec.model.session ?? record?.name ?? "", started: "Today, 09:14", ...(record ? { lastUsed: record.age, size: record.size, sizedBy: other ? other.name : "This device" } : {}), ...(record?.running ? { lastCommand: record.running } : {}) },
      });
    },
  };
}
