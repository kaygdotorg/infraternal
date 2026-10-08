/**
 * The mockup world: who is signed in, which hosts exist, what the test double shows for them. One object shared
 * by the mock adapters and the scenes. Test-double data only; the product never imports this.
 */
import type { HostPlatform } from "../../../../../packages/ui/src/host-icons";
import type { DeviceRow } from "../../../../../packages/ui/src/settings-panels";
import { INITIAL_GRANTS, type Role } from "./data";
import type { Grant } from "../model/types";

export interface MockScreen { os: HostPlatform; user: string; screen: string[] }
interface Fixture { hosts?: Array<{ name: string; user: string; os: HostPlatform; sessions: Array<{ screen: string[] }> }> }

export interface MockWorld {
  role: Role;
  /** Hosts a scene leaves out of Console (so the palette can open them). */
  omit: string[];
  /** A role chosen by hand (or by URL) sticks across scenes. */
  forcedRole: boolean;
  screens: Map<string, MockScreen>;
  grants: Grant[];
  devices: DeviceRow[];
}

export const initialDevices = (): DeviceRow[] => [
  { id: "d1", name: "iPhone 15", kind: "phone", type: "iOS · Safari", lastSeen: "now", view: "Console", online: true, current: true },
  { id: "d2", name: "MacBook Pro", kind: "laptop", type: "macOS · Chrome", lastSeen: "now", view: "Mesh", online: true },
  { id: "d3", name: "iPad", kind: "tablet", type: "iPadOS · Safari", lastSeen: "2 days ago", view: "Containers", online: false },
  { id: "d4", name: "Work laptop", kind: "desktop", type: "Linux · Firefox", lastSeen: "3 weeks ago", view: "Console", online: false },
];

/** The hosts the signed-in role may open shells on. */
export const allowedHosts = (role: Role): string[] => (role === "viewer" || role === "asha" ? ["build-01", "nix-cache"] : role === "new" ? [] : ["build-01", "edge-arm", "nix-cache", "studio-mac"]);

export async function createMockWorld(role: Role, forced: boolean): Promise<MockWorld> {
  const screens = new Map<string, MockScreen>();
  try {
    const data = await fetch("/__mock/proto/windows", { credentials: "same-origin" }).then((r) => (r.ok ? (r.json() as Promise<Fixture>) : undefined));
    for (const h of data?.hosts ?? []) screens.set(h.name, { os: h.os, user: h.user, screen: h.sessions[0]?.screen ?? [] });
  } catch { /* the mock fixture is optional: windows then show an empty prompt */ }
  return { role, omit: [], forcedRole: forced, screens, grants: INITIAL_GRANTS.map((g) => ({ ...g })), devices: initialDevices() };
}
