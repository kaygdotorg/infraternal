// SPDX-License-Identifier: AGPL-3.0-only
/**
 * Subnet-route scenes for review (D197 M3, #580; `?mock=1&proto=clusters&routes=1`): the states the owner approved in
 * the J1172 mockup, put on the fake Mesh server (`mesh-server.ts`). The product adapter reads them exactly as it reads a
 * real server, so nothing here decides anything the server would: it only sets the server's rows and arrows, and
 * presses Approve where a scene shows the moment after it. The palette has a "Mockup: routes – …" row for each scene.
 */
import type { PaletteEntry } from "../../core-screen";
import { routesSource } from "../mesh/networks";
import type { FakeMeshServer, FakeRoute } from "./mesh-server";

/** One network of a scene: who advertises it, its state, and who already has an arrow to it. */
type SceneRoute = Omit<FakeRoute, "id" | "nodeId"> & { node: string; arrows?: readonly string[] };
/** A scene: the networks, whether to open Settings › Mesh › Networks, and an Approve to press once it is up. */
export interface RoutesScene { id: string; label: string; hint: string; routes: () => SceneRoute[]; window: boolean; approve?: string }

/** A network row of a scene. */
const net = (network: string, node: string, state: "pending" | "approved" | "declined", extra: Partial<SceneRoute> = {}): SceneRoute =>
  ({ network, node, advertised: true, approved: state === "approved", declined: state === "declined", masquerade: true, ...extra });

/** Every scene the owner reviews. The first is what `?routes=1` opens on. */
export const ROUTE_SCENES: readonly RoutesScene[] = [
  { id: "approved", label: "approved network with arrows", hint: "the Mesh view; one network approved, one waiting", window: false,
    routes: () => [net("192.168.10.0/24", "build-01", "approved", { arrows: ["tag:ops", "nix-cache"] }), net("10.20.0.0/16", "edge-arm", "pending")] },
  { id: "waiting", label: "waiting for approval", hint: "two advertisements, none approved", window: false,
    routes: () => [net("192.168.10.0/24", "build-01", "pending"), net("10.20.0.0/16", "edge-arm", "pending")] },
  { id: "window", label: "networks window", hint: "Settings · Mesh · Networks", window: true,
    routes: () => [net("192.168.10.0/24", "build-01", "approved", { arrows: ["tag:ops", "nix-cache"] }), net("10.20.0.0/16", "edge-arm", "pending"), net("172.20.0.0/16", "nix-cache", "declined")] },
  { id: "keep-source", label: "keep each machine's address", hint: "an approved network that shows the real source address", window: true,
    routes: () => [net("192.168.10.0/24", "build-01", "approved", { masquerade: false, arrows: ["tag:ops", "nix-cache"] }), net("10.20.0.0/16", "edge-arm", "approved", { arrows: ["studio-mac"] })] },
  { id: "overlap", label: "overlap refused", hint: "Approve on 192.168.0.0/16 while 192.168.10.0/24 is approved", window: true, approve: "192.168.0.0/16",
    routes: () => [net("192.168.10.0/24", "build-01", "approved", { arrows: ["tag:ops", "nix-cache"] }), net("192.168.0.0/16", "edge-arm", "pending")] },
  { id: "revoke", label: "revoke question", hint: "the question that names the network and the arrows it deletes", window: true,
    routes: () => [net("192.168.10.0/24", "build-01", "approved", { arrows: ["tag:ops", "nix-cache", "studio-mac"] })] },
  { id: "none", label: "nothing advertised", hint: "no machine advertises a network", window: true, routes: () => [] },
];

/** The scenes' palette rows and the way to play one on `server`. `openWindow` opens Settings › Mesh › Networks. */
export function createRouteScenes(server: () => FakeMeshServer, openWindow: () => void): { entries(): PaletteEntry[]; run(id: string): void } {
  return {
    entries: () => ROUTE_SCENES.map((s): PaletteEntry => ({ group: "Mockup", glyph: "◇", label: `Mockup: routes – ${s.label}`, hint: s.hint, action: `proto:routes:${s.id}` })),
    run(id) {
      const scene = ROUTE_SCENES.find((s) => s.id === id);
      if (!scene) return;
      server().setRoutes(scene.routes());
      // The overlap scene is the moment after Approve was pressed: the refusal is on the card and in the window. It waits for
      // the adapter to list the new rows (a few microtasks on the fake server), then presses Approve the way the card does.
      if (scene.approve) {
        const cidr = scene.approve;
        const press = (tries: number): void => {
          const n = routesSource()?.list().find((o) => o.cidr === cidr && o.state === "pending");
          if (n) void routesSource()!.approve(n.id).catch(() => undefined);
          else if (tries > 0) window.setTimeout(() => press(tries - 1), 20);
        };
        press(50);
      }
      if (scene.window) openWindow();
    },
  };
}
