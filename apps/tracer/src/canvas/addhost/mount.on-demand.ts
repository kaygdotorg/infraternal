// SPDX-License-Identifier: AGPL-3.0-only
/**
 * The add-host flow as the product canvas mounts it (#87, D183, D255): where the wizard is drawn (a canvas window, or an overlay
 * on a phone), and what the canvas does with each host as it finishes enrolling (open its shell, show the rest of its setup in the
 * window's machine pill). The person only reaches this by choosing "Add hosts", so it is its own chunk (D188, #322): `product.ts` holds a
 * handle that fetches it when the browser is idle and on the first tap. The wizard itself is a further on-demand module.
 */
import { onDemand } from "../../on-demand";
import type { CoreScreen } from "../../core-screen";
import type { HostPlatform } from "../../../../../packages/ui/src/host-icons";
import type { Adapters, Ctx } from "../context";
import type { LiveSessions } from "../sessions/live";
import type { LiveInventory } from "../sessions/live-inventory";
import { createAddHost, type AddHost } from "./index";
import { attachSetup, warmSetup } from "./setup-attach";
import { createOverlayFlowHost } from "./flow-host";
import type { ProvisioningService } from "./service";
import { createWindowFlowHost } from "./window-host";

/** What the canvas lends the flow; all of it is read when a host enrols, never at mount (the canvas is still being made then). */
export interface AddHostDeps {
  service: () => Promise<ProvisioningService>;
  cx: () => Ctx;
  sessions: LiveSessions;
  inventory: LiveInventory;
  /** Hosts whose shell is attached before the account inventory admits them: snapshots must not detach those windows. */
  setupPendingHostIds: Set<string>;
  removal: NonNullable<Adapters["hostRemoval"]>;
  applyIdentities(hosts: readonly { id: string; name: string; user?: string; os?: HostPlatform }[]): void;
}

export function mountAddHost(core: CoreScreen, deps: AddHostDeps): AddHost {
  const addHost = createAddHost(core, {
    service: deps.service, sink: { setupInPill: true, prepareTerminal() {
      const font = core.font();
      // Optional preparation shares the normal open path's cached resources.
      // A failed prefetch leaves the eventual terminal open responsible for its error.
      void onDemand(() => import("../../terminal")).then(({ TerminalClient }) => TerminalClient.prepare(font)).catch(() => {});
    }, enrolled(hosts, status) {
      for (const host of hosts) {
        const hostId = host.hostId;
        if (!hostId) { core.toast.show({ message: "The host did not return its connection identity. Add it again.", tone: "error", duration: 5000 }); continue; }
        deps.sessions.registerHost({ id: hostId, name: host.name, ...(host.user ? { user: host.user } : {}), os: host.os, ...(host.address ? { address: host.address } : {}) });
        if (host.sessionId) {
          deps.setupPendingHostIds.add(hostId);
          deps.inventory.attach(hostId, host.sessionId);
          // The shell is attachable now; install, join and start go on behind it and show in this window's machine pill.
          const rec = deps.cx().win.openSession(hostId, host.sessionId);
          if (rec) void attachSetup(rec, { host: host.name, hostId, status, remove: () => { const label = deps.removal.label(); return label ? { label, run: (anchor) => deps.removal.remove(hostId, host.name, anchor) } : undefined; }, onComplete: () => { deps.setupPendingHostIds.delete(hostId); } });
        } else deps.cx().win.open(hostId);
        deps.applyIdentities([{ id: hostId, name: host.name, ...(host.user ? { user: host.user } : {}), os: host.os }]);
      }
    }, openHost(hostId) { deps.cx().win.open(hostId); }, hasHost: (hostId) => deps.sessions.hosts().some((host) => host.id === hostId) },
    host: createWindowFlowHost(() => deps.cx(), createOverlayFlowHost(core.stage)),
  });
  return { open: () => { warmSetup(); addHost.open(); }, dispose: () => addHost.dispose() };
}
