/** Mockup Settings panels: devices, account, users, grants and discovery, with test-double data. */
import { renderDevices, renderFacts } from "../../../../../packages/ui/src/settings-panels";
import type { SettingsSource } from "../views/settings-body.on-demand";
import type { ViewId } from "../model/types";
import type { MockWorld } from "./world";

export function createMockSettings(world: MockWorld): SettingsSource {
  return {
    sections: ["devices", "users", "grants", "discovery"],
    accountFacts: () => [
      { title: "Passkeys", rows: [{ key: "iPhone 15", value: "added 2 weeks ago" }, { key: "MacBook Pro", value: "added 3 months ago" }] },
      { title: "Recovery key", rows: [{ key: "Status", value: "saved" }, { key: "Last checked", value: "6 days ago" }] },
    ],
    render(section, pane, cx) {
      switch (section) {
        case "devices": return renderDevices(pane, {
          get devices() { return world.devices; },
          jump: (view) => { const id = view.toLowerCase() as ViewId; if (cx.views.has(id)) cx.nav.flyView(id); },
          signOut: (d) => { world.devices = world.devices.filter((x) => x.id !== d.id); cx.toast.show({ message: `${d.name} signed out` }); },
          rename: (_d, name) => { cx.toast.show({ message: `Renamed to ${name}` }); },
        });
        case "users": return renderFacts(pane, "Users", [{ title: "People", rows: [{ key: "kayg", value: "owner" }, { key: "mira", value: "operator" }, { key: "ops", value: "viewer" }] }]);
        case "grants": return renderFacts(pane, "Access", [{ title: "Mesh", rows: [{ key: "Rules", value: String(world.grants.length) }, { key: "Via relay", value: String(world.grants.filter((g) => g.via).length) }] }]);
        case "discovery": return renderFacts(pane, "Found hosts", [{ title: "Sources", rows: [{ key: "NetBird", value: "on" }, { key: "Tailscale", value: "on" }, { key: "known_hosts", value: "on" }, { key: "SSH config", value: "on" }] }]);
        default: return undefined;
      }
    },
  };
}
