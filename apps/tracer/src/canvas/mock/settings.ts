/** Mockup Settings panels: devices, account, users, grants and discovery, with test-double data. */
import { renderDevices, renderFacts } from "../../../../../packages/ui/src/settings-panels";
import type { SettingsSource } from "../views/settings-body.on-demand";
import type { ViewId } from "../model/types";
import type { MockWorld } from "./world";
import { renderGroup, revealSetting } from "../settings-rows/body";
import { entriesOf, locate, rowsOf, spotBySection, valueOf, visibleMap } from "../settings-rows/model";

/**
 * `rows` is `?settings=sections` (issue #304): Settings as rows of windows, one row per component and one window per group,
 * read from the table in `settings-map/catalog.ts`. Without it the panels below are the whole of Settings, as before.
 */
export function createMockSettings(world: MockWorld, rows = false): SettingsSource {
  const map = () => visibleMap(world.role === "operator");
  return {
    sections: ["devices", "users", "grants", "discovery"],
    ...(rows ? { outline: { rows: () => rowsOf(map()), entries: () => entriesOf(map(), valueOf), locate: (target: string) => locate(map(), target), reveal: revealSetting } } : {}),
    accountFacts: () => [
      { title: "Passkeys", rows: [{ key: "iPhone 15", value: "added 2 weeks ago" }, { key: "MacBook Pro", value: "added 3 months ago" }] },
      { title: "Recovery key", rows: [{ key: "Status", value: "saved" }, { key: "Last checked", value: "6 days ago" }] },
    ],
    render(section, pane, cx) {
      const spot = rows ? spotBySection(map(), section) : undefined;
      if (spot) return renderGroup(cx, pane, `s-${section}`, spot);
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
