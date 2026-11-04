/**
 * Mockup Settings: the rows of windows (`settings-rows/source.ts`) with a test double behind them. Every setting is "backed" by
 * memory for the session, and the groups the server cannot list yet are filled with example facts and keys, so the whole of
 * Settings can be seen and tested before the server can say it. The product backs only what its server stores.
 */
import { renderDevices } from "../../../../../packages/ui/src/settings-panels";
import type { SettingValue } from "../../../../../packages/ui/src/setting-value";
import type { SettingsSource } from "../views/settings-body.on-demand";
import type { ViewId } from "../model/types";
import type { GroupData } from "../settings-rows/catalog";
import { onDemand } from "../../on-demand";
import { createRowsSource } from "../settings-rows/source";
import type { MockWorld } from "./world";

/** Every setting's value, kept for the session so a window that is rebuilt (a role change) keeps what was typed. */
const values = new Map<string, SettingValue>();
/** The wording and rules of each setting load on demand, as they do in the product (D188). */
const defs = () => onDemand(() => import("../settings-rows/entries.on-demand"));

const EXAMPLE: Readonly<Record<string, GroupData>> = {
  "you.apps": { keys: [
    { id: "k1", name: "laptop", kind: "cli", lastUsed: "2 hours ago", expires: "in 28 days" },
    { id: "k2", name: "Claude Code", kind: "mcp", lastUsed: "yesterday", expires: "in 21 days" },
    { id: "k3", name: "build script", kind: "cli", lastUsed: "6 days ago", expires: "in 24 days" },
  ] },
  "mesh.keys": { facts: [{ title: "Machine Authority", rows: [{ key: "Expires", value: "in 9 years" }, { key: "Lock", value: "locked until an administrator confirms with a passkey" }] }] },
  "mesh.access": { facts: [{ title: "Who Can Reach What", rows: [{ key: "Rules", value: "14" }, { key: "Through A Relay", value: "3" }, { key: "Open To Everyone", value: "none" }] }] },
  "mesh.connections": { facts: [{ title: "Now", rows: [{ key: "Direct", value: "5" }, { key: "Through A Relay", value: "3" }, { key: "Offline", value: "1" }] }] },
  "machines.updates": { facts: [{ title: "Machines", rows: [{ key: "Channel", value: "stable" }, { key: "Last Checked", value: "2 hours ago" }, { key: "Behind", value: "1 machine" }] }] },
  "sharing.published-services": { facts: [{ title: "Reachable From Outside", rows: [{ key: "grafana", value: "monitor01:3000" }, { key: "docs", value: "build-01:8080" }] }] },
  "about.licences": { facts: [{ title: "infraternal", rows: [{ key: "Licence", value: "AGPL-3.0-only" }, { key: "Commercial Features", value: "separate licence" }] }] },
};

export function createMockSettings(world: MockWorld): SettingsSource {
  const rows = createRowsSource({
      admin: () => world.role === "operator",
      backing: (id) => ({
        read: async () => { const m = await defs(), def = m.SETTING_DEFS[id]; return def ? values.get(id) ?? m.defaultOf(def) : undefined; },
        write: async (v) => { const m = await defs(), def = m.SETTING_DEFS[id]; if (def && v === m.defaultOf(def)) values.delete(id); else values.set(id, v); },
      }),
      data: (comp, group) => EXAMPLE[`${comp}.${group}`],
      value: (s, standard) => values.get(s.id) ?? standard,
  });
  return {
    sections: ["devices"],
    ...rows,
    accountFacts: () => [
      { title: "Passkeys", rows: [{ key: "iPhone 15", value: "added 2 weeks ago" }, { key: "MacBook Pro", value: "added 3 months ago" }] },
      { title: "Recovery key", rows: [{ key: "Status", value: "saved" }, { key: "Last checked", value: "6 days ago" }] },
    ],
    render(section, pane, cx) {
      if (section === "devices") return renderDevices(pane, {
        get devices() { return world.devices; },
        jump: (view) => { const id = view.toLowerCase() as ViewId; if (cx.views.has(id)) cx.nav.flyView(id); },
        signOut: (d) => { world.devices = world.devices.filter((x) => x.id !== d.id); cx.toast.show({ message: `${d.name} signed out` }); },
        rename: (_d, name) => { cx.toast.show({ message: `Renamed to ${name}` }); },
      });
      return rows.render(section, pane, cx);
    },
  };
}
