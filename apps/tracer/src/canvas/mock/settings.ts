/**
 * Mockup Settings: the rows of windows (`settings-rows/source.ts`) with a test double behind them. Every setting is "backed" by
 * memory for the session, and the groups the server cannot list yet are filled with example facts and keys, so the whole of
 * Settings can be seen and tested before the server can say it. The product backs only what its server stores.
 */
import { renderDevices } from "../../../../../packages/ui/src/settings-panels";
import { defaultValue, type SettingValue } from "../../../../../packages/ui/src/setting-value";
import type { SettingsSource } from "../views/settings-body.on-demand";
import type { ViewId } from "../model/types";
import type { GroupData, SettingDef } from "../settings-rows/catalog";
import { SETTINGS_MAP } from "../settings-rows/catalog";
import { createRowsSource } from "../settings-rows/source";
import type { MockWorld } from "./world";

/** Every setting's value, kept for the session so a window that is rebuilt (a role change) keeps what was typed. */
const values = new Map<string, SettingValue>();
const valueOf = (s: SettingDef): SettingValue => values.get(s.id) ?? defaultValue(s.spec);
const defs = new Map(SETTINGS_MAP.flatMap((c) => c.groups.flatMap((g) => g.settings ?? [])).map((s) => [s.id, s]));

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
      backing: (id) => { const def = defs.get(id); return def && { read: async () => valueOf(def), write: async (v) => { if (v === defaultValue(def.spec)) values.delete(id); else values.set(id, v); } }; },
      data: (comp, group) => EXAMPLE[`${comp}.${group}`],
      value: valueOf,
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
