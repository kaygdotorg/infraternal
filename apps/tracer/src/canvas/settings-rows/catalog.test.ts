// SPDX-License-Identifier: AGPL-3.0-only
/** The table that maps settings to rows and windows holds together, whoever edits it next. */
import { expect, test } from "bun:test";
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { parseValue, defaultValue, formatValue } from "../../../../../packages/ui/src/setting-value";
import { SETTINGS_MAP } from "./catalog";
import { defaultWidth, metricsFor } from "../layout/geometry";
import { runsOf } from "../layout/grid";
import { SETTING_DEFS } from "./definitions.on-demand";
import { entriesOf } from "./entries.on-demand";
import { LEGACY, locate } from "./locate.on-demand";
import { SETTINGS_ROWS, buildSettingsMapView, spots, visibleMap, winId } from "./model";
import { ADD_HOST, NO_ACCESS, TERMINAL } from "./docs-adapter";

test("Settings is one row of windows for each component: one grid, the layout's size, no window spans", () => {
  for (const admin of [true, false]) for (const [w, h, coarse] of [[1440, 900, false], [1024, 768, false], [2560, 1300, false], [393, 852, true]] as const) {
    const m = metricsFor(w, h, coarse);
    const map = visibleMap(admin);
    const view = buildSettingsMapView(map, m, { id: "settings", name: "Settings", layout: "tiled", cols: [], nodes: [], x: 0, y: 0 });
    // One column for each window of the longest row, every one the width a terminal window has (Window Sizes): the screen is the only input.
    const tracks = Math.max(...map.map((c) => c.groups.length));
    expect(view.cols.length).toBe(tracks);
    for (const col of view.cols) { expect(col.w).toBe(defaultWidth(m, tracks)); expect(col.group).toBe(SETTINGS_ROWS); }
    // A component is a band, its windows in the tracks from the left, in the order of the table, at the layout's height; no window has a span.
    map.forEach((comp, band) => comp.groups.forEach((g, k) => {
      const win = view.cols[k]!.wins.find((x) => x.id === winId(comp.id, g.id));
      expect(win?.row, `${comp.id} is band ${band}`).toBe(band);
      expect(win?.h).toBe(1);
      expect(win?.span).toBeUndefined(); expect(win?.rows).toBeUndefined();
    }));
    // The canvas sees it as ONE group, with every track in it, although no window crosses a seam.
    const runs = runsOf(view.cols.map((c) => ({ ...(c.group !== undefined ? { group: c.group } : {}), wins: c.wins.map((x) => ({ span: x.span ?? 1, ...(x.row !== undefined ? { row: x.row } : {}) })) })));
    expect(runs).toEqual([{ from: 0, to: tracks - 1, rows: map.length }]);
  }
});

test("ids are unique: a window, a component and a setting each have one place", () => {
  const windows = spots(SETTINGS_MAP).map((s) => winId(s.comp.id, s.group.id));
  expect(new Set(windows).size).toBe(windows.length);
  expect(new Set(SETTINGS_MAP.map((c) => c.id)).size).toBe(SETTINGS_MAP.length);
  const settings = spots(SETTINGS_MAP).flatMap((s) => s.group.settings ?? []);
  expect(new Set(settings).size).toBe(settings.length);
});

test("every default is inside its own allowed range and survives being typed back", () => {
  for (const s of Object.values(SETTING_DEFS)) {
    const shown = formatValue(s.spec, defaultValue(s.spec));
    expect(parseValue(s.spec, shown, defaultValue(s.spec))).toEqual({ ok: true, value: defaultValue(s.spec) });
  }
});

test("the numbers the owner gave are in the table", () => {
  const get = (id: string) => SETTING_DEFS[id]!.spec;
  const text = (id: string) => formatValue(get(id), defaultValue(get(id)));
  expect(text("connection-keys")).toBe("7 d");
  expect(text("machine-identity")).toBe("7 d");
  expect(text("name-suffix")).toBe(".internal");
  expect(text("renewal-window")).toBe("90 d");
  expect(text("add-link")).toBe("15 min");
  expect(text("join-code")).toBe("10 min");
  expect(text("browser-session")).toBe("30 d");
  expect(text("app-key")).toBe("30 d");
  expect(parseValue(get("browser-session"), "91", 43200).ok).toBe(false);
  expect(parseValue(get("app-key"), "365", 43200).ok).toBe(true);
  expect(parseValue(get("app-key"), "366", 43200).ok).toBe(false);
});

test("an administrator sees every row; others only the personal ones, and no row is left empty", () => {
  expect(visibleMap(true).map((c) => c.id)).toEqual(SETTINGS_MAP.map((c) => c.id));
  const others = visibleMap(false).map((c) => c.id);
  expect(others).toContain("you");
  expect(others).toContain("appearance");
  expect(others).not.toContain("mesh");
  for (const c of visibleMap(false)) expect(c.groups.length).toBeGreaterThan(0);
});

test("a window's docs link points at a page, and only the windows the owner named have one", () => {
  const linked = spots(SETTINGS_MAP).filter((s) => s.group.docs).map((s) => `${s.comp.id}.${s.group.id}`);
  expect(linked).toEqual(["terminal.multiplexer", "you.passkeys", "you.recovery", "you.apps", "you.devices", "machines.new-machines", "mesh.keys"]);
  for (const { group } of spots(SETTINGS_MAP)) if (group.docs) expect(["reference/keys", "terminal/multiplexer"]).toContain(group.docs.page);
});

/** Every page of `docs/user/` as its address (`reference/keys`) and the ids of its headings, cut the way the docs build cuts them. */
function docsPages(): Map<string, Set<string>> {
  const root = join(import.meta.dir, "../../../../../docs/user");
  const pages = new Map<string, Set<string>>();
  const strip = (name: string): string => name.replace(/^\d+-/, "").replace(/\.md$/, "");
  for (const dir of readdirSync(root, { withFileTypes: true }).filter((d) => d.isDirectory())) {
    for (const file of readdirSync(join(root, dir.name)).filter((f) => f.endsWith(".md") && f !== "index.md")) {
      const ids = new Set<string>();
      for (const line of readFileSync(join(root, dir.name, file), "utf8").split("\n")) {
        const m = /^#{2,6}\s+(.*)$/.exec(line);
        if (m) ids.add(m[1]!.toLowerCase().replace(/[^\p{L}\p{N}]+/gu, "-").replace(/^-+|-+$/g, ""));
      }
      pages.set(`${strip(dir.name)}/${strip(file)}`, ids);
    }
  }
  return pages;
}

test("every \"?\" link opens a page and a heading that exist in docs/user", () => {
  const pages = docsPages();
  const links = [...spots(SETTINGS_MAP).flatMap((s) => (s.group.docs ? [s.group.docs] : [])), TERMINAL, NO_ACCESS, ADD_HOST];
  expect(links.length).toBeGreaterThan(5);
  for (const link of links) {
    expect(pages.has(link.page), `page ${link.page}`).toBe(true);
    if (link.heading) expect(pages.get(link.page)!.has(link.heading), `${link.page}#${link.heading}`).toBe(true);
  }
});

test("the table holds no invented data: no lists of facts or keys, and every panel it names is one the product renders", () => {
  const PANELS = ["windows", "hosts", "toolbar", "shortcuts", "account", "about", "devices"];
  for (const { group } of spots(SETTINGS_MAP)) {
    expect(Object.keys(group).filter((k) => ["facts", "keys", "later"].includes(k))).toEqual([]);
    for (const id of typeof group.panel === "string" ? [group.panel] : group.panel ?? []) expect(PANELS).toContain(id);
  }
});

test("the owner's map: rows, windows and their order", () => {
  expect(SETTINGS_MAP.map((c) => `${c.title}: ${c.groups.map((g) => g.title).join(", ")}`)).toEqual([
    "Appearance: Themes, Layout",
    "Terminal: Typing, Hosts, Scrollback, Multiplexer",
    "You: Profile, Passkeys, Recovery, Apps, Devices",
    "Machines: New Machines, Updates",
    "Mesh: Keys, Names, Access, Connections",
    "Sharing: Published Services, Certificates",
    "About: Version, Licences",
  ]);
  for (const name of [...SETTINGS_MAP.map((c) => c.title), ...spots(SETTINGS_MAP).map((s) => s.group.title)]) expect(name).toMatch(/^[A-Z][A-Za-z]*( [A-Z][A-Za-z]*)*$/);
});

test("every section of the old Settings still opens somewhere, and a setting is found from its group", () => {
  const admin = visibleMap(true);
  for (const old of Object.keys(LEGACY)) expect(locate(admin, old)).toBeDefined();
  expect(locate(admin, "mesh")).toEqual({ windowId: "s-mesh-keys" });
  expect(locate(admin, "mesh.keys.connection-keys")).toEqual({ windowId: "s-mesh-keys", settingId: "connection-keys" });
  expect(locate(admin, "mesh.keys.nope")).toEqual({ windowId: "s-mesh-keys" });
  expect(locate(admin, "nope")).toBeUndefined();
});

test("⌘K has one row per group and one per setting, and a setting is findable by its technical name", () => {
  const entries = entriesOf(visibleMap(true), (s) => defaultValue(s.spec), () => true);
  const groups = spots(SETTINGS_MAP).length, settings = spots(SETTINGS_MAP).reduce((n, s) => n + (s.group.settings?.length ?? 0), 0);
  expect(entries.length).toBe(groups + settings);
  expect(entries.find((e) => e.hint.includes("wireguard"))?.label).toBe("Connection Keys");
  expect(entries.find((e) => e.action === "canvas:settings:mesh.keys")?.label).toBe("Mesh › Keys");
});

test("⌘K offers a setting only when something stores it", () => {
  const entries = entriesOf(visibleMap(true), (s) => defaultValue(s.spec), (id) => id === "app-key");
  expect(entries.filter((e) => e.action.split(".").length === 3).map((e) => e.label)).toEqual(["Keys Last"]);
  expect(entries.length).toBe(spots(SETTINGS_MAP).length + 1);
});

test("the table and the definitions agree: every id in a window is defined, and every definition is in a window", () => {
  const placed = spots(SETTINGS_MAP).flatMap((s) => s.group.settings ?? []);
  for (const id of placed) expect(SETTING_DEFS[id], id).toBeDefined();
  expect(Object.keys(SETTING_DEFS).sort()).toEqual([...placed].sort());
});

test("the Themes window is the one the theme editor fills, and no other window is", () => {
  expect(spots(SETTINGS_MAP).filter((s) => s.group.themes).map((s) => `${s.comp.id}.${s.group.id}`)).toEqual(["appearance.themes"]);
});
