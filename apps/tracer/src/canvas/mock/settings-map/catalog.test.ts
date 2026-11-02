// SPDX-License-Identifier: AGPL-3.0-only
/** The table that maps settings to rows and windows holds together, whoever edits it next. */
import { expect, test } from "bun:test";
import { parseValue, defaultValue, formatValue } from "../../../../../../packages/ui/src/setting-value";
import { SETTINGS_MAP } from "./catalog";
import { LEGACY, MAX_WINDOWS, entriesOf, locate, spots, trackPlan, valueOf, visibleMap, winId } from "./model";

test("no row holds more windows than the grid is planned for", () => {
  for (const comp of SETTINGS_MAP) expect(comp.groups.length).toBeLessThanOrEqual(MAX_WINDOWS);
});

test("the tracks make every window of every row exactly as wide as the others in its row, and every row flush", () => {
  for (const counts of [[4, 3, 5, 2, 4, 2, 2], [5, 2, 1, 1, 1], [3], [1], [5]]) for (const target of [1428, 1100, 1900]) {
    const plan = trackPlan(counts, target, 12);
    const total = plan.widths.reduce((a, b) => a + b, 0) + 12 * (plan.widths.length - 1);
    for (const n of new Set(counts)) {
      const sizes = Array.from({ length: n }, (_, k) => {
        const { start, span } = plan.place(n, k);
        expect(start).toBeGreaterThanOrEqual(0);
        return plan.widths.slice(start, start + span).reduce((a, b) => a + b, 0) + 12 * (span - 1);
      });
      for (const s of sizes) expect(Math.abs(s - sizes[0]!)).toBeLessThan(0.01);
      expect(Math.abs(sizes.reduce((a, b) => a + b, 0) + 12 * (n - 1) - total)).toBeLessThan(0.01);
    }
    // Every track has a window that starts in it (the canvas drops a track without one).
    const starts = new Set<number>();
    for (const n of new Set(counts)) for (let k = 0; k < n; k++) starts.add(plan.place(n, k).start);
    expect(starts.size).toBe(plan.widths.length);
  }
});

test("ids are unique: a window, a component and a setting each have one place", () => {
  const windows = spots(SETTINGS_MAP).map((s) => winId(s.comp.id, s.group.id));
  expect(new Set(windows).size).toBe(windows.length);
  expect(new Set(SETTINGS_MAP.map((c) => c.id)).size).toBe(SETTINGS_MAP.length);
  const settings = spots(SETTINGS_MAP).flatMap((s) => s.group.settings ?? []).map((s) => s.id);
  expect(new Set(settings).size).toBe(settings.length);
});

test("every default is inside its own allowed range and survives being typed back", () => {
  for (const { group } of spots(SETTINGS_MAP)) for (const s of group.settings ?? []) {
    const shown = formatValue(s.spec, defaultValue(s.spec));
    expect(parseValue(s.spec, shown, defaultValue(s.spec))).toEqual({ ok: true, value: defaultValue(s.spec) });
  }
});

test("the numbers the owner gave are in the table", () => {
  const get = (id: string) => spots(SETTINGS_MAP).flatMap((s) => s.group.settings ?? []).find((s) => s.id === id)!.spec;
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
  for (const { group } of spots(SETTINGS_MAP)) if (group.docs) expect(["keys", "multiplexer"]).toContain(group.docs.page);
});

test("the owner's map: rows, windows and their order", () => {
  expect(SETTINGS_MAP.map((c) => `${c.title}: ${c.groups.map((g) => g.title).join(", ")}`)).toEqual([
    "Appearance: Theme, Font, Size, Layout",
    "Terminal: Typing, Scrollback, Multiplexer",
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
  const entries = entriesOf(visibleMap(true), valueOf);
  const groups = spots(SETTINGS_MAP).length, settings = spots(SETTINGS_MAP).reduce((n, s) => n + (s.group.settings?.length ?? 0), 0);
  expect(entries.length).toBe(groups + settings);
  expect(entries.find((e) => e.hint.includes("wireguard"))?.label).toBe("Connection Keys");
  expect(entries.find((e) => e.action === "canvas:settings:mesh.keys")?.label).toBe("Mesh › Keys");
});
