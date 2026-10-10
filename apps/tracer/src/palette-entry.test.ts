/** Every palette row has a title: strict builds refuse a blank one, production builds repair it. */
import { describe, expect, test } from "bun:test";
import type { PaletteEntry } from "./core-screen";
import { fallbackLabel, titled } from "./palette-entry";
import { windowLabel } from "./canvas/windows/label";
import { SETTINGS_SECTIONS } from "./canvas/views/settings";
import type { WindowModel } from "./canvas/model/types";

const row = (over: Partial<PaletteEntry> = {}): PaletteEntry => ({ group: "Settings", glyph: "⚙", label: "Appearance", hint: "", action: "canvas:settings:appearance", ...over });

describe("palette rows are always titled", () => {
  test("a titled row passes through untouched", () => {
    const entry = row();
    expect(titled(entry, true)).toBe(entry);
  });
  test("a blank title throws in a strict build and names the row", () => {
    expect(() => titled(row({ label: "  " }), true)).toThrow(/without a title.*canvas:settings:appearance/);
  });
  test("a blank title is repaired from the settings section in production", () => {
    expect(titled(row({ label: "" }), false).label).toBe("Settings: Appearance");
    expect(fallbackLabel({ group: "Settings", action: "canvas:settings:grants" })).toBe("Settings: Access");
  });
  test("a blank title with no section falls back to the group", () => {
    expect(titled(row({ label: "", group: "Hosts", action: "canvas:open:x" }), false).label).toBe("Hosts");
  });
});

describe("a settings window always has a title in the scoped palette", () => {
  test.each(SETTINGS_SECTIONS.map((s) => [s.id, s.title] as const))("section %s without its host field is still %s", (id, title) => {
    const m: WindowModel = { id: `s-${id}`, kind: "settings", host: "" };
    expect(windowLabel(m)[0]).toBe(title);
  });
  test("a window of any other kind never has an empty name", () => {
    expect(windowLabel({ id: "x", kind: "logs", host: "" } as WindowModel)[0]).toBe("logs");
  });
});
