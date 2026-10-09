/** The shortcut registry: area order, replacement, removal, and key caps (packages/ui/src/shortcuts.ts). */
import { expect, test } from "bun:test";
import { GLOBAL_AREA, keyCaps, registerShortcuts, shortcutSections } from "../../../packages/ui/src/shortcuts";

test("current areas come first in the order given, then the global ones; other areas stay out", () => {
  const removers = [
    registerShortcuts({ id: "t-global", title: "Everywhere", area: GLOBAL_AREA, shortcuts: [] }),
    registerShortcuts({ id: "t-terminal", title: "Terminal", area: "terminal", shortcuts: [] }),
    registerShortcuts({ id: "t-canvas", title: "Canvas", area: "canvas", shortcuts: [] }),
    registerShortcuts({ id: "t-lxc", title: "LXC", area: "lxc", shortcuts: [] }),
  ];
  expect(shortcutSections(["canvas", "terminal"]).map((section) => section.id)).toEqual(["t-canvas", "t-terminal", "t-global"]);
  expect(shortcutSections(["lxc"]).map((section) => section.id)).toEqual(["t-lxc", "t-global"]);
  for (const remove of removers) remove();
  expect(shortcutSections(["canvas"])).toEqual([]);
});

test("registering an id again replaces the section; a stale remover leaves the new one", () => {
  const first = registerShortcuts({ id: "t-replace", title: "One", area: "x", shortcuts: [] });
  const second = registerShortcuts({ id: "t-replace", title: "Two", area: "x", shortcuts: [] });
  first();
  expect(shortcutSections(["x"]).map((section) => section.title)).toEqual(["Two"]);
  second();
  expect(shortcutSections(["x"])).toEqual([]);
});

test("key caps: chords split on +, mac glyphs are one cap each, single labels stay whole", () => {
  expect(keyCaps("Ctrl+Shift+L")).toEqual(["Ctrl", "Shift", "L"]);
  expect(keyCaps("⌘K")).toEqual(["⌘", "K"]);
  expect(keyCaps("Esc")).toEqual(["Esc"]);
  expect(keyCaps("F6")).toEqual(["F6"]);
  expect(keyCaps("?")).toEqual(["?"]);
  expect(keyCaps("+")).toEqual(["+"]);
});
