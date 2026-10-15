/** The machine's window list as the picker and the palette read it: bounded, defensive and stable. */
import { expect, test } from "bun:test";
import { appInitial, entryTitle, matches, parseInventory, sameInventory } from "./inventory";

const sample = {
  windows: [
    { window_id: 7, owner_pid: 40, app_name: "Editor", title: "stream.ts", bundle_id: "test.editor", layer: 0, frame: [0, 0, 900, 600], on_screen: true },
    { window_id: 3, owner_pid: 41, app_name: "Browser", title: "", layer: 0, frame: { x: 0, y: 0, width: 1200, height: 800 }, on_screen: false },
    { window_id: 5, owner_pid: 1, app_name: "Window Server", title: "Menubar", layer: 25, frame: [0, 0, 2560, 30], on_screen: true },
    { window_id: 6, owner_pid: 41, app_name: "Browser", title: "badge", layer: 0, frame: [0, 0, 20, 20], on_screen: true },
    { window_id: 0, owner_pid: 41, app_name: "Browser", title: "no id", layer: 0 },
    "junk", null,
  ],
  displays: [{ display_id: 1, backing_scale: 2, pixel_width: 2880, pixel_height: 1800 }],
  permission_state: { screen_recording: true, accessibility: false },
};

test("only normal, sizeable, identified windows are listed, on-screen ones first", () => {
  const inv = parseInventory(sample);
  expect(inv.windows.map((w) => `${w.appName}:${w.target.windowId}`)).toEqual(["Editor:7", "Browser:3"]);
  expect(inv.windows[1]!.onScreen).toBe(false);
  expect(inv.permissions).toEqual({ screenRecording: true, accessibility: false });
});

test("keys carry no colon, because a palette action splits on colons", () => {
  const inv = parseInventory(sample);
  for (const e of [...inv.windows, ...inv.screens]) expect(e.key.includes(":")).toBe(false);
  expect(inv.screens[0]!.name).toBe("Whole screen");
});

test("several displays are numbered, and nonsense input yields an empty inventory", () => {
  const two = parseInventory({ displays: [{ display_id: 1 }, { display_id: 2, pixel_width: 100, pixel_height: 50 }] });
  expect(two.screens.map((s) => s.name)).toEqual(["Display 1", "Display 2"]);
  expect(parseInventory(42)).toEqual({ windows: [], screens: [], permissions: {} });
  expect(parseInventory({ windows: "no", displays: 3 })).toEqual({ windows: [], screens: [], permissions: {} });
});

test("search needs every word, in any order, across app, title and bundle", () => {
  const [editor] = parseInventory(sample).windows;
  expect(matches(editor!, "editor stream")).toBe(true);
  expect(matches(editor!, "stream editor")).toBe(true);
  expect(matches(editor!, "test.editor")).toBe(true);
  expect(matches(editor!, "browser")).toBe(false);
  expect(matches(editor!, "")).toBe(true);
});

test("a poll that changed nothing is the same inventory, and a new title is not", () => {
  const a = parseInventory(sample), b = parseInventory(sample);
  expect(sameInventory(a, b)).toBe(true);
  const changed = parseInventory({ ...sample, windows: [{ ...(sample.windows[0] as object), title: "other.ts" }, sample.windows[1]] });
  expect(sameInventory(a, changed)).toBe(false);
});

test("a window without a title says what it is, and the app tile takes a letter", () => {
  const inv = parseInventory(sample);
  expect(entryTitle(inv.windows[1]!)).toBe("Minimised");
  expect(entryTitle(inv.windows[0]!)).toBe("stream.ts");
  expect(appInitial("  éditeur")).toBe("É");
  expect(appInitial("@@@")).toBe("?");
});
