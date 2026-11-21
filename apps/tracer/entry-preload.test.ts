/** The module preload list of the first screen (entry-preload.ts). */
import { expect, test } from "bun:test";
import type { MetaOutput } from "./chunk-classes";
import { readFileSync } from "node:fs";
import { returningVisitChunks, SIGN_IN_COUNTER_KEY, staticClosure, withModulePreload, withReturningVisitPreload } from "./entry-preload";

/** A metafile output with the given imports and no source inputs. */
const out = (imports: Array<[string, "import-statement" | "dynamic-import"]>): MetaOutput => ({
  imports: imports.map(([path, kind]) => ({ path, kind })), inputs: {},
});

test("the closure follows static imports level by level and skips dynamic ones", () => {
  const closure = staticClosure({
    "./main.js": out([["./a.js", "import-statement"], ["./terminal.js", "dynamic-import"]]),
    "./a.js": out([["./b.js", "import-statement"], ["./c.js", "import-statement"]]),
    "./b.js": out([["./c.js", "import-statement"]]),
    "./c.js": out([]),
    "./terminal.js": out([["./c.js", "import-statement"]]),
  }, "main.js");
  expect(closure).toEqual(["main.js", "a.js", "b.js", "c.js"]);
});

test("an entry that is not in the build has nothing to preload", () => {
  expect(staticClosure({ "./other.js": out([]) }, "main.js")).toEqual([]);
});

test("the hints go in front of the end of the head, and a page without one is refused", () => {
  const page = withModulePreload("<head><title>x</title></head><body></body>", ["main.js", "a.js"]);
  expect(page).toBe('<head><title>x</title>    <link rel="modulepreload" href="./main.js" />\n    <link rel="modulepreload" href="./a.js" />\n  </head><body></body>');
  expect(() => withModulePreload("<body></body>", ["main.js"])).toThrow("no </head>");
});

test("the returning-visit list holds the closures of the wanted sources, without what everyone already preloads", () => {
  const outputs: Record<string, MetaOutput> = {
    "./main.js": out([["./shared.js", "import-statement"], ["./core.js", "dynamic-import"]]),
    "./shared.js": out([]),
    "./core.js": { ...out([["./shared.js", "import-statement"], ["./ui.js", "import-statement"]]), inputs: { "src/core-screen.ts": {} } },
    "./ui.js": out([]),
    "./terminal.js": { ...out([["./ui.js", "import-statement"], ["./wasm.js", "import-statement"]]), inputs: { "src/terminal.ts": {} } },
    "./wasm.js": out([]),
  };
  expect(returningVisitChunks(outputs, ["src/core-screen.ts", "src/terminal.ts"], ["main.js", "shared.js"])).toEqual(["core.js", "ui.js", "terminal.js", "wasm.js"]);
  expect(() => returningVisitChunks(outputs, ["src/gone.ts"], [])).toThrow("no chunk holds src/gone.ts");
});

test("the returning-visit script reads the same counter that hints.ts writes", () => {
  expect(readFileSync(new URL("./src/hints.ts", import.meta.url), "utf8")).toContain(`"${SIGN_IN_COUNTER_KEY}"`);
  const page = withReturningVisitPreload("<head></head>", ["core.js"]);
  expect(page).toContain('localStorage.getItem("tracer.hints")');
  expect(page).toContain('["./core.js"]');
  expect(withReturningVisitPreload("<head></head>", [])).toBe("<head></head>");
  // The engine's wasm is preloaded as a fetch (what streaming compilation asks for), only for a returning device.
  const withEngine = withReturningVisitPreload("<head></head>", [], ["ghostty-vt-abc.wasm"]);
  expect(withEngine).toContain('["./ghostty-vt-abc.wasm"]');
  expect(withEngine).toContain('l.as="fetch";l.crossOrigin="anonymous"');
  expect(withEngine).toContain('signIns>0');
});
