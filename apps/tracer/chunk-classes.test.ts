/** The critical/deferred split of the JavaScript budget (chunk-classes.ts). */
import { expect, test } from "bun:test";
import { classifyChunks, type MetaOutput } from "./chunk-classes";

const out = (imports: Array<[string, "import-statement" | "dynamic-import"]>, inputs: string[] = [], entryPoint?: string): MetaOutput => ({
  imports: imports.map(([path, kind]) => ({ path, kind })), inputs: Object.fromEntries(inputs.map((i) => [i, {}])), ...(entryPoint ? { entryPoint } : {}),
});

test("the first screen is critical, the canvas product module and what only it uses are deferred", () => {
  const result = classifyChunks({
    "./main.js": out([["./core.js", "dynamic-import"], ["./product.js", "dynamic-import"], ["./shared.js", "import-statement"]], ["src/main.ts"], "src/main.ts"),
    "./shared.js": out([]),
    "./core.js": out([["./terminal.js", "dynamic-import"], ["./shared.js", "import-statement"]], ["src/core-screen.ts"]),
    "./terminal.js": out([["./shared.js", "import-statement"]], ["src/terminal.ts"]),
    "./product.js": out([["./canvas.js", "import-statement"], ["./terminal.js", "dynamic-import"], ["./shared.js", "import-statement"]], ["src/canvas/product.ts"]),
    "./canvas.js": out([["./shared.js", "import-statement"]], ["src/canvas/create.ts"]),
    "./worker.js": out([], ["w.ts"], "w.ts"),
  });
  expect(result.critical).toEqual(["core.js", "main.js", "shared.js", "terminal.js", "worker.js"]);
  expect(result.deferred).toEqual(["canvas.js", "product.js"]);
});

test("a chunk that both sides use stays critical", () => {
  const result = classifyChunks({
    "./main.js": out([["./product.js", "dynamic-import"], ["./core.js", "dynamic-import"]], ["src/main.ts"], "src/main.ts"),
    "./core.js": out([["./both.js", "import-statement"]], ["src/core-screen.ts"]),
    "./product.js": out([["./both.js", "import-statement"], ["./only.js", "import-statement"]], ["src/canvas/product.ts"]),
    "./both.js": out([]), "./only.js": out([]),
  });
  expect(result.critical).toContain("both.js");
  expect(result.deferred).toEqual(["only.js", "product.js"]);
});
