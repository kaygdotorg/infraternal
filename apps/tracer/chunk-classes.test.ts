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
  expect(result.onDemand).toEqual([]);
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

test("code only an action loads is on demand, even when the lazy canvas is what loads it", () => {
  const result = classifyChunks({
    "./main.js": out([["./product.js", "dynamic-import"]], ["src/main.ts"], "src/main.ts"),
    "./product.js": out([["./wizard.js", "dynamic-import"], ["./canvasonly.js", "import-statement"], ["./both.js", "import-statement"]], ["src/canvas/product.ts"]),
    "./canvasonly.js": out([]),
    "./wizard.js": out([["./wizardonly.js", "import-statement"], ["./both.js", "import-statement"]], ["src/add-host.on-demand.ts"]),
    "./wizardonly.js": out([]), "./both.js": out([]),
  });
  expect(result.critical).toEqual(["main.js"]);
  expect(result.deferred).toEqual(["both.js", "canvasonly.js", "product.js"]);
  expect(result.onDemand).toEqual(["wizard.js", "wizardonly.js"]);
});


test("post-terminal host inventory entry and its shared canvas imports stay deferred", () => {
  const result = classifyChunks({
    "./main.js": out([["./product.js", "dynamic-import"]], ["src/main.ts"], "src/main.ts"),
    "./product.js": out([["./hosts.js", "dynamic-import"], ["./sessions.js", "import-statement"]], ["src/canvas/product.ts"], "src/canvas/product.ts"),
    "./hosts.js": out([["./sessions.js", "import-statement"]], ["src/canvas/sessions/hosts.ts"], "src/canvas/sessions/hosts.ts"),
    "./sessions.js": out([]),
  });
  expect(result.critical).toEqual(["main.js"]);
  expect(result.deferred).toEqual(["hosts.js", "product.js", "sessions.js"]);
});

test("automatic canonical painting loads after the first canvas draw", () => {
  const result = classifyChunks({
    "./main.js": out([["./product.js", "dynamic-import"]], ["src/main.ts"], "src/main.ts"),
    "./product.js": out([["./paint.js", "dynamic-import"]], ["src/canvas/product.ts"], "src/canvas/product.ts"),
    "./paint.js": out([["./bindings.js", "import-statement"]], ["src/canvas/model/reconcile.ts"], "src/canvas/model/reconcile.ts"),
    "./bindings.js": out([]),
  });
  expect(result.critical).toEqual(["main.js"]);
  expect(result.deferred).toEqual(["bindings.js", "paint.js", "product.js"]);
});
