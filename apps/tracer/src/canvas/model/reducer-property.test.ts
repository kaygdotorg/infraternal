/** Seeded operation sequences compare every accepted browser projection with the shipping Rust reducer (#243). */
import { beforeAll, expect, test } from "bun:test";
import { reduce, type Intent } from "./operations";
import type { CanvasDocument, DocTarget } from "./schema";

const target: DocTarget = { type: "settings", section: "appearance" };
const initial = (): CanvasDocument => ({ format: "infraternal.canvas", version: 1, revision: 0, views: [{ id: "console", kind: "console", name: "Console", cell: { x: 0, y: 0 }, layout: { type: "tiled", columns: [
  { id: "a", weight: 1, windows: [{ id: "left", target, span: 2, row: 0, rows: 1 }] },
  { id: "b", weight: 1, windows: [{ id: "middle", target, span: 2, row: 1, rows: 1 }] },
  { id: "c", weight: 1, windows: [{ id: "right", target, span: 1, row: 0, rows: 1 }] },
] } }] });

function sequence(seed: number): Intent[] {
  let state = seed;
  const random = (n: number): number => { state = (Math.imul(state, 1664525) + 1013904223) >>> 0; return state % n; };
  const ids = ["left", "middle", "right"], columns = ["a", "b", "c"];
  const intents: Intent[] = [
    { type: "split", view_id: "console", column_id: "unused", anchor_id: "right", axis: "down", window: { id: "first", target } },
    { type: "resize", window_id: "left", height: null, rows: 2 },
  ];
  ids.push("first");
  for (let step = 0; step < 126; step++) {
    // High bits keep operation choice independent of the small-index selection below.
    random(1); const kind = state >>> 28;
    const id = ids[random(ids.length)]!, column = columns[random(columns.length)]!;
    const fresh = `w-${seed}-${step}`, newColumn = `c-${seed}-${step}`;
    if (kind < 3) {
      const col = random(2) ? column : newColumn;
      intents.push({ type: "open", view_id: "console", column_id: col, window: { id: fresh, target }, ...(random(2) ? { after: id } : { column_after: null }) });
      ids.push(fresh); columns.push(col);
    } else if (kind < 6) {
      intents.push({ type: "split", view_id: "console", column_id: newColumn, anchor_id: id, axis: random(2) ? "down" : "right", window: { id: fresh, target } });
      ids.push(fresh); columns.push(newColumn);
    } else if (kind < 8) intents.push({ type: "resize", window_id: id, height: random(3) ? random(8) + 1 : null, span: random(3) + 1, rows: random(3) + 1, row: random(6) });
    else if (kind < 10) intents.push({ type: "move", view_id: "console", window_id: id, column_id: column, after: ids[random(ids.length)]! });
    else if (kind < 12) intents.push({ type: "close", window_id: id });
    else if (kind < 14) intents.push({ type: "weight", view_id: "console", column_id: column, weight: [0.1, 0.125, 0.2, 0.5, 1][random(5)]! });
    else intents.push({ type: "view.update", view_id: "console", name: `Console ${step}`, cell: { x: random(20), y: random(20) } });
  }
  return intents;
}

/** Repository root, the working directory for the oracle build and run. */
const repo = new URL("../../../../../", import.meta.url).pathname;
/** Cargo arguments that select the layout oracle example, shared by its build and its run. */
const oracleArgs = ["-p", "infraternal-plugin-canvas", "--example", "layout_oracle"];

// Compiling the Rust oracle is setup, not the behaviour under test. On a shared build host it can wait on
// cargo's target-dir lock or rebuild dependencies for minutes, so it gets its own bound here and the
// property test below measures only the oracle run and the comparison (#509).
beforeAll(async () => {
  const build = Bun.spawn(["cargo", "build", "--quiet", ...oracleArgs], { cwd: repo, stdout: "ignore", stderr: "pipe" });
  const [stderr, status] = await Promise.all([new Response(build.stderr).text(), build.exited]);
  if (status !== 0) throw Error(`layout_oracle did not build:\n${stderr}`);
}, 1_800_000);

test("property: accepted random operation sequences match the real server reducer", () => {
  const cases = Array.from({ length: 32 }, (_, seed) => ({ document: initial(), intents: sequence(seed + 1) }));
  const oracle = Bun.spawnSync(["cargo", "run", "--quiet", ...oracleArgs], {
    cwd: repo,
    stdin: new TextEncoder().encode(cases.map((entry) => JSON.stringify(entry)).join("\n") + "\n"), maxBuffer: 128 * 1024 * 1024,
  });
  if (oracle.exitCode !== 0) throw Error(new TextDecoder().decode(oracle.stderr));
  const results = new TextDecoder().decode(oracle.stdout).trim().split("\n").map((line) => JSON.parse(line) as Array<{ accepted: boolean; document: CanvasDocument }>);
  expect(results).toHaveLength(cases.length);
  let accepted = 0;
  for (const [index, entry] of cases.entries()) {
    const projection = structuredClone(entry.document), rows = results[index]!;
    expect(rows).toHaveLength(entry.intents.length);
    for (const [step, intent] of entry.intents.entries()) {
      const row = rows[step]!;
      // Refusals are never published as committed operations. Accepted no-ops still reduce identically.
      if (row.accepted) { reduce(projection, intent); accepted++; }
      expect(projection, `seed=${index + 1} step=${step} intent=${JSON.stringify(intent)}`).toEqual(row.document);
    }
  }
  console.log(`layout property: ${cases.length} seeds, 4096 operations, ${accepted} accepted, zero divergences`);
}, 120_000);
