/** Independent live-ID boundary sequences compare browser projections with the shipping reducer (#243, D183). */
import { expect, test } from "bun:test";
import { reduce, type Intent } from "./operations";
import { parseDocument, type CanvasDocument, type DocTarget } from "./schema";

const target: DocTarget = { type: "settings", section: "appearance" };
const initial = (): CanvasDocument => ({ format: "infraternal.canvas", version: 1, revision: 0, views: [{ id: "console", kind: "console", name: "Console", cell: { x: 0, y: 0 }, layout: { type: "tiled", columns: [{ id: "root", weight: 0.2, windows: [{ id: "root", target }] }] } }] });
function sequence(seed: number): Intent[] {
  let state = seed >>> 0, drawing = initial();
  const random = (n: number): number => { state ^= state << 13; state ^= state >>> 17; state ^= state << 5; return (state >>> 0) % n; };
  const pick = <T>(values: readonly T[]): T => values[random(values.length)]!;
  const intents: Intent[] = [];
  for (let step = 0; step < 512; step++) {
    const view = drawing.views[0]!;
    if (view.layout.type !== "tiled") throw Error("expected tiled view");
    const columns = view.layout.columns, live = columns.flatMap((c) => c.windows);
    const id = pick(live)?.id ?? "absent", column = pick(columns)?.id ?? "root";
    const fresh = `s${seed}-${step}`, kind = random(100);
    let intent: Intent;
    if (!live.length || kind < 12) intent = { type: "open", view_id: "console", column_id: column, window: { id: fresh, target } };
    else if (kind < 42 && live.length < 48) intent = { type: "split", view_id: "console", column_id: fresh, anchor_id: id, axis: pick(["right", "down"] as const), window: { id: fresh, target } };
    else if (kind < 65) intent = { type: "resize", window_id: id, height: pick([null, 0.05, 0.1, 1, 10_000]), span: pick([null, 1, 2, 64]), rows: pick([null, 1, 2, 64]), row: pick([null, 0, 1, 64]) };
    else if (kind < 84) intent = { type: "close", window_id: id };
    else if (kind < 94) intent = { type: "weight", view_id: "console", column_id: column, weight: pick([0.1, 0.125, 0.2, 10]) };
    else intent = { type: "move", view_id: "console", window_id: id, column_id: column, after: id };
    intents.push(intent);
    // Prefer live references. This provisional drawing only chooses subsequent IDs;
    // the independent oracle decides acceptance and the assertion uses its canonical history.
    const next = structuredClone(drawing); reduce(next, intent);
    if (parseDocument(next)) drawing = next;
  }
  return intents;
}
test("review r2: longer boundary-weighted sequences preserve every accepted projection", () => {
  const seeds = [0x91e10da5, 0xdeadbeef, 0x12345678, 0xabcdef01, 97, 65537, 99991, 20261019];
  const cases = seeds.map((seed) => ({ document: initial(), intents: sequence(seed) }));
  const oracle = Bun.spawnSync(["cargo", "run", "--quiet", "-p", "infraternal-plugin-canvas", "--example", "layout_oracle"], {
    cwd: new URL("../../../../../", import.meta.url).pathname,
    stdin: new TextEncoder().encode(cases.map((entry) => JSON.stringify(entry)).join("\n") + "\n"), maxBuffer: 128 * 1024 * 1024,
  });
  if (oracle.exitCode !== 0) throw Error(new TextDecoder().decode(oracle.stderr));
  const results = new TextDecoder().decode(oracle.stdout).trim().split("\n").map((line) => JSON.parse(line) as Array<{ accepted: boolean; document: CanvasDocument }>);
  let accepted = 0;
  for (const [index, entry] of cases.entries()) {
    const projection = structuredClone(entry.document);
    for (const [step, intent] of entry.intents.entries()) {
      const row = results[index]![step]!;
      if (row.accepted) { reduce(projection, intent); accepted++; }
      expect(projection, `seed=${seeds[index]} step=${step} intent=${JSON.stringify(intent)}`).toEqual(row.document);
    }
  }
  console.log(`review r2 boundary comparison: ${seeds.length} seeds, 4096 operations, ${accepted} accepted`);
}, 120_000);
