/** Cached retries must be replayable before either offline startup or a connected canvas accepts them (#243). */
import { expect, test } from "bun:test";
import { readLayoutCache } from "./cache";
const canonical = { format: "infraternal.canvas", version: 1, revision: 1, views: [{ id: "console", kind: "console", name: "Console", cell: { x: 0, y: 0 }, layout: { type: "tiled", columns: [] } }] };
const cache = (intent: unknown) => ({ cacheVersion: 2, canonical, document: canonical, pending: [{ op_id: "12345678-1234-4234-8234-123456789abc", base_revision: 1, intent }] });
test("damaged pending opens cannot stall offline drawing", () => {
  expect(readLayoutCache(cache({ type: "open", view_id: "console", column_id: "c" }))).toBeUndefined();
  expect(readLayoutCache(cache({ type: "open", view_id: "console", column_id: "c", window: { id: "w", target: null } }))).toBeUndefined();
  expect(readLayoutCache({ ...cache({ type: "close", window_id: "w" }), pending: [null] })).toBeUndefined();
});
test("a valid unresolved reference remains local and replayable", () => {
  const value = readLayoutCache({ ...cache({ type: "open", view_id: "console", column_id: "c", window: { id: "w", target: { type: "session", id: "w", host: "local" } } }), unresolved: ["w"] });
  expect(value?.pending).toHaveLength(1); expect(value?.unresolved.has("w")).toBe(true);
});
