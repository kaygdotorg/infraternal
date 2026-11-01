/**
 * The About pane's key/value list, in a chunk of its own so the shared list (kv-list.ts, with its copy confirmation, marks and
 * in-place changes) is not part of the first screen (D188). `settings-overlay.ts` loads it when About opens, and once when the
 * page is idle.
 */
import { createKeyValueList, type KeyValueRow } from "./kv-list";

/** Fills `container` with a list of `rows`; returns the disposer. */
export function renderFactList(container: HTMLElement, label: string, rows: KeyValueRow[]): () => void {
  const list = createKeyValueList(label);
  list.set(rows);
  container.append(list.root);
  return () => list.dispose();
}
