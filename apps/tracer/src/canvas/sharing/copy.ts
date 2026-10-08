/**
 * What a recipient gets when a layout is shared with them (D182): a copy that is theirs, named after the sender,
 * with hosts outside their own grants shown as "no access". Pure, so the rule can be tested alone.
 */
import type { ViewModel } from "../model/types";

/** A copy of a view as the recipient gets it: their own, with hosts outside their grants shown as "no access". */
export function copyForRecipient(snapshot: ViewModel, from: string, allowedHosts: readonly string[], idSuffix: string): ViewModel {
  const copy: ViewModel = JSON.parse(JSON.stringify(snapshot)) as ViewModel;
  copy.id = `${snapshot.id}-from-${from}-${idSuffix}`;
  copy.name = `${snapshot.name} (from ${from})`;
  copy.from = from;
  for (const col of copy.cols) for (const w of col.wins) {
    w.id = `${copy.id}:${w.id}`;
    if (w.kind === "terminal" && !allowedHosts.includes(w.host)) { w.noAccess = true; w.lines = []; }
  }
  return copy;
}