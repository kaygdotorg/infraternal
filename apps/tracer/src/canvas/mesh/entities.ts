/**
 * The Mesh view's names as entity chips (`packages/ui/src/entity-chip.ts`): a tag, or a host with its tags and its
 * operating system, drawn the same in confirmations, toasts and cards. Copy stays a plain-language template with
 * `{placeholders}`; `say` gives the sentence both as plain text (labels, tests) and as text with chips.
 */
import { entityChip, entityPlain, entityText, type EntityRef } from "../../../../../packages/ui/src/entity-chip";
import type { MeshSource } from "./source";

/** A tag or host id as the thing it names, with what its colours need (a host's tags, its system). */
export function meshEntity(source: MeshSource, id: string): EntityRef {
  if (id.startsWith("tag:")) return { kind: "tag", name: id };
  const node = source.data().nodes.get(id);
  return { kind: "host", name: id, via: node?.tags ?? [], ...(node?.os ? { platform: node.os } : {}) };
}

/** A sentence in two forms: `plain` text for labels and tests, and `node` with entity chips for display. */
export interface Say { plain: string; node: DocumentFragment }

/** `say("Let {a} reach {b}?", { a: "tag:ci", b: "nix-cache" })`. */
export function createSay(source: MeshSource): (template: string, ids: Readonly<Record<string, string>>) => Say {
  return (template, ids) => {
    const refs = Object.fromEntries(Object.entries(ids).map(([k, id]) => [k, meshEntity(source, id)]));
    return { plain: entityPlain(template, refs), node: entityText(template, refs) };
  };
}

/** The tags of a host as chips, for a card's detail line. */
export function tagChips(names: readonly string[]): DocumentFragment {
  const out = document.createDocumentFragment();
  for (const name of names) out.append(entityChip({ kind: "tag", name: name.startsWith("tag:") ? name : `tag:${name}` }), " ");
  return out;
}
