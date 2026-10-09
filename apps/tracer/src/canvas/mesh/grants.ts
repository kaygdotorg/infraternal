/**
 * Reachability over mesh grants, pure (no DOM). A grant "A to B" lets A open connections to B (D164); a tag
 * stands for the hosts that carry it. The Mesh adapter (`source.ts`) supplies the tags and grants.
 */
import type { Grant } from "../model/types";

/** Hosts a node (a host or a tag) stands for. */
export const hostsOf = (id: string, tags: Readonly<Record<string, readonly string[]>>): readonly string[] => (id.startsWith("tag:") ? tags[id] ?? [] : [id]);

/** Hosts that `host` can reach through the grants, with the relay when the route needs one. */
export function reach(host: string, grants: readonly Grant[], tags: Readonly<Record<string, readonly string[]>> = {}): Array<{ host: string; via?: string }> {
  const out = new Map<string, { host: string; via?: string }>();
  for (const g of grants) {
    // A grant that works both ways (a double-headed arrow, D164) also lets its other end reach the first.
    for (const [a, b] of g.both ? [[g.from, g.to], [g.to, g.from]] as const : [[g.from, g.to]] as const) {
      if (!hostsOf(a, tags).includes(host)) continue;
      for (const t of hostsOf(b, tags)) if (t !== host && !out.has(t)) out.set(t, { host: t, ...(g.via ? { via: g.via } : {}) });
    }
  }
  return [...out.values()];
}
