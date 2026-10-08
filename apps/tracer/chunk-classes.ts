/**
 * Classifies the bundle's JavaScript chunks as critical or deferred, from the build graph (D188).
 *
 * - **Critical**: everything needed before the first paint of sign-in and of the first screen. That is every
 *   entry (the app, the workers), everything they import statically, and every chunk they or those chunks load
 *   dynamically, except the deferred roots below. So the terminal, its renderer and the core screen are critical.
 * - **Deferred**: code reachable only through a deferred root, the canvas product module (views, Mesh, the
 *   toolbar's edit mode, the droplet, the settings windows). A chunk that a critical chunk also uses stays critical.
 *
 * The only hand-kept input is the list of deferred root modules (the places the app lazily enters the canvas);
 * chunk names are never listed, so a rebuild, a split or a merge of chunks cannot make the gate stale.
 */
export interface MetaOutput {
  imports: Array<{ path: string; kind: string }>;
  entryPoint?: string;
  inputs: Record<string, unknown>;
}

/** Modules that start the canvas lazily; their chunk and what only they use are deferred. */
export const DEFERRED_ROOTS = ["src/canvas/product.ts", "src/canvas/mock/index.ts"];

export interface ChunkClasses { critical: string[]; deferred: string[] }

const name = (path: string): string => path.replace(/^\.\//, "");

export function classifyChunks(outputs: Record<string, MetaOutput>): ChunkClasses {
  const byName = new Map(Object.entries(outputs).map(([path, out]) => [name(path), out]));
  const isRoot = (chunk: string): boolean => Object.keys(byName.get(chunk)?.inputs ?? {}).some((input) => DEFERRED_ROOTS.some((root) => input.endsWith(root)));
  const critical = new Set<string>();
  const queue: string[] = [];
  for (const [chunk, out] of byName) if (out.entryPoint !== undefined && !isRoot(chunk)) queue.push(chunk);
  while (queue.length) {
    const chunk = queue.pop()!;
    if (critical.has(chunk)) continue;
    critical.add(chunk);
    for (const edge of byName.get(chunk)?.imports ?? []) {
      const target = name(edge.path);
      if (byName.has(target) && !critical.has(target) && (edge.kind === "import-statement" || !isRoot(target))) queue.push(target);
    }
  }
  const deferred = new Set<string>();
  const rest = [...byName.keys()].filter((chunk) => isRoot(chunk) && !critical.has(chunk));
  while (rest.length) {
    const chunk = rest.pop()!;
    if (deferred.has(chunk) || critical.has(chunk)) continue;
    deferred.add(chunk);
    for (const edge of byName.get(chunk)?.imports ?? []) {
      const target = name(edge.path);
      if (byName.has(target)) rest.push(target);
    }
  }
  return { critical: [...critical].sort(), deferred: [...deferred].sort() };
}
