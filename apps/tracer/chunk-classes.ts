/**
 * Classifies the bundle's JavaScript chunks into three transfer classes, from the build graph (D188).
 *
 * - **Critical**: everything needed before the first paint of sign-in and of the first screen. That is every
 *   entry (the app and first-screen workers), everything they import statically, and every chunk they or those
 *   chunks load dynamically, except the roots below. So the terminal, its renderer and the core screen are critical.
 * - **Deferred**: code only the lazily loaded canvas reaches (views, Mesh, the toolbar's edit mode).
 *   It loads after the first screen without the person asking for it.
 * - **On demand**: code that loads only when the person takes an action (the add-host wizard, the share studio, a
 *   Settings window). Its roots are modules named `*.on-demand.ts` (see src/on-demand.ts).
 *
 * A chunk that more than one class reaches belongs to the earliest: critical, then deferred, then on demand.
 *
 * The only hand-kept input is the list of deferred roots (the places the app lazily enters the canvas or
 * warms its offline drawing cache after sign-in);
 * on-demand roots are found by their file name, and chunk names are never listed, so a rebuild, a split or a merge
 * of chunks cannot make the gate stale.
 */
/** One output file of the bundler's metafile: the chunks it imports (with the import kind), its entry point if it is one, and the source files inside it. */
export interface MetaOutput {
  imports: Array<{ path: string; kind: string }>;
  entryPoint?: string;
  inputs: Record<string, unknown>;
}

/** Canvas and offline drawing roots load after the first screen; their exclusive imports are deferred. */
export const DEFERRED_ROOTS = ["src/canvas/product.ts", "src/canvas/mock/index.ts", "src/canvas/sessions/hosts.ts", "src/canvas/model/reconcile.ts", "src/offline-drawing.ts", "src/offline.worker.ts"];
/** Modules the person's action loads: named `*.on-demand.ts`. */
export const ON_DEMAND_PATTERN = /\.on-demand\.ts$/;

/** The chunk file names of each transfer class, sorted. */
export interface ChunkClasses { critical: string[]; deferred: string[]; onDemand: string[] }

/** A metafile path without a leading `./`, so paths from `outputs` and from `imports` compare equal. */
const name = (path: string): string => path.replace(/^\.\//, "");

/**
 * Sorts the chunks of a build into critical, deferred and on-demand (see the module comment).
 * @param outputs the `outputs` object of the bundler's metafile
 * @returns the three lists; a chunk appears in exactly one of them. Chunks that no class reaches appear in none.
 */
export function classifyChunks(outputs: Record<string, MetaOutput>): ChunkClasses {
  const byName = new Map(Object.entries(outputs).map(([path, out]) => [name(path), out]));
  const hasInput = (chunk: string, test: (input: string) => boolean): boolean => Object.keys(byName.get(chunk)?.inputs ?? {}).some(test);
  const isDeferredRoot = (chunk: string): boolean => hasInput(chunk, (input) => DEFERRED_ROOTS.some((root) => input.endsWith(root)));
  const isOnDemandRoot = (chunk: string): boolean => hasInput(chunk, (input) => ON_DEMAND_PATTERN.test(input));
  const isRoot = (chunk: string): boolean => isDeferredRoot(chunk) || isOnDemandRoot(chunk);

  /** Walks the graph from `seeds`, entering a root chunk only through a static import, and never entering `taken`. */
  const reach = (seeds: string[], taken: Set<string>, enter: (chunk: string) => boolean): Set<string> => {
    const seen = new Set<string>();
    const queue = [...seeds];
    while (queue.length) {
      const chunk = queue.pop()!;
      if (seen.has(chunk) || taken.has(chunk)) continue;
      seen.add(chunk);
      for (const edge of byName.get(chunk)?.imports ?? []) {
        const target = name(edge.path);
        if (byName.has(target) && !seen.has(target) && (edge.kind === "import-statement" || enter(target))) queue.push(target);
      }
    }
    return seen;
  };
  const none = new Set<string>();
  const entries = [...byName].filter(([chunk, out]) => out.entryPoint !== undefined && !isRoot(chunk)).map(([chunk]) => chunk);
  const critical = reach(entries, none, (chunk) => !isRoot(chunk));
  const deferred = reach([...byName.keys()].filter((c) => isDeferredRoot(c) && !critical.has(c)), critical, (chunk) => !isOnDemandRoot(chunk) || isDeferredRoot(chunk));
  const taken = new Set([...critical, ...deferred]);
  const onDemand = reach([...byName.keys()].filter((c) => isOnDemandRoot(c) && !taken.has(c)), taken, () => true);
  return { critical: [...critical].sort(), deferred: [...deferred].sort(), onDemand: [...onDemand].sort() };
}
