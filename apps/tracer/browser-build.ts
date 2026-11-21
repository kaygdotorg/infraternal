/** Browser-build plugin for the pinned renderer: resolves its optional Node filesystem loader and leaves its embedded wasm out. */
import type { BunPlugin } from "bun";

/** The renderer artifact's embedded engine: a data URL holding the whole wasm in base64. */
const ENGINE_DATA_URL = /data:application\/wasm;base64,[A-Za-z0-9+/=]+/;

/**
 * A build plugin: add it to the bundler's `plugins` for the browser build. It answers the one unresolved import in the
 * renderer artifact with a stub whose `readFile` always throws, and it removes the artifact's base64 copy of the engine
 * (the app loads the wasm file itself, see `src/engine-wasm.ts`).
 */
export const browserFileLoader: BunPlugin = {
  name: "browser-file-loader",
  setup(build) {
    // The pinned Vite artifact leaves this import unresolved. In a browser its
    // readFile attempt must throw so Ghostty uses fetch for its inline WASM.
    // Bundling the shim produces an immutable chunk instead of requesting SPA
    // HTML and paying a no-cache revalidation on every returning sign-in.
    build.onResolve({ filter: /\/__vite-browser-external-2447137e\.js$/ }, () => ({
      path: "node-file-unavailable",
      namespace: "browser-file-loader",
    }));
    // The engine's wasm travels as a file of its own (src/engine-wasm.ts), so the artifact's base64 copy of it is cut
    // out: the one place it appears is the default of `Ghostty.load()`, which the app never calls without a path.
    // The build fails loudly if a re-pinned artifact no longer has that shape.
    build.onLoad({ filter: /\/ghostty-web\/dist\/ghostty-web\.js$/ }, async (args) => {
      const source = await Bun.file(args.path).text();
      const stripped = source.replace(ENGINE_DATA_URL, "data:application/wasm;base64,");
      if (stripped === source) throw new Error("ghostty-web.js has no embedded wasm to leave out: update browser-build.ts for the new artifact");
      return { contents: stripped, loader: "js" };
    });
    build.onLoad({ filter: /.*/, namespace: "browser-file-loader" }, () => ({
      contents: 'export function readFile() { throw new Error("Node filesystem unavailable in browser"); }',
      loader: "js",
    }));
  },
};
