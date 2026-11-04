/** Resolves the pinned renderer's optional Node filesystem loader inside browser builds. */
import type { BunPlugin } from "bun";

/**
 * A build plugin: add it to the bundler's `plugins` for the browser build. It answers the one unresolved import in the
 * renderer artifact with a stub whose `readFile` always throws, which makes the renderer fetch its WebAssembly instead.
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
    build.onLoad({ filter: /.*/, namespace: "browser-file-loader" }, () => ({
      contents: 'export function readFile() { throw new Error("Node filesystem unavailable in browser"); }',
      loader: "js",
    }));
  },
};
