/**
 * Loads the terminal engine's WebAssembly from its own content-hashed file (#573).
 *
 * The pinned renderer ships the engine as base64 inside its script, which made the terminal chunk a third larger (the
 * wasm's base64 is about 133 KB of Brotli against 99 KB for the raw bytes) and forced the browser to decode it and
 * compile it only after the whole chunk had arrived. Here the build leaves the base64 out (`browser-build.ts`) and the
 * wasm is a file of its own, served as `application/wasm` with a year-long immutable cache. The browser compiles it
 * while it downloads (`WebAssembly.instantiateStreaming`), and a signed-in device fetches it alongside the page
 * (`entry-preload.ts`), so by the time the terminal chunk runs the engine is usually ready.
 *
 * Use {@link loadEngine}: it is memoised, so every renderer shares one engine.
 */
import { Ghostty } from "../vendor/ghostty-web";
// The bundler copies the file to `ghostty-vt-<hash>.wasm` and gives back its URL; under `bun test` it is the source path.
import engineUrl from "../vendor/ghostty-web/dist/ghostty-vt.wasm" with { type: "file" };

/** The imports the engine expects: one logging hook the engine calls with a pointer and a length into its own memory. */
function engineImports(holder: { instance?: WebAssembly.Instance }): WebAssembly.Imports {
  return {
    env: {
      log: (pointer: number, length: number) => {
        const memory = holder.instance?.exports.memory as WebAssembly.Memory | undefined;
        if (memory) console.log("[ghostty-vt]", new TextDecoder().decode(new Uint8Array(memory.buffer, pointer, length)));
      },
    },
  };
}

/**
 * Fetches and instantiates the engine. Streaming compilation needs the server to say `application/wasm`; when the
 * response has another type (or a proxy rewrites it) the bytes are compiled the ordinary way instead, so a mislabelled
 * file costs time, never the terminal.
 * @param url where the wasm file is
 */
async function instantiate(url: string): Promise<Ghostty> {
  const holder: { instance?: WebAssembly.Instance } = {};
  const imports = engineImports(holder);
  const response = await fetch(url);
  if (!response.ok) throw new Error(`Failed to fetch the terminal engine: ${response.status} ${response.statusText}`);
  let instance: WebAssembly.Instance;
  try {
    // A clone, so the fallback below can still read the body when streaming refuses it before consuming it.
    ({ instance } = await WebAssembly.instantiateStreaming(response.clone(), imports));
  } catch {
    const bytes = await response.arrayBuffer();
    if (bytes.byteLength === 0) throw new Error("The terminal engine file is empty");
    ({ instance } = await WebAssembly.instantiate(bytes, imports));
  }
  holder.instance = instance;
  return new Ghostty(instance);
}

/** The shared engine, started by the first caller; cleared on failure so a later attempt can retry. */
let engine: Promise<Ghostty> | undefined;

/**
 * The terminal engine, loaded once.
 * @returns the engine to pass to `new Terminal({ ghostty })`
 */
export function loadEngine(): Promise<Ghostty> {
  if (!engine) {
    const attempt = instantiate(engineUrl);
    engine = attempt;
    attempt.catch(() => { if (engine === attempt) engine = undefined; });
  }
  return engine;
}
