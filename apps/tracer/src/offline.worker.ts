/** Keeps only public app-shell assets that a signed-in page has already used, for offline layout drawing (D245). */
/// <reference lib="webworker" />
const worker = globalThis as unknown as ServiceWorkerGlobalScope;
/** The name of the cache that holds the app-shell files; bump the version suffix to drop old entries. */
const cacheName = "infraternal-drawing-v1";
/**
 * The URL when `input` is a same-origin script, stylesheet, font or WebAssembly file that has no query string and is not
 * under `/v1/` (the API); otherwise `undefined`. This is the only kind of file the worker will ever cache.
 */
function staticUrl(input: string): URL | undefined {
  try {
    const url = new URL(input, worker.location.origin);
    return url.origin === worker.location.origin && !url.pathname.startsWith("/v1/") && !url.search && /\.(?:js|css|woff2|wasm)$/.test(url.pathname) ? url : undefined;
  } catch { return undefined; }
}
worker.addEventListener("install", (event) => { event.waitUntil(worker.skipWaiting()); });
worker.addEventListener("activate", (event) => { event.waitUntil(worker.clients.claim()); });
worker.addEventListener("message", (event) => {
  const value: unknown = event.data;
  if (!value || typeof value !== "object" || !("type" in value) || value.type !== "cache-drawing-assets" || !("paths" in value) || !Array.isArray(value.paths)) return;
  const paths = value.paths.filter((p): p is string => typeof p === "string").map(staticUrl).filter((u): u is URL => Boolean(u));
  event.waitUntil((async () => {
    const cache = await caches.open(cacheName);
    for (const path of ["/", ...new Set(paths.map((u) => u.pathname))]) {
      try { const response = await fetch(path, { credentials: "omit" }); if (response.ok) await cache.put(path, response); } catch { /* keep the prior public asset while offline */ }
    }
    const keys = await cache.keys();
    for (const key of keys.slice(0, Math.max(0, keys.length - 256))) await cache.delete(key);
  })());
});
worker.addEventListener("fetch", (event) => {
  const url = new URL(event.request.url);
  const navigation = event.request.mode === "navigate" && url.origin === worker.location.origin && url.pathname === "/";
  if (event.request.method !== "GET" || (!navigation && !staticUrl(url.href))) return;
  const key = navigation ? "/" : url.pathname;
  event.respondWith((async () => {
    const cache = await caches.open(cacheName);
    try {
      const response = await fetch(event.request);
      if (response.ok && response.type !== "opaque") await cache.put(key, response.clone());
      return response;
    } catch {
      const cached = await cache.match(key);
      return cached ?? Response.error();
    }
  })());
});
