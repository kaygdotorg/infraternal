// SPDX-License-Identifier: AGPL-3.0-only
/**
 * Serves public release objects from the RELEASES binding at their existing R2
 * keys (D401). The static release landing page and the rest of the site stay
 * on the Pages asset server.
 */

/** The published pointer and index keys can change after each release. */
const MUTABLE = /^releases\/(?:index\.json|channels\/(?:stable|edge)\.json)$/;

/** Versioned keys are write-once. Published filenames use portable ASCII path segments. */
const VERSIONED = /^releases\/(?:[0-9]+\.[0-9]+\.[0-9]+|edge-[0-9]{8}T[0-9]{6}Z)(?:\/[A-Za-z0-9_][A-Za-z0-9_.-]*)+$/;

/** Infers the type from the public filename because older uploads use generic R2 metadata. */
function contentType(key) {
  if (key.endsWith(".json")) return "application/json";
  if (key.endsWith(".tar.gz") || key.endsWith(".gz")) return "application/gzip";
  if (key.endsWith(".tar")) return "application/x-tar";
  if (key.endsWith(".zip")) return "application/zip";
  if (/(?:\/(?:VERSION|SHA256SUMS)(?:\.sig)?|\.(?:md|txt))$/.test(key)) return "text/plain; charset=utf-8";
  return "application/octet-stream";
}

/** Builds public headers from trusted object fields, without inheriting bucket cache policy. */
function objectHeaders(key, object, immutable) {
  return new Headers({
    "Accept-Ranges": "bytes",
    "Cache-Control": immutable ? "public, max-age=31536000, immutable" : "no-store",
    "Content-Type": contentType(key),
    "ETag": object.httpEtag,
    "Last-Modified": object.uploaded.toUTCString(),
    "X-Content-Type-Options": "nosniff",
  });
}

/** Tests an entity-tag list, using weak comparison only where HTTP permits it. */
function matchesTag(value, etag, weak = false) {
  if (value.trim() === "*") return true;
  return (value.match(/(?:W\/)?"[^"]*"/g) ?? []).some(tag => (weak ? tag.replace(/^W\//, "") : tag) === etag);
}

/** HTTP dates have one-second precision, while R2 upload timestamps can include milliseconds. */
function modifiedAt(object) {
  return Math.floor(object.uploaded.getTime() / 1000) * 1000;
}

/** Evaluates GET and HEAD preconditions in HTTP precedence order. */
function conditionalStatus(headers, object) {
  const ifMatch = headers.get("If-Match");
  if (ifMatch !== null ? !matchesTag(ifMatch, object.httpEtag) :
      modifiedAt(object) > Date.parse(headers.get("If-Unmodified-Since"))) return 412;
  const ifNoneMatch = headers.get("If-None-Match");
  if (ifNoneMatch !== null ? matchesTag(ifNoneMatch, object.httpEtag, true) :
      modifiedAt(object) <= Date.parse(headers.get("If-Modified-Since"))) return 304;
  return 200;
}

/** Resolves one byte range. Invalid or multipart syntax falls back to a full response. */
function byteRange(headers, object) {
  const ifRange = headers.get("If-Range");
  if (ifRange !== null && ifRange !== object.httpEtag && Date.parse(ifRange) !== modifiedAt(object)) return null;
  const match = /^bytes=(\d*)-(\d*)$/i.exec(headers.get("Range") ?? "");
  if (!match || (!match[1] && !match[2])) return null;

  const size = object.size;
  const offset = match[1] ? Number(match[1]) : Math.max(0, size - Number(match[2]));
  const end = match[1] && match[2] ? Number(match[2]) : size - 1;
  if (match[1] && match[2] && end < offset) return null;
  const length = Math.min(end + 1, size) - offset;
  return { offset, length };
}

/** Returns an empty, uncacheable error for a missing object or unsupported request. */
function errorResponse(status, headers = new Headers()) {
  headers.set("Cache-Control", "no-store");
  return new Response(null, { status, headers });
}

/**
 * Serves metadata-only and conditional requests. A ranged read uses the
 * inspected ETag so a pointer replaced concurrently cannot send bytes with
 * the previous representation's Content-Range or validators.
 */
async function serveWithMetadata(request, bucket, key, immutable) {
  const object = await bucket.head(key);
  if (!object) return errorResponse(request.headers.get("If-Match") === "*" ? 412 : 404);
  const headers = objectHeaders(key, object, immutable);
  const status = conditionalStatus(request.headers, object);
  if (status === 304) return new Response(null, { status, headers });
  if (status === 412) return errorResponse(status, headers);

  if (request.method === "HEAD") {
    headers.set("Content-Length", String(object.size));
    return new Response(null, { headers });
  }

  const range = byteRange(request.headers, object);
  if (range && range.length <= 0) {
    headers.set("Content-Range", `bytes */${object.size}`);
    return errorResponse(416, headers);
  }
  const body = await bucket.get(key, { onlyIf: { etagMatches: object.etag }, ...(range ? { range } : {}) });
  if (!body?.body) return errorResponse(503, new Headers({ "Retry-After": "0" }));
  headers.set("Content-Length", String(range?.length ?? object.size));
  if (range) headers.set("Content-Range", `bytes ${range.offset}-${range.offset + range.length - 1}/${object.size}`);
  return new Response(body.body, { status: range ? 206 : 200, headers });
}

/**
 * Fills the edge cache with its own stream. Cloning a download would tee it
 * and could buffer the entire object behind a slow client or cache writer.
 */
async function fillCache(cache, cacheKey, bucket, key, etag, headers) {
  const copy = await bucket.get(key, { onlyIf: { etagMatches: etag } });
  if (copy?.body) await cache.put(cacheKey, new Response(copy.body, { headers }));
}

/** Streams an unconditional GET and saves only complete, versioned responses to the edge cache. */
async function serveFull(context, key, immutable, url) {
  const bucket = context.env.RELEASES;
  const cache = immutable ? caches.default : null;
  url.search = "";
  const cacheKey = new Request(url.href);
  const hit = await cache?.match(cacheKey);
  if (hit) return hit;

  const object = await bucket.get(key);
  if (!object) return errorResponse(404);
  const headers = objectHeaders(key, object, immutable);
  headers.set("Content-Length", String(object.size));
  if (cache) {
    context.waitUntil(fillCache(cache, cacheKey, bucket, key, object.etag, headers).catch(() => {
      // An edge cache write failure must not interrupt a valid R2 download.
      console.warn("Release cache fill failed");
    }));
  }
  return new Response(object.body, { headers });
}

/** Handles read-only HTTP access to the public release namespace. */
export async function onRequest(context) {
  const { request } = context;
  const url = new URL(request.url);
  if (url.pathname === "/releases" || url.pathname === "/releases/") return context.next();
  const key = url.pathname.slice(1);
  const immutable = VERSIONED.test(key);
  if (!immutable && !MUTABLE.test(key)) return errorResponse(404);
  if (request.method !== "GET" && request.method !== "HEAD") {
    return errorResponse(405, new Headers({ Allow: "GET, HEAD" }));
  }
  const needsMetadata = request.method === "HEAD" || [
    "Range", "If-Match", "If-None-Match", "If-Modified-Since", "If-Unmodified-Since",
  ].some(name => request.headers.has(name));
  return needsMetadata
    ? serveWithMetadata(request, context.env.RELEASES, key, immutable)
    : serveFull(context, key, immutable, url);
}
