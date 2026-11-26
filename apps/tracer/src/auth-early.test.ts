/**
 * Verifies the one-shot early auth fetch handoff between `index.html` and `src/auth.ts` (#573).
 *
 * `index.html` starts `/auth/status` and `/auth/session` while `main.js` is still downloading and stores the
 * promises on `window.__earlyAuth`. `checkStatus` and `checkSession` must consume each slot once and issue fresh
 * `fetch` requests for every later call (refresh, foreground check, retry).
 */
import { afterEach, expect, test } from "bun:test";
import { checkSession, checkStatus } from "./auth";

/** Original `window` global restored after every test so the single-process unit suite stays isolated (#503). */
const originalWindow = globalThis.window;
/** Original `fetch` global restored after every test. */
const originalFetch = globalThis.fetch;

afterEach(() => {
  if (originalWindow === undefined) delete (globalThis as { window?: unknown }).window;
  else (globalThis as { window?: unknown }).window = originalWindow;
  globalThis.fetch = originalFetch;
});

/** Builds a minimal JSON Response matching the server's auth endpoints. */
function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
}

test("checkStatus and checkSession consume window.__earlyAuth once and fetch fresh afterwards", async () => {
  const fetched: string[] = [];
  globalThis.fetch = (async (input: RequestInfo | URL) => {
    const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
    fetched.push(url);
    if (url.endsWith("/auth/status")) return jsonResponse({ setup_required: false });
    return jsonResponse({}, 401);
  }) as typeof fetch;

  (globalThis as { window?: unknown }).window = {
    __earlyAuth: {
      status: Promise.resolve(jsonResponse({ setup_required: false })),
      session: Promise.resolve(jsonResponse({ user_id: "u1", username: "a", display_name: "A", device: "d", fresh: 1 })),
    },
  };

  const firstStatus = await checkStatus();
  const firstSession = await checkSession();
  expect(firstStatus.setupRequired).toBe(false);
  expect(firstSession?.user_id).toBe("u1");
  expect(fetched).toEqual([]);

  const secondStatus = await checkStatus();
  const secondSession = await checkSession();
  expect(secondStatus.setupRequired).toBe(false);
  expect(secondSession).toBeUndefined();
  expect(fetched).toEqual(["/auth/status", "/auth/session"]);
});
