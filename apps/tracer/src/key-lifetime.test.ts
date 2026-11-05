/**
 * D336: changing the API key lifetime in Settings needs a passkey tap bound to that exact value.
 * A plain sign-in authorizes no security-settings change, so the re-authentication that follows
 * a refusal must name the action and the new value.
 */
import { expect, test } from "bun:test";
import { writeKeyLifetime } from "./auth";

test("a refused key-lifetime change asks for a tap bound to that value", async () => {
  const seen: Array<{ url: string; body: unknown }> = [];
  globalThis.fetch = (async (url: string, init?: RequestInit) => {
    seen.push({ url: String(url), body: JSON.parse(String(init?.body ?? "null")) });
    // The update is refused; the tap's start then fails, so no WebAuthn prompt is reached.
    const status = String(url).endsWith("/login-start") ? 503 : 401;
    return new Response(JSON.stringify({ error: "x" }), { status, headers: { "Content-Type": "application/json" } });
  }) as unknown as typeof fetch;
  await expect(writeKeyLifetime(7, "laptop")).rejects.toBeDefined();
  expect(seen[0]).toEqual({ url: "/auth/security-settings-update", body: { api_key_lifetime_days: 7 } });
  const start = seen.find((request) => request.url.endsWith("/login-start"));
  expect(start?.body).toEqual({ action: { kind: "security.settings", api_key_lifetime_days: 7 } });
});
