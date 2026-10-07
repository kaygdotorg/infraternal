/** Checks callable signed-in rotation using production crypto and captured HTTP requests. */
import { expect, test } from "bun:test";
import { recoveryAuth as auth, type Wrap } from "../src/auth";
import * as recovery from "../src/recovery-auth";

const user = "00000000-0000-0000-0000-000000000001";
test("signed-in rotation sends only a local envelope and verifier after acknowledgement", async () => {
  const originalFetch = globalThis.fetch;
  const dek = new Uint8Array(32).fill(9);
  const requests: { path: string; body: Record<string, unknown>; account: string | null }[] = [];
  globalThis.fetch = (async (path: string | URL | Request, init?: RequestInit) => {
    requests.push({ path: String(path), body: JSON.parse(String(init?.body)) as Record<string, unknown>, account: new Headers(init?.headers).get("X-Infraternal-User") });
    return new Response(JSON.stringify({ ok: true }), { status: 200 });
  }) as unknown as typeof fetch;
  try {
    let displayed = "";
    await recovery.rotateRecoveryWords(user, dek, async (words, finish) => {
      displayed = words;
      expect(requests.length).toBe(0);
      await Promise.all([finish(), finish()]);
    });
    expect(requests.length).toBe(1);
    const request = requests[0]!;
    expect(request.account).toBe(user);
    expect(request.path).toBe("/auth/recovery-rotate");
    expect(Object.keys(request.body).sort()).toEqual(["recovery_verifier", "recovery_wrap"]);
    const derived = await auth.recoverySecrets(displayed);
    expect(request.body.recovery_verifier === derived.verifier).toBe(true);
    const wrap = request.body.recovery_wrap as Wrap;
    expect(Buffer.from(await auth.unwrapRecoveryDek(displayed, wrap, user, 2)).equals(Buffer.from(dek))).toBe(true);
    let denied = false;
    try { await auth.unwrapDek(Buffer.from(derived.verifier, "base64url"), wrap, user, "recovery"); }
    catch { denied = true; }
    expect(denied).toBe(true);
    derived.wrap.fill(0);
    expect(dek.every(byte => byte === 9)).toBe(true);
  } finally { globalThis.fetch = originalFetch; }
});

test("abandoned word acknowledgement uploads nothing", async () => {
  const originalFetch = globalThis.fetch;
  let requests = 0;
  globalThis.fetch = (async () => { requests++; return new Response("{}"); }) as unknown as typeof fetch;
  try {
    await expect(recovery.rotateRecoveryWords(user, new Uint8Array(32), async () => { throw new Error("dismissed"); })).rejects.toThrow("dismissed");
    expect(requests).toBe(0);
  } finally { globalThis.fetch = originalFetch; }
});

for (const dismiss of [true, false]) {
  test(`settled acknowledgement cannot upload later (${dismiss ? "dismissed" : "no acknowledgement"})`, async () => {
    const original = globalThis.fetch;
    let requests = 0;
    let retained: (() => Promise<void>) | undefined;
    globalThis.fetch = (async () => { requests++; return new Response("{}"); }) as unknown as typeof fetch;
    try {
      await expect(recovery.rotateRecoveryWords(user, new Uint8Array(32), async (_words, finish) => {
        retained = finish;
        if (dismiss) throw new Error("dismissed");
      })).rejects.toThrow();
      expect(retained).toBeDefined();
      await expect(retained!()).rejects.toThrow();
      expect(requests).toBe(0);
    } finally { globalThis.fetch = original; }
  });
}
