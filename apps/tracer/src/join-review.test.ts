/** The browser reviews a join request only in the exact shape the server promises, for the link form that opened it (#263). */
import { afterEach, expect, test } from "bun:test";
import { AuthError, approveDeviceApproval, inspectDeviceApproval } from "./auth";
import { shortFingerprint } from "./key-fingerprint";

const FINGERPRINT = "SHA256:AbCdEfGhIjKlMnOpQrStUvWxYz0123456789+/AbCde";
const CODE = "AbCdEfGhIjKlMnOp";
const realFetch = globalThis.fetch;
afterEach(() => { globalThis.fetch = realFetch; });

function server(answer: unknown, status = 200): Array<{ url: string; body: unknown }> {
  const seen: Array<{ url: string; body: unknown }> = [];
  globalThis.fetch = (async (url: string, init?: RequestInit) => {
    seen.push({ url, body: JSON.parse(String(init?.body ?? "null")) });
    return new Response(JSON.stringify(answer), { status, headers: { "Content-Type": "application/json" } });
  }) as unknown as typeof fetch;
  return seen;
}

const join = { kind: "join_machine", hostname: "build-01", mode: "system", key_fingerprint: FINGERPRINT };

test("a join request is read as hostname, mode and key fingerprint, and the code goes in the body", async () => {
  const seen = server(join);
  expect(await inspectDeviceApproval(CODE, "join_machine")).toEqual({
    kind: "join_machine", hostname: "build-01", mode: "system", keyFingerprint: FINGERPRINT,
  });
  expect(seen).toEqual([{ url: "/auth/device-inspect", body: { code: CODE } }]);
});

test("a join link never opens a sign-in answer, and a sign-in link never opens a join answer", async () => {
  server({ device: "kayg-laptop", scopes: ["hosts:read", "terminal:connect", "actions:dry-run"] });
  await expect(inspectDeviceApproval(CODE, "join_machine")).rejects.toBeInstanceOf(AuthError);
  server(join);
  await expect(inspectDeviceApproval(CODE, "sign_in")).rejects.toBeInstanceOf(AuthError);
});

test("the sign-in answer without a kind is still accepted", async () => {
  server({ device: "kayg-laptop", scopes: ["hosts:read", "terminal:connect", "actions:dry-run"] });
  expect(await inspectDeviceApproval(CODE, "sign_in")).toMatchObject({ kind: "sign_in", device: "kayg-laptop" });
});

test("a join answer with a bad field is refused whole", async () => {
  for (const bad of [
    { ...join, mode: "root" },
    { ...join, hostname: "" },
    { ...join, hostname: "a\nb" },
    { ...join, hostname: "x".repeat(129) },
    { ...join, key_fingerprint: "SHA256:short" },
    { ...join, key_fingerprint: "MD5:00:11" },
    { ...join, key_fingerprint: undefined },
  ]) {
    server(bad);
    await expect(inspectDeviceApproval(CODE, "join_machine")).rejects.toBeInstanceOf(AuthError);
  }
});

test("an expired join request tells the person to run up again", async () => {
  server({ error: "x" }, 401);
  await expect(inspectDeviceApproval(CODE, "join_machine")).rejects.toThrow("infraternal up");
  server({ error: "x" }, 404);
  await expect(approveDeviceApproval(CODE, "join_machine")).rejects.toThrow("Upgrade the server");
});

test("a malformed code is refused before any request", async () => {
  const seen = server(join);
  await expect(inspectDeviceApproval("short", "join_machine")).rejects.toThrow("infraternal up");
  expect(seen).toEqual([]);
});

test("the short fingerprint is the first sixteen characters in groups of four", () => {
  expect(shortFingerprint(FINGERPRINT)).toBe("AbCd EfGh IjKl MnOp");
});
