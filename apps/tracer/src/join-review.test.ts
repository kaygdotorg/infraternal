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
  // The server always sends the key lifetime the tap approves (D333).
  server({ device: "kayg-laptop", scopes: ["hosts:read", "terminal:connect", "actions:dry-run"], lifetime_seconds: 86400 });
  expect(await inspectDeviceApproval(CODE, "sign_in")).toMatchObject({ kind: "sign_in", device: "kayg-laptop" });
});

test("a join answer with a bad field is refused whole", async () => {
  for (const bad of [
    { ...join, mode: "root" },
    { ...join, hostname: "" },
    { ...join, hostname: "a\nb" },
    { ...join, hostname: "x".repeat(129) },
    // J134 P3-3: bidi overrides, zero-width and other non-ASCII characters make one name read as another.
    { ...join, hostname: "build-\u202e10-dliub" },
    { ...join, hostname: "build\u200b-01" },
    { ...join, hostname: "build\u2066-01" },
    { ...join, hostname: "bu\u0456ld-01" },
    { ...join, hostname: "build 01" },
    { ...join, key_fingerprint: "SHA256:short" },
    { ...join, key_fingerprint: "MD5:00:11" },
    { ...join, key_fingerprint: undefined },
  ]) {
    server(bad);
    await expect(inspectDeviceApproval(CODE, "join_machine")).rejects.toBeInstanceOf(AuthError);
  }
});

test("a sign-in device name with a format character is refused", async () => {
  const scopes = ["hosts:read", "terminal:connect", "actions:dry-run"];
  for (const device of ["kayg-\u202elaptop", "kayg\u200blaptop", "kayg\ufefflaptop", "kayg\u2028laptop"]) {
    server({ device, scopes });
    await expect(inspectDeviceApproval(CODE, "sign_in")).rejects.toBeInstanceOf(AuthError);
  }
  server({ device: "Kayg's laptop", scopes });
  expect(await inspectDeviceApproval(CODE, "sign_in")).toMatchObject({ device: "Kayg's laptop" });
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
