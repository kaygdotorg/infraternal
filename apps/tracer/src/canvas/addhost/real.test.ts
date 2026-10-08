// SPDX-License-Identifier: AGPL-3.0-only
import { afterEach, describe, expect, test } from "bun:test";
import { createRealProvisioning, parseDiscovered, parseInstallCommand, parseServerKey } from "./real";
import { ServiceError } from "./service";

const realFetch = globalThis.fetch;
afterEach(() => { globalThis.fetch = realFetch; });
const answer = (status: number, body: string, type = "application/json"): void => {
  globalThis.fetch = (async () => new Response(body, { status, headers: { "content-type": type } })) as unknown as typeof fetch;
};

describe("parsing the server's data", () => {
  test("a discovery row keeps only known fields and valid ids", () => {
    expect(parseDiscovered({ id: "o2", address: "10.0.0.2", sources: ["netbird", "nonsense"], reach: "ready", already_added: true, root_available: true, user: "kayg", os: "ubuntu" }))
      .toEqual({ id: "o2", address: "10.0.0.2", sources: ["netbird"], reach: "ready", alreadyAdded: true, rootAvailable: true, user: "kayg", os: "ubuntu" });
    expect(parseDiscovered({ id: "bad id", address: "x" })).toBeUndefined();
    expect(parseDiscovered({ id: "ok" })).toBeUndefined();
    expect(parseDiscovered("ok")).toBeUndefined();
  });
  test("the server key needs its public key and fingerprint", () => {
    expect(parseServerKey({ public_key: "ssh-ed25519 AAAA x", fingerprint: "SHA256:abc", locked: true })).toEqual({ publicKey: "ssh-ed25519 AAAA x", fingerprint: "SHA256:abc", locked: true });
    expect(parseServerKey({ public_key: "ssh-ed25519 AAAA x" })).toBeUndefined();
  });
  test("an install command needs a lifetime", () => {
    expect(parseInstallCommand({ command: "run", expires_in_seconds: 900 })).toEqual({ command: "run", expiresInSeconds: 900 });
    expect(parseInstallCommand({ command: "run" })).toBeUndefined();
  });
});

describe("a server that lacks an endpoint", () => {
  test("serving the web app (200, HTML) for an unknown path is 'not available'", async () => {
    answer(200, "<!doctype html><title>app</title>", "text/html");
    const service = createRealProvisioning();
    expect(await service.serverKey()).toBeUndefined();
    expect(await service.discover()).toEqual([]);
    expect(await service.installCommand("h")).toBeUndefined();
    await expect(service.mintCredential({ kind: "password", text: "x" })).rejects.toMatchObject({ kind: "unavailable" });
  });
  test("404 discovery is an empty list; 500 discovery is an error to show", async () => {
    answer(404, "{}");
    expect(await createRealProvisioning().discover()).toEqual([]);
    answer(500, "{}");
    await expect(createRealProvisioning().discover()).rejects.toBeInstanceOf(ServiceError);
  });
  test("a locked session says to unlock, never leaks the request", async () => {
    answer(401, "{}");
    const error = await createRealProvisioning().mintCredential({ kind: "password", text: "hunter2" }).catch((caught: unknown) => caught);
    expect((error as Error).message).toBe("Unlock with your passkey, then try again.");
    expect(String(error)).not.toContain("hunter2");
  });
  test("the secret goes only in the request body, never in the URL", async () => {
    let seen: { url: string; body: string } | undefined;
    globalThis.fetch = (async (url: string, init?: RequestInit) => { seen = { url: String(url), body: String(init?.body) }; return new Response(JSON.stringify({ reference: "ref-1" }), { headers: { "content-type": "application/json" } }); }) as unknown as typeof fetch;
    expect(await createRealProvisioning().mintCredential({ kind: "private-key", text: "KEYTEXT", passphrase: "PASS" })).toBe("ref-1");
    expect(seen!.url).toBe("/v1/bootstrap/credential");
    expect(JSON.parse(seen!.body)).toEqual({ kind: "private-key", secret: "KEYTEXT", passphrase: "PASS" });
  });
});
