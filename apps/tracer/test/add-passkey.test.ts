/** Second-passkey enrollment preserves the existing DEK and never uploads PRF output (#224). */
import { expect, test } from "bun:test";
import { addSecondPasskey, recoveryAuth as auth, type Wrap } from "../src/auth";

const user = "00000000-0000-0000-0000-000000000001";
const other = "00000000-0000-0000-0000-000000000002";

for (const mode of ["success", "wrong-login", "changed-account", "cancel", "no-prf", "finish-failed"] as const) {
  test(`adding a second passkey: ${mode}`, async () => {
    const saved = new Map<string, PropertyDescriptor | undefined>();
    const replace = (name: string, value: unknown): void => {
      saved.set(name, Object.getOwnPropertyDescriptor(globalThis, name));
      Object.defineProperty(globalThis, name, { configurable: true, writable: true, value });
    };
    const originalFetch = globalThis.fetch;
    const oldPrf = new Uint8Array(32).fill(7), newPrf = new Uint8Array(32).fill(8);
    const dek = new Uint8Array(32).fill(9), input = new Uint8Array(32).fill(6);
    const oldWrap = await auth.wrapDek(oldPrf, dek, user, "passkey");
    const requests: Array<{ action: string; body: Record<string, unknown> }> = [];
    class Assertion {
      clientDataJSON = new Uint8Array([1]); authenticatorData = new Uint8Array([2]); signature = new Uint8Array([3]); userHandle = null;
    }
    class Attestation {
      clientDataJSON = new Uint8Array([1]); attestationObject = new Uint8Array([2]); getTransports() { return ["internal"]; }
    }
    class Credential {
      id = "AQ"; rawId = new Uint8Array([1]); type = "public-key";
      constructor(readonly response: Assertion | Attestation, readonly prf: Uint8Array) {}
      getClientExtensionResults() { return { prf: { enabled: mode !== "no-prf", results: { first: this.prf } } }; }
    }
    replace("PublicKeyCredential", Credential);
    replace("AuthenticatorAssertionResponse", Assertion);
    replace("AuthenticatorAttestationResponse", Attestation);
    replace("navigator", { credentials: {
      get: async () => new Credential(new Assertion(), oldPrf),
      create: async () => mode === "cancel" ? null : new Credential(new Attestation(), newPrf),
    } });
    globalThis.fetch = (async (path: string | URL | Request, init?: RequestInit) => {
      const action = String(path).split("/").pop()!;
      requests.push({ action, body: JSON.parse(String(init?.body)) as Record<string, unknown> });
      const options = { challenge: "AQ", rpId: "localhost", extensions: { prf: { eval: { first: auth.base64url(input) } } } };
      let result: unknown;
      switch (action) {
        case "login-start": result = { ceremony: "login", options: { publicKey: options } }; break;
        case "login-finish": result = { pending_transaction: "pending" }; break;
        case "unlock-session": result = { user_id: mode === "wrong-login" ? other : user }; break;
        case "wraps": result = [{ kind: "passkey", key_id: "AQ", wrap: oldWrap, prf_input: auth.base64url(input) }]; break;
        case "add-start": result = { ceremony: "add", user_id: mode === "changed-account" ? other : user, options: { publicKey: { ...options, rp: { id: "localhost" }, user: { id: "AQ", name: "person", displayName: "Person" } } } }; break;
        default: result = { ok: true };
      }
      return new Response(JSON.stringify(result), { status: mode === "finish-failed" && action === "registration-finish" ? 503 : 200 });
    }) as unknown as typeof fetch;
    try {
      if (mode === "success") {
        await addSecondPasskey(user);
        const finish = requests.find((request) => request.action === "registration-finish")!;
        expect(Object.keys(finish.body).sort()).toEqual(["ceremony", "passkey_wrap", "proof"]);
        expect(JSON.stringify(finish.body.proof)).not.toContain('"prf"');
        const unwrapped = await auth.unwrapDek(newPrf, finish.body.passkey_wrap as Wrap, user, "passkey");
        expect([...unwrapped]).toEqual([...dek]);
        unwrapped.fill(0);
      } else {
        await expect(addSecondPasskey(user)).rejects.toThrow();
        if (mode !== "finish-failed") expect(requests.some((request) => request.action === "registration-finish")).toBe(false);
        // Enrollment failure after unlock does not attempt pending-login cleanup on an active cookie.
        if (mode !== "wrong-login") expect(requests.some((request) => request.action === "logout")).toBe(false);
      }
      expect(requests.some((request) => request.action.startsWith("recovery-"))).toBe(false);
      expect([...oldPrf]).toEqual(Array(32).fill(7));
      expect([...newPrf]).toEqual(Array(32).fill(8));
    } finally {
      globalThis.fetch = originalFetch;
      for (const [name, descriptor] of saved) {
        if (descriptor) Object.defineProperty(globalThis, name, descriptor);
        else Reflect.deleteProperty(globalThis, name);
      }
      dek.fill(0); oldPrf.fill(0); newPrf.fill(0); input.fill(0);
    }
  });
}
