/** Real-browser regression tests for third-party WebAuthn binary output shapes. */
import { expect, test } from "playwright/test";
import { execFileSync } from "node:child_process";
let source: string;
test.beforeAll(() => {
  source = execFileSync("bun", ["-e", `
    const build = await Bun.build({ entrypoints: ["src/auth.ts"], target: "browser", plugins: [{ name: "test-exports", setup(build) {
      build.onLoad({ filter: /auth\\.ts$/ }, async (args) => ({ contents: (await Bun.file(process.env.AUTH_BINARY_SOURCE ?? args.path).text()) + "\\nexport { prfFrom, credentialProof, copyBytes };", loader: "ts" }));
    } }] });
    if (!build.success) throw new Error("test bundle failed");
    process.stdout.write(await build.outputs[0].text());
  `], { encoding: "utf8" });
});
for (const shape of ["buffer", "view", "data-view", "wide-view", "array", "realm", "realm-view", "invalid"]) {
  test(`auth binary boundary: ${shape}`, async ({ page }) => {
    await page.route("**/auth-boundary.js", route => route.fulfill({ body: source, contentType: "text/javascript" }));
    await page.goto("/health");
    const result = await page.evaluate(async (shape) => {
      const auth = await import(/* @vite-ignore */ String("/auth-boundary.js"));
      const frame = document.createElement("iframe"); document.body.append(frame);
      const other = frame.contentWindow as Window & typeof globalThis;
      const logs: unknown[][] = []; console.warn = (...args: unknown[]) => { logs.push(args); };
      function bytes(length: number): unknown {
        const array = Array.from({ length }, (_, i) => i % 256);
        if (shape === "array") return array;
        if (shape === "realm") { const b = new other.ArrayBuffer(length); new other.Uint8Array(b).set(array); return b; }
        if (shape === "realm-view") { const b = new other.ArrayBuffer(length + 4); new other.Uint8Array(b).set(array, 2); return new other.DataView(b, 2, length); }
        if (shape === "buffer") return Uint8Array.from(array).buffer;
        const backing = new Uint8Array(length + 4); backing.set(array, 2);
        if (shape === "wide-view" && length % 2 === 0) return new Uint16Array(backing.buffer, 2, length / 2);
        return shape === "view" ? backing.subarray(2, length + 2) : new DataView(backing.buffer, 2, length);
      }
      const proofs = [];
      for (const registration of [true, false]) {
        const response = Object.create(registration ? AuthenticatorAttestationResponse.prototype : AuthenticatorAssertionResponse.prototype);
        const fields = { clientDataJSON: bytes(3), ...(registration ? { attestationObject: bytes(3), getTransports: () => ["internal"] } : { authenticatorData: bytes(3), signature: bytes(3), userHandle: bytes(3) }) };
        Object.defineProperties(response, Object.fromEntries(Object.entries(fields).map(([key, value]) => [key, { value }])));
        const credential = { id: "AAEC", rawId: bytes(3), type: "public-key", response, getClientExtensionResults: () => ({ prf: { enabled: true, results: { first: bytes(32), second: bytes(32) } } }) };
        const prf = auth.prfFrom(credential);
        proofs.push({ length: prf.length, prf: Array.from(prf), proof: auth.credentialProof(credential) });
      }
      const errors = [];
      if (shape === "invalid") {
        try { auth.prfFrom({ getClientExtensionResults: () => ({ prf: { results: { first: bytes(32), second: [256] } } }) }); errors.push(null); }
        catch (error) { errors.push((error as Error).message); }
      }
      if (shape === "invalid") for (const input of [[-1], [256], [1.5], ["secret"], new Array(32), {}, { [Symbol.toStringTag]: "ArrayBuffer" }, { get [Symbol.toStringTag]() { throw new Error("secret"); } }, "secret", null, new Uint8Array(31), new Uint8Array(33)]) {
        try { auth.prfFrom({ getClientExtensionResults: () => ({ prf: { results: { first: input } } }) }); errors.push(null); }
        catch (error) { errors.push((error as Error).message); }
      }
      const invalidProofs: string[] = [];
      if (shape === "invalid") for (const field of ["rawId", "clientDataJSON", "attestationObject", "authenticatorData", "signature", "userHandle"]) {
        const registration = field === "attestationObject";
        const response = Object.create(registration ? AuthenticatorAttestationResponse.prototype : AuthenticatorAssertionResponse.prototype);
        const fields = { clientDataJSON: bytes(3), ...(registration ? { attestationObject: bytes(3), getTransports: () => [] } : { authenticatorData: bytes(3), signature: bytes(3), userHandle: null }) };
        Object.defineProperties(response, Object.fromEntries(Object.entries({ ...fields, ...(field === "rawId" ? {} : { [field]: "secret" }) }).map(([key, value]) => [key, { value }])));
        try { auth.credentialProof({ id: "AAEC", rawId: field === "rawId" ? "secret" : bytes(3), type: "public-key", response, getClientExtensionResults: () => ({}) }); }
        catch (error) { invalidProofs.push((error as Error).message); }
      }
      const input = new Uint8Array(32); input.fill(7);
      const copied = auth.copyBytes(input, "prf.first"); copied.fill(0);
      const independent = input.every(byte => byte === 7);
      frame.remove(); return { proofs, errors, logs, invalidProofs, independent };
    }, shape);
    for (const { length, prf, proof } of result.proofs) {
      expect(length).toBe(32); expect(prf).toEqual(Array.from({ length: 32 }, (_, i) => i)); expect(proof.rawId).toBe("AAEC");
      for (const [key, value] of Object.entries(proof.response)) if (key !== "transports") expect(value).toBe("AAEC");
      expect(proof.extensions).toEqual({});
    }
    expect(result.independent).toBe(true);
    if (shape === "invalid") {
      expect(result.invalidProofs).toHaveLength(6);
      expect(result.errors.every(message => message === "Your passkey could not unlock your account key. Try again.")).toBe(true);
      expect(result.logs).toHaveLength(19); expect(JSON.stringify(result.logs)).not.toContain("secret");
    }
  });
}


test("binary normalization cost at 50 concurrent login equivalents", async ({ page }) => {
  await page.route("**/auth-boundary.js", route => route.fulfill({ body: source, contentType: "text/javascript" }));
  await page.goto("/health");
  const timing = await page.evaluate(async () => {
    const auth = await import(String("/auth-boundary.js"));
    const inputs = Array.from({ length: 50 }, () => new Uint8Array(32).buffer);
    const run = (copy: (input: ArrayBuffer) => Uint8Array) => {
      const start = performance.now();
      for (let repeat = 0; repeat < 2000; repeat++) for (const input of inputs) copy(input).fill(0);
      return (performance.now() - start) / 100000;
    };
    const old = (input: ArrayBuffer) => { const result = new Uint8Array(input.byteLength); result.set(new Uint8Array(input)); return result; };
    run(old); run(input => auth.copyBytes(input, "prf.first"));
    return { old_us: run(old) * 1000, normalized_us: run(input => auth.copyBytes(input, "prf.first")) * 1000, count: 100000 };
  });
  console.log(`AUTH_BINARY_TIMING ${JSON.stringify(timing)}`);
  expect(timing.normalized_us).toBeLessThan(1000);
});
