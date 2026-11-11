// SPDX-License-Identifier: AGPL-3.0-only (test-only; copy of the ops tool, shipped only to the Mac VM driver)
// Test-only software WebAuthn authenticator, injected into the page with addInitScript (never shipped).
// Durable replacement for Chrome's virtual authenticator, whose PRF secret cannot be exported.
// Implements "none" attestation, ES256 assertions and the WebAuthn PRF extension. The PRF output is
// HMAC-SHA-256(per-credential secret, SHA-256("WebAuthn PRF\0" || input)), the construction browsers use
// on top of CTAP hmac-secret. State lives on the Node side (window.__swLoad / window.__swSave).
(() => {
  const ORIGIN = "__SW_ORIGIN__";
  if (location.origin !== ORIGIN || !navigator.credentials) return;
  const enc = new TextEncoder();
  const b64u = (buf) => {
    const b = new Uint8Array(buf instanceof ArrayBuffer ? buf : buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength));
    let s = ""; for (const x of b) s += String.fromCharCode(x);
    return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  };
  const unb64u = (s) => Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/")), (c) => c.charCodeAt(0));
  const bytes = (v) => v instanceof ArrayBuffer ? new Uint8Array(v) : new Uint8Array(v.buffer, v.byteOffset, v.byteLength);
  const cat = (...parts) => { const n = parts.reduce((a, p) => a + p.length, 0); const o = new Uint8Array(n); let i = 0; for (const p of parts) { o.set(p, i); i += p.length; } return o; };
  const sha256 = async (d) => new Uint8Array(await crypto.subtle.digest("SHA-256", d));
  const u32 = (n) => new Uint8Array([(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255]);

  // Minimal CBOR: unsigned/negative ints, byte/text strings, maps.
  const head = (major, n) => n < 24 ? [major << 5 | n] : n < 256 ? [major << 5 | 24, n] : [major << 5 | 25, n >> 8, n & 255];
  const cInt = (n) => new Uint8Array(n >= 0 ? head(0, n) : head(1, -1 - n));
  const cBytes = (b) => cat(new Uint8Array(head(2, b.length)), b);
  const cText = (s) => { const t = enc.encode(s); return cat(new Uint8Array(head(3, t.length)), t); };
  const cMap = (pairs) => cat(new Uint8Array(head(5, pairs.length)), ...pairs.flat());

  const derFromRaw = (raw) => {
    const int = (x) => { let i = 0; while (i < x.length - 1 && x[i] === 0) i++; x = x.slice(i); if (x[0] & 128) x = cat(new Uint8Array([0]), x); return cat(new Uint8Array([2, x.length]), x); };
    const body = cat(int(raw.slice(0, 32)), int(raw.slice(32)));
    return cat(new Uint8Array([48, body.length]), body);
  };

  const rpIdOf = (pk, rpId) => rpId || location.hostname;
  const clientData = (type, challenge) => enc.encode(JSON.stringify({ type, challenge: b64u(challenge), origin: location.origin, crossOrigin: false }));
  const ab = (u8) => u8.buffer.slice(u8.byteOffset, u8.byteOffset + u8.byteLength);

  // Real PublicKeyCredential/response instances cannot be constructed; borrow the prototypes so the app's
  // `instanceof` checks pass and shadow every brand-checked accessor with own data properties.
  const makeResponse = (proto, props) => { const o = Object.create(proto); for (const [k, v] of Object.entries(props)) Object.defineProperty(o, k, { value: v, enumerable: true }); return o; };
  const makeCredential = (id, response, extensionResults) => {
    const o = Object.create(PublicKeyCredential.prototype);
    const props = { id: b64u(id), rawId: ab(id), type: "public-key", authenticatorAttachment: "platform", response, getClientExtensionResults: () => extensionResults };
    for (const [k, v] of Object.entries(props)) Object.defineProperty(o, k, { value: v, enumerable: true });
    return o;
  };

  const prfOutput = async (secret, input) => {
    const salt = await sha256(cat(enc.encode("WebAuthn PRF\0"), bytes(input)));
    const key = await crypto.subtle.importKey("raw", secret, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
    return ab(new Uint8Array(await crypto.subtle.sign("HMAC", key, salt)));
  };

  const create = async (options) => {
    const pk = options && options.publicKey;
    if (!pk) throw new DOMException("not supported", "NotSupportedError");
    if (pk.pubKeyCredParams && !pk.pubKeyCredParams.some((p) => p.alg === -7)) throw new DOMException("no ES256", "NotSupportedError");
    const rpId = rpIdOf(pk, pk.rp && pk.rp.id);
    const pair = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
    const jwk = await crypto.subtle.exportKey("jwk", pair.publicKey);
    const pkcs8 = new Uint8Array(await crypto.subtle.exportKey("pkcs8", pair.privateKey));
    const id = crypto.getRandomValues(new Uint8Array(32));
    const prfSecret = crypto.getRandomValues(new Uint8Array(32));
    const userHandle = bytes(pk.user.id).slice();
    const cose = cMap([[cInt(1), cInt(2)], [cInt(3), cInt(-7)], [cInt(-1), cInt(1)], [cInt(-2), cBytes(unb64u(jwk.x))], [cInt(-3), cBytes(unb64u(jwk.y))]]);
    // flags: UP | UV | AT. Counter starts at 0; later assertions persist and increase it.
    const authData = cat(await sha256(enc.encode(rpId)), new Uint8Array([0x45]), u32(0), new Uint8Array(16), new Uint8Array([id.length >> 8, id.length & 255]), id, cose);
    const attestationObject = cMap([[cText("fmt"), cText("none")], [cText("attStmt"), cMap([])], [cText("authData"), cBytes(authData)]]);
    await window.__swSave({ rpOrigin: ORIGIN, rpId, credentialId: b64u(id), userHandle: b64u(userHandle), privateKeyPkcs8: b64u(pkcs8), publicKeyJwk: jwk, prfSecret: b64u(prfSecret), signCount: 0 });
    const ext = { credProps: { rk: true } };
    if (pk.extensions && pk.extensions.prf) ext.prf = { enabled: true };
    const response = makeResponse(AuthenticatorAttestationResponse.prototype, {
      clientDataJSON: ab(clientData("webauthn.create", bytes(pk.challenge))),
      attestationObject: ab(attestationObject),
      getTransports: () => ["internal"],
      getAuthenticatorData: () => ab(authData),
      getPublicKeyAlgorithm: () => -7,
    });
    return makeCredential(id, response, ext);
  };

  const get = async (options) => {
    const pk = options && options.publicKey;
    if (!pk) throw new DOMException("not supported", "NotSupportedError");
    const st = await window.__swLoad();
    if (!st) throw new DOMException("no credential", "NotAllowedError");
    const allowed = pk.allowCredentials || [];
    if (allowed.length && !allowed.some((c) => b64u(c.id) === st.credentialId)) throw new DOMException("no matching credential", "NotAllowedError");
    const rpId = rpIdOf(pk, pk.rpId);
    if (rpId !== st.rpId) throw new DOMException("rp mismatch", "SecurityError");
    const counter = (st.signCount || 0) + 1;
    await window.__swSave({ ...st, signCount: counter });
    const authData = cat(await sha256(enc.encode(rpId)), new Uint8Array([0x05]), u32(counter));
    const cd = clientData("webauthn.get", bytes(pk.challenge));
    const priv = await crypto.subtle.importKey("pkcs8", unb64u(st.privateKeyPkcs8), { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"]);
    const raw = new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, priv, cat(authData, await sha256(cd))));
    const ext = {};
    const prf = pk.extensions && pk.extensions.prf;
    if (prf) {
      const secret = unb64u(st.prfSecret);
      const evalIn = (prf.evalByCredential && prf.evalByCredential[st.credentialId]) || prf.eval;
      if (evalIn && evalIn.first) {
        const results = { first: await prfOutput(secret, evalIn.first) };
        if (evalIn.second) results.second = await prfOutput(secret, evalIn.second);
        ext.prf = { results };
      } else ext.prf = {};
    }
    const response = makeResponse(AuthenticatorAssertionResponse.prototype, {
      clientDataJSON: ab(cd), authenticatorData: ab(authData), signature: ab(derFromRaw(raw)), userHandle: ab(unb64u(st.userHandle)),
    });
    return makeCredential(unb64u(st.credentialId), response, ext);
  };

  Object.defineProperty(navigator.credentials, "create", { value: create, configurable: true, writable: true });
  Object.defineProperty(navigator.credentials, "get", { value: get, configurable: true, writable: true });
})();
