# Host identity key rotation

This contract rotates an enrolled host's Ed25519 identity key over its already
authenticated control stream. It does not enroll a host, change its privilege,
or grant authority to a candidate key before the candidate proves possession
through a new mutual TLS connection.

## Capability and schedule

Hosts advertise `LIVE_IDENTITY_ROTATION` only when they can durably retain a
candidate key and certificate alongside the current identity. Servers rotate an
online host only when that capability is present and the configured CA is
unlocked. The server owns a seven-day interval and sequence; hosts do not send
schedule timestamps. A locked CA, offline host, unsupported host, or failed
control stream defers the operation without changing active identity.

## Exchange

The server persists one challenge per host before sending
`transport.csr.rotate`:

```json
{
  "host_id": "uuid",
  "operation_id": "uuid",
  "sequence": 1,
  "challenge": [32 random bytes],
  "predecessor_fingerprint": [32 bytes],
  "issuer_fingerprint": [32 bytes],
  "issuer_generation": 1
}
```

The host generates an Ed25519 candidate key and fsyncs it with the pending
operation before replying. `transport.csr.rotate` returns
`{"operation_id":"uuid","sequence":1,"csr_der":[...],"old_signature":[...]}`.
The CSR proves possession of the candidate key. The predecessor identity signs
the domain-separated transcript containing the host ID, predecessor
certificate fingerprint, operation ID, sequence, server nonce, issuer
fingerprint and generation, and the SHA-256 digest of the exact CSR DER. The
server checks all fields against its persisted challenge and the live,
unrevoked predecessor before
signing a seven-day certificate for the candidate public key.

The server atomically persists the candidate certificate and fingerprint with
the operation before sending `transport.identity.rotate.certificate`:

```json
{"operation_id":"uuid","sequence":1,"certificate_der":[...]}
```

The host verifies the issuer, host identity, validity, operation, and candidate
public key, then fsyncs the certificate beside the old key and certificate.
It selects the candidate for the next connection and retires the predecessor
control stream after the certificate response has been written. A transport
receipt alone does not promote the candidate.

When a new mutual TLS connection proves possession of the candidate key, the
server transactionally advances the identity sequence, revokes every
certificate for the predecessor public key, and records completion. It then
sends `transport.identity.rotate.ack` with the operation ID and sequence over
that candidate-authenticated control stream. The host fsyncs promotion and removes the
predecessor private key only after this acknowledgment. Repeated requests,
candidate admission, and acknowledgment are idempotent across a lost response
or either process restarting.

## Safety and compatibility

At most one operation is pending per host. A new challenge cannot replace an
in-flight operation; a repeated operation ID with different CSR bytes is
refused. The old certificate remains admitted through candidate issuance and
until candidate mutual TLS admission. No elapsed-time timeout retires either
identity. The server uses its database clock and persisted sequence. Normal
half-life certificate renewal continues for the active identity during
overlap. Legacy hosts continue ordinary certificate renewal and never receive
identity-rotation actions.

Private keys remain only in the host's mode-0600 `identity.json`. The server
stores public challenge, proof digest, candidate certificate, and phase only.
Control payloads and diagnostics never contain private keys, full certificates
outside the bounded authenticated exchange, or raw OpenSSL errors.
