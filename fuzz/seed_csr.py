"""Write the remote_csr_decode seeds: PKCS10 requests built from throwaway keys (#580, J1188 F1).

Run from anywhere: `python3 -I fuzz/seed_csr.py`. Seeds go to
`fuzz/corpus/remote_csr_decode/`. The keys are made by `openssl req` in a
private temporary folder that is deleted when the script ends, so no key
material reaches the repository.

Python only rearranges the DER that OpenSSL writes: it replaces the public
key or the signature, then signs the changed request again with
`openssl dgst`. Seeds:

- `ed25519-host`: the Ed25519 host shape that `ValidatedCsr::parse` admits.
- `p256-device`: a P-256 request that the device shape admits.
- `p256-high-s`: the same request with S above n/2. The device shape admits
  it, because a Secure Enclave does not normalise S.
- `p256-compressed-point`: a 33-byte point. The envelope refuses it.
- `p256-explicit-params`: the curve written out instead of named by OID. Refused.
- `p256-truncated`: `p256-device` cut short. Refused.

Each seed is checked with `openssl req -verify` before it is written, and the
high-S seed must have S above n/2, so it cannot silently turn into a low-S one.
"""
import subprocess
import tempfile
from pathlib import Path

root = Path(__file__).resolve().parent
out = root / 'corpus' / 'remote_csr_decode'
# P-256 group order n. Only used to check and rewrite the signature's S value.
P256_ORDER = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551


def run(args, cwd):
    """Run one command given as an argument list (never through a shell); return its stdout."""
    return subprocess.run(args, cwd=cwd, check=True, capture_output=True).stdout


def enc_len(n):
    """DER length octets for a body of `n` bytes."""
    if n < 128:
        return bytes([n])
    body = n.to_bytes((n.bit_length() + 7) // 8, 'big')
    return bytes([0x80 | len(body)]) + body


def tlv(tag, body):
    """One DER element: tag, definite length, body."""
    return bytes([tag]) + enc_len(len(body)) + body


def items(data):
    """Split concatenated DER elements into (tag, body) pairs.

    Accepts only the minimal DER that OpenSSL writes, so `tlv` on each pair
    gives back the original bytes. The re-encoding below depends on that.
    """
    result, i = [], 0
    while i < len(data):
        tag, first = data[i], data[i + 1]
        start, length = i + 2, first
        if first & 0x80:
            count = first & 0x7F
            length = int.from_bytes(data[i + 2:i + 2 + count], 'big')
            start = i + 2 + count
        result.append((tag, data[start:start + length]))
        i = start + length
    return result


def int_der(value):
    """A positive DER INTEGER, with the leading zero byte that keeps it positive."""
    body = value.to_bytes((value.bit_length() + 7) // 8, 'big')
    if body[0] & 0x80:
        body = b'\x00' + body
    return tlv(0x02, body)


def sign(cwd, key, data):
    """Sign `data` with the private key file `key` (ECDSA, SHA-256); return the DER signature."""
    (cwd / 'tbs.der').write_bytes(data)
    run(['openssl', 'dgst', '-sha256', '-sign', str(key), '-out', 'sig.der', 'tbs.der'], cwd)
    return (cwd / 'sig.der').read_bytes()


def assemble(info_items, sig_alg, signature):
    """CertificationRequest = SEQUENCE { info, sigAlg, BIT STRING signature }, from its parts."""
    info = tlv(0x30, b''.join(tlv(tag, body) for tag, body in info_items))
    return tlv(0x30, info + sig_alg + tlv(0x03, b'\x00' + signature))


def openssl_csr(cwd, name, key_args):
    """Create a DER CSR with a fresh unencrypted key; return (key path, CSR bytes)."""
    key = cwd / f'{name}.pem'
    csr = cwd / f'{name}.csr.der'
    run(['openssl', 'req', '-new', '-nodes', '-keyout', str(key), '-subj', f'/CN={name}',
         '-outform', 'DER', '-out', str(csr)] + key_args, cwd)
    return key, csr.read_bytes()


def split(der):
    """Break a CSR into its parts: info items [version, subject, SPKI, attributes], signature AlgorithmIdentifier TLV, and signature bytes.

    The SPKI item body is its algorithm identifier followed by the key BIT STRING.
    """
    top = items(der)[0][1]
    info, sig_alg, bits = items(top)
    info_items = items(info[1])
    sig_alg_tlv = tlv(sig_alg[0], sig_alg[1])
    return info_items, sig_alg_tlv, bits[1][1:]


def spki_body(algid_body, point_bits):
    """Body of SubjectPublicKeyInfo: the AlgorithmIdentifier, then the key BIT STRING holding `point_bits` (with its unused-bits byte)."""
    return tlv(0x30, algid_body) + tlv(0x03, b'\x00' + point_bits)


def high_s(der):
    """The same CSR with its signature's S replaced by n - S, when S is in the lower half.

    (r, n - S) is a second valid signature over the same bytes, so the CSR still verifies.
    """
    info_items, sig_alg_tlv, sig = split(der)
    r, s = [int.from_bytes(body, 'big') for _, body in items(items(sig)[0][1])]
    if s <= P256_ORDER // 2:
        s = P256_ORDER - s
    new_sig = tlv(0x30, int_der(r) + int_der(s))
    return assemble(info_items, sig_alg_tlv, new_sig)


def resign(cwd, key, der, algid_body, point_bits):
    """A new CSR for the same subject with its key replaced, signed again by `key`.

    The signature must be made with the private key that matches the point,
    otherwise `openssl req -verify` would refuse the seed for the wrong reason.
    """
    info_items, sig_alg_tlv, _ = split(der)
    info_items[2] = (0x30, spki_body(algid_body, point_bits))
    info_der = tlv(0x30, b''.join(tlv(tag, body) for tag, body in info_items))
    return assemble(info_items, sig_alg_tlv, sign(cwd, key, info_der))


def main():
    """Write the six seeds into the corpus folder, verifying each with OpenSSL first."""
    out.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='csr-seeds.') as scratch:
        cwd = Path(scratch)
        ed_key, ed = openssl_csr(cwd, 'ed25519-host', ['-newkey', 'ed25519'])
        p_key, device = openssl_csr(cwd, 'p256-device',
                                    ['-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1', '-sha256'])

        # The SPKI's AlgorithmIdentifier holds two OIDs (id-ecPublicKey, prime256v1), which the
        # variants below reuse or replace; the point is the uncompressed 0x04 || X || Y form.
        info_items, _, _ = split(device)
        spki = items(info_items[2][1])
        algid_items = items(spki[0][1])
        oid_ec = tlv(0x06, algid_items[0][1])
        oid_curve = tlv(0x06, algid_items[1][1])
        point = spki[1][1][1:]
        assert point[0] == 0x04 and len(point) == 65, 'expected an uncompressed P-256 point'
        compressed = bytes([0x02 | (point[-1] & 1)]) + point[1:33]
        explicit_params = run(['openssl', 'ecparam', '-name', 'prime256v1', '-param_enc', 'explicit',
                               '-outform', 'DER'], cwd)

        seeds = {
            'ed25519-host': ed,
            'p256-device': device,
            'p256-high-s': high_s(device),
            'p256-compressed-point': resign(cwd, p_key, device, oid_ec + oid_curve, compressed),
            'p256-explicit-params': resign(cwd, p_key, device, oid_ec + explicit_params, point),
            'p256-truncated': device[:len(device) - 17],
        }

        for name, data in seeds.items():
            path = cwd / f'{name}.der'
            path.write_bytes(data)
            result = subprocess.run(['openssl', 'req', '-inform', 'DER', '-in', str(path), '-verify', '-noout'],
                                    cwd=cwd, capture_output=True, text=True)
            verified = 'verify OK' in result.stdout + result.stderr
            if name == 'p256-truncated':
                assert not verified, 'a truncated request must not parse'
            else:
                assert verified, f'{name} does not verify with OpenSSL'
            (out / name).write_bytes(data)

        _, _, sig = split(seeds['p256-high-s'])
        s = int.from_bytes(items(items(sig)[0][1])[1][1], 'big')
        assert s > P256_ORDER // 2, 'p256-high-s seed must have S above n/2'
        print(f'wrote {len(seeds)} seeds to {out}')


if __name__ == '__main__':
    main()
