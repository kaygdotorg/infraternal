/// Supplies Rust with a Simulator P-256 key or a Secure Enclave signer (#580).

import CryptoKit
import Foundation

/// A Swift-owned identity key that UniFFI calls for the Rust CSR and QUIC TLS.
final class DeviceIdentity: DeviceSigner {
#if targetEnvironment(simulator)
    /// The Simulator's test-only software identity key.
    private let key = P256.Signing.PrivateKey()
#else
    /// The device identity private key, which CryptoKit keeps in secure hardware.
    private let key: SecureEnclave.P256.Signing.PrivateKey
#endif

    /// Makes the software key only in Simulator, and requests Secure Enclave on a device.
    init() throws {
#if !targetEnvironment(simulator)
        key = try SecureEnclave.P256.Signing.PrivateKey()
#endif
    }

    /// Returns the exact SubjectPublicKeyInfo encoding the Rust CSR builder accepts.
    func publicKeySpki() -> Data {
        let prefix = Data([
            0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02,
            0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03,
            0x42, 0x00,
        ])
        return prefix + key.publicKey.x963Representation
    }

    /// Returns a DER ECDSA P-256 signature over SHA-256(message).
    func sign(message: Data) throws -> Data {
        try key.signature(for: message).derRepresentation
    }
}
