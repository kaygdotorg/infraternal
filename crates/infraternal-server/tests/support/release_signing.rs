//! Creates public SSHSIG fixtures using ephemeral Ed25519 keys held only in memory [224,226], #157.
use base64::{Engine, engine::general_purpose::STANDARD as B64};
use openssl::{pkey::PKey, sign::Signer};
fn field(message: &mut Vec<u8>, value: &[u8]) {
    message.extend_from_slice(&u32::try_from(value.len()).unwrap().to_be_bytes());
    message.extend_from_slice(value);
}
pub fn sign(manifest: &[u8]) -> (String, String) {
    let key = PKey::generate_ed25519().unwrap();
    let mut public = Vec::new();
    field(&mut public, b"ssh-ed25519");
    field(&mut public, &key.raw_public_key().unwrap());
    let namespace = b"infraternal-release";
    let hash = openssl::sha::sha512(manifest);
    let mut message = b"SSHSIG".to_vec();
    for value in [namespace.as_slice(), b"", b"sha512", &hash] {
        field(&mut message, value);
    }
    let mut signer = Signer::new_without_digest(&key).unwrap();
    let signature = signer.sign_oneshot_to_vec(&message).unwrap();
    let mut encoded_signature = Vec::new();
    field(&mut encoded_signature, b"ssh-ed25519");
    field(&mut encoded_signature, &signature);
    let mut envelope = b"SSHSIG".to_vec();
    envelope.extend_from_slice(&1u32.to_be_bytes());
    for value in [
        public.as_slice(),
        namespace,
        b"",
        b"sha512",
        &encoded_signature,
    ] {
        field(&mut envelope, value);
    }
    let encoded = B64.encode(envelope);
    let mut armor = String::from("-----BEGIN SSH SIGNATURE-----\n");
    for line in encoded.as_bytes().chunks(70) {
        armor.push_str(std::str::from_utf8(line).unwrap());
        armor.push('\n');
    }
    armor.push_str("-----END SSH SIGNATURE-----\n");
    let trust = format!(
        "release@infraternal.com namespaces=\"infraternal-release\" ssh-ed25519 {} fixture\n",
        B64.encode(public)
    );
    (armor, trust)
}
