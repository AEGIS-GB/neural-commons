// X25519 Diffie-Hellman key exchange — wraps x25519-dalek
// Used for: mesh encryption, encrypted backup

pub use x25519_dalek::{EphemeralSecret, PublicKey, SharedSecret};

/// Generate a new ephemeral X25519 keypair
pub fn generate_ephemeral() -> (EphemeralSecret, PublicKey) {
    let secret = EphemeralSecret::random_from_rng(rand::rngs::OsRng);
    let public = PublicKey::from(&secret);
    (secret, public)
}
