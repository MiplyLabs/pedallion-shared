//! Generate an Ed25519 keypair for the licensing server.
//!
//! `cargo run -p pedallion-shared --example keygen`
//!
//! Prints the secret key (store it as the server's signing secret, never commit it) and the
//! public key (bake it into client builds via `PEDALLION_LICENSE_PUBKEY`).

use ed25519_dalek::SigningKey;
use pedallion_shared::verifying_key_to_base64;

fn main() {
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).expect("OS random source");
    let key = SigningKey::from_bytes(&seed);
    use base64::Engine;
    let secret = base64::engine::general_purpose::STANDARD.encode(seed);
    println!("secret (server only): {secret}");
    println!(
        "public (client build): {}",
        verifying_key_to_base64(&key.verifying_key())
    );
}
