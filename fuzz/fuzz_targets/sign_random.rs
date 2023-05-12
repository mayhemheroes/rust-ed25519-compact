#![no_main]
use std::convert::TryInto;

use ed25519_compact::{KeyPair, Seed, Noise};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: (&[u8], &[u8], &[u8])| {
    if input.0.len() >= 32 && input.1.len() >= 16 && !input.0[..32].into_iter().all(|x| *x == 0) {
        let seed_data: &[u8; 32] = input.0[..32].try_into().unwrap();
        let noise_data: &[u8; 16] = input.1[..16].try_into().unwrap();
        let key_pair = KeyPair::from_seed(Seed::new(*seed_data));
        let signature = key_pair.sk.sign(input.2, Some(Noise::new(*noise_data)));
        key_pair.pk.verify(input.2, &signature).expect("Signature didn't verify");
    }
});
