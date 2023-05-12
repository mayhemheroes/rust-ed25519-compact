#![no_main]
use ed25519_compact::{KeyPair, Seed, Noise};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: &[u8]| {
    let key_pair = KeyPair::from_seed(Seed::default());
    let signature = key_pair.sk.sign(input, Some(Noise::default()));
    key_pair.pk.verify(input, &signature).expect("Signature didn't verify");
});
