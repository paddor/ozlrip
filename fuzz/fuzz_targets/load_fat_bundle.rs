#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut decoder = ozlrip::Decoder::new();
    let _ = decoder.load_dictionary_bundle(data);
});
