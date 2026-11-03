#![no_main]

use libfuzzer_sys::fuzz_target;

// Decoding chunk by chunk accepts exactly the frames `decode` accepts, and
// the chunks put together are its output.
fuzz_target!(|data: &[u8]| {
    let whole = ozlrip::decode(data);
    let mut chunks = Vec::new();
    let streamed = ozlrip::Decoder::new().decode_chunks(data, |chunk| {
        chunks.extend_from_slice(chunk);
        Ok(())
    });
    match (whole, streamed) {
        (Ok(whole), Ok(written)) => {
            assert_eq!(written, whole.len());
            assert_eq!(chunks, whole);
        }
        (Err(_), Err(_)) => {}
        (whole, streamed) => panic!("decode {whole:?}, decode_chunks {streamed:?}"),
    }
});
