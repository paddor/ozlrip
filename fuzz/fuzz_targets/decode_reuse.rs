#![no_main]

//! A reused `Decoder` must give the same result (bytes or error kind) as a
//! fresh one, including after decoding an unrelated frame. This covers the
//! scratch buffer pool, dictionary store, and zstd context state.

use libfuzzer_sys::fuzz_target;
use ozlrip::{ErrorKind, Limits, Options};

fn outcome(result: ozlrip::Result<Vec<u8>>) -> Result<Vec<u8>, ErrorKind> {
    result.map_err(|err| err.kind())
}

fuzz_target!(|data: &[u8]| {
    let mut limits = Limits::strict();
    limits.max_frame_bytes = 1 << 16;
    limits.max_decoded_bytes = 1 << 20;
    limits.max_buffer_bytes = 1 << 20;
    limits.max_stored_stream_bytes = 1 << 16;
    let options = Options::from(limits);

    let fresh = outcome(ozlrip::decode_with_options(data, options));
    let mut decoder = ozlrip::Decoder::with_options(options);
    let first = outcome(decoder.decode(data));
    let _ = decoder.decode(&data[..data.len() / 2]);
    let second = outcome(decoder.decode(data));

    assert_eq!(first, fresh);
    assert_eq!(second, fresh);
});
