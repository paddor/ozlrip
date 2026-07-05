#![no_main]

use libfuzzer_sys::fuzz_target;
use ozlrip::Limits;

fuzz_target!(|data: &[u8]| {
    let limits = Limits {
        max_frame_bytes: 4096,
        max_decoded_bytes: 4096,
        max_chunks: 16,
        max_nodes: 256,
        max_streams: 256,
        max_transform_header_bytes: 4096,
        max_stored_stream_bytes: 4096,
        max_buffer_bytes: 4096,
        max_graph_depth: 64,
        max_expansion_ratio: 64,
    };
    let mut output = Vec::new();
    let _ = ozlrip::decode_into_with_options(
        data,
        &mut output,
        ozlrip::Options {
            limits,
            ..ozlrip::Options::default()
        },
    );
});
