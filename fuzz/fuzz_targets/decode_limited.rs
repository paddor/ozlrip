#![no_main]

use libfuzzer_sys::fuzz_target;
use ozlrip::Limits;

fuzz_target!(|data: &[u8]| {
    let mut limits = Limits::strict();
    limits.max_frame_bytes = 4096;
    limits.max_decoded_bytes = 4096;
    limits.max_chunks = 16;
    limits.max_nodes = 256;
    limits.max_streams = 256;
    limits.max_transform_header_bytes = 4096;
    limits.max_stored_stream_bytes = 4096;
    limits.max_buffer_bytes = 4096;
    limits.max_graph_depth = 64;
    limits.max_expansion_ratio = 64;
    let mut output = Vec::new();
    let _ = ozlrip::decode_into_with_options(data, &mut output, ozlrip::Options::from(limits));
});
