#![no_main]

use libfuzzer_sys::fuzz_target;
use ozlrip::Limits;
use ozlrip_test_support::standard_transform_serial_frame;

const DELTA_INT_ID: u32 = 1;

// Format v13 and later keep the first value in the transform header, older
// versions first in the delta stream. The low bit of `data[0]` picks v12 or
// v21; the first value and the deltas follow.
fuzz_target!(|data: &[u8]| {
    let [control, first, deltas @ ..] = data else {
        return;
    };
    let decoded_len = deltas.len() + 1;
    let frame = if control & 1 == 0 {
        standard_transform_serial_frame(21, DELTA_INT_ID, deltas, decoded_len, &[*first])
    } else {
        let stored = [&[*first][..], deltas].concat();
        standard_transform_serial_frame(12, DELTA_INT_ID, &stored, decoded_len, &[])
    };
    let mut limits = Limits::strict();
    limits.max_frame_bytes = 8192;
    limits.max_decoded_bytes = 4096;
    limits.max_chunks = 1;
    limits.max_nodes = 1;
    limits.max_streams = 2;
    limits.max_transform_header_bytes = 1;
    limits.max_stored_stream_bytes = 8192;
    limits.max_buffer_bytes = 4096;
    limits.max_graph_depth = 1;
    limits.max_expansion_ratio = 4096;
    let mut output = Vec::new();
    let _ = ozlrip::decode_into_with_options(&frame, &mut output, ozlrip::Options::from(limits));
});
