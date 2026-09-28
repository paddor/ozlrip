#![no_main]

use libfuzzer_sys::fuzz_target;
use ozlrip::Limits;
use ozlrip_test_support::standard_transform_serial_frame;

const FSE_NCOUNT_ID: u32 = 52;

fuzz_target!(|data: &[u8]| {
    let decoded_len = data.get(..2).map_or(0, |bytes| {
        usize::from(u16::from_le_bytes([bytes[0], bytes[1]]) & 0x01ff)
    }) & !1;
    let stored = data.get(2..).unwrap_or_default();
    let frame = standard_transform_serial_frame(21, FSE_NCOUNT_ID, stored, decoded_len, &[]);
    let mut limits = Limits::strict();
    limits.max_frame_bytes = 8192;
    limits.max_decoded_bytes = 4096;
    limits.max_chunks = 1;
    limits.max_nodes = 1;
    limits.max_streams = 2;
    limits.max_transform_header_bytes = 0;
    limits.max_stored_stream_bytes = 8192;
    limits.max_buffer_bytes = 4096;
    limits.max_graph_depth = 1;
    limits.max_expansion_ratio = 4096;
    let mut output = Vec::new();
    let _ = ozlrip::decode_into_with_options(&frame, &mut output, ozlrip::Options::from(limits));
});
