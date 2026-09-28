#![no_main]

use libfuzzer_sys::fuzz_target;
use ozlrip::Limits;
use ozlrip_test_support::{MAGIC_BASE, push_var_u64};

fuzz_target!(|data: &[u8]| {
    let frame = concat_serial_frame(data);
    let mut limits = Limits::strict();
    limits.max_frame_bytes = 8192;
    limits.max_decoded_bytes = 4096;
    limits.max_chunks = 1;
    limits.max_nodes = 1;
    limits.max_streams = 4;
    limits.max_transform_header_bytes = 0;
    limits.max_stored_stream_bytes = 8192;
    limits.max_buffer_bytes = 4096;
    limits.max_graph_depth = 1;
    limits.max_expansion_ratio = 4096;
    let mut output = Vec::new();
    let _ = ozlrip::decode_into_with_options(&frame, &mut output, ozlrip::Options::from(limits));
});

fn concat_serial_frame(payload: &[u8]) -> Vec<u8> {
    let size = u32::try_from(payload.len()).unwrap_or(u32::MAX);
    let mut input = Vec::new();
    input.extend_from_slice(&(MAGIC_BASE + 21).to_le_bytes());
    input.push(0);
    input.push(1);
    push_var_u64(&mut input, u64::try_from(payload.len() + 1).unwrap());
    input.push(2);
    input.push(2);
    input.push(0);
    input.push(55);
    input.push(0);
    input.push(0);
    input.push(0);
    input.push(0);
    input.push(4);
    push_var_u64(&mut input, u64::try_from(payload.len()).unwrap());
    input.extend_from_slice(&size.to_le_bytes());
    input.extend_from_slice(payload);
    input.push(0);
    input
}
