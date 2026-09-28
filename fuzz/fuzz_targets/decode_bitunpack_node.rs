#![no_main]

use libfuzzer_sys::fuzz_target;
use ozlrip::Limits;
use ozlrip_test_support::{MAGIC_BASE, push_var_u64};

fuzz_target!(|data: &[u8]| {
    if data.len() < 2 {
        return;
    }
    let bits = (data[0] % 8) + 1;
    let frame = bitunpack_serial_frame(bits, data[1], &data[2..]);
    let mut limits = Limits::strict();
    limits.max_frame_bytes = 8192;
    limits.max_decoded_bytes = 4096;
    limits.max_chunks = 1;
    limits.max_nodes = 1;
    limits.max_streams = 2;
    limits.max_transform_header_bytes = 2;
    limits.max_stored_stream_bytes = 8192;
    limits.max_buffer_bytes = 4096;
    limits.max_graph_depth = 1;
    limits.max_expansion_ratio = 4096;
    let mut output = Vec::new();
    let _ = ozlrip::decode_into_with_options(&frame, &mut output, ozlrip::Options::from(limits));
});

fn bitunpack_serial_frame(bits: u8, trailing: u8, values: &[u8]) -> Vec<u8> {
    let decoded_len = (values.len() * usize::from(bits)).div_ceil(8);
    let mut input = Vec::new();
    input.extend_from_slice(&(MAGIC_BASE + 21).to_le_bytes());
    input.push(0);
    input.push(1);
    push_var_u64(&mut input, u64::try_from(decoded_len + 1).unwrap());
    input.push(2);
    input.push(1);
    input.push(0);
    input.push(34);
    input.push(1);
    input.push(1);
    input.push(0);
    input.push(0);
    input.push(0);
    push_var_u64(&mut input, u64::try_from(values.len()).unwrap());
    input.push(bits);
    input.push(trailing);
    input.extend_from_slice(values);
    input.push(0);
    input
}
