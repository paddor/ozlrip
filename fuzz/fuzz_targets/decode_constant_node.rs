#![no_main]

use libfuzzer_sys::fuzz_target;
use ozlrip::Limits;
use ozlrip_test_support::{MAGIC_BASE, push_var_u64};

fuzz_target!(|data: &[u8]| {
    if data.len() < 2 {
        return;
    }
    let count = u16::from_le_bytes([data[0], data[1]]) as usize & 0x0fff;
    let value = data.get(2).copied().unwrap_or(0);
    let transform_id = if data.get(3).copied().unwrap_or(0) & 1 == 0 {
        44
    } else {
        45
    };
    let frame = constant_frame(transform_id, value, count);
    let mut limits = Limits::strict();
    limits.max_frame_bytes = 8192;
    limits.max_decoded_bytes = 4096;
    limits.max_chunks = 1;
    limits.max_nodes = 1;
    limits.max_streams = 2;
    limits.max_transform_header_bytes = 8;
    limits.max_stored_stream_bytes = 1;
    limits.max_buffer_bytes = 4096;
    limits.max_graph_depth = 1;
    limits.max_expansion_ratio = 4096;
    let mut output = Vec::new();
    let _ = ozlrip::decode_into_with_options(&frame, &mut output, ozlrip::Options::from(limits));
});

fn constant_frame(transform_id: u8, value: u8, count: usize) -> Vec<u8> {
    let mut header = Vec::new();
    push_var_u64(&mut header, u64::try_from(count).unwrap());
    let mut input = Vec::new();
    input.extend_from_slice(&(MAGIC_BASE + 21).to_le_bytes());
    input.push(0);
    input.push(1);
    push_var_u64(&mut input, u64::try_from(count + 1).unwrap());
    input.push(2);
    input.push(1);
    input.push(0);
    input.push(transform_id);
    input.push(1);
    push_var_u64(&mut input, u64::try_from(header.len() - 1).unwrap());
    input.push(0);
    input.push(0);
    input.push(0);
    input.push(1);
    input.extend_from_slice(&header);
    input.push(value);
    input.push(0);
    input
}
