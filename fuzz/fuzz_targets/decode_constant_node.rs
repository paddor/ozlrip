#![no_main]

use libfuzzer_sys::fuzz_target;
use ozlrip::Limits;

const MAGIC_BASE: u32 = 0xd7b1_a5c0;

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
    let limits = Limits {
        max_frame_bytes: 8192,
        max_decoded_bytes: 4096,
        max_chunks: 1,
        max_nodes: 1,
        max_streams: 2,
        max_transform_header_bytes: 8,
        max_stored_stream_bytes: 1,
        max_buffer_bytes: 4096,
        max_graph_depth: 1,
        max_expansion_ratio: 4096,
    };
    let mut output = Vec::new();
    let _ = ozlrip::decode_into_with_options(
        &frame,
        &mut output,
        ozlrip::Options {
            limits,
            ..ozlrip::Options::default()
        },
    );
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

fn push_var_u64(out: &mut Vec<u8>, mut value: u64) {
    while value >= 0x80 {
        out.push(u8::try_from(value & 0x7f).unwrap() | 0x80);
        value >>= 7;
    }
    out.push(u8::try_from(value).unwrap());
}
