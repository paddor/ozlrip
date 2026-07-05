#![no_main]

use libfuzzer_sys::fuzz_target;
use ozlrip::Limits;

const MAGIC_BASE: u32 = 0xd7b1_a5c0;

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }
    let width = match data[0] % 3 {
        0 => 2,
        1 => 4,
        _ => 8,
    };
    let frame = transpose_split_frame(width, &data[1..]);
    let limits = Limits {
        max_frame_bytes: 8192,
        max_decoded_bytes: 4096,
        max_chunks: 1,
        max_nodes: 1,
        max_streams: 8,
        max_transform_header_bytes: 0,
        max_stored_stream_bytes: 8192,
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

fn transpose_split_frame(width: usize, payload: &[u8]) -> Vec<u8> {
    let transform_id = match width {
        2 => 30,
        4 => 31,
        8 => 32,
        _ => unreachable!(),
    };
    let mut input = Vec::new();
    input.extend_from_slice(&(MAGIC_BASE + 21).to_le_bytes());
    input.push(0);
    input.push(1);
    input.push(0);
    input.push(2);
    push_var_u64(&mut input, u64::try_from(width).unwrap());
    input.push(0);
    input.push(transform_id);
    input.push(0);
    input.push(0);
    input.push(0);
    input.push(0);

    let base = payload.len() / width;
    let extra = payload.len() % width;
    let mut offset = 0usize;
    for index in 0..width {
        let len = base + usize::from(index < extra);
        push_var_u64(&mut input, u64::try_from(len).unwrap());
    }
    for index in 0..width {
        let len = base + usize::from(index < extra);
        input.extend_from_slice(&payload[offset..offset + len]);
        offset += len;
    }
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
