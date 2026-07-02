#![no_main]

use libfuzzer_sys::fuzz_target;
use ozlrip::Limits;

const MAGIC_BASE: u32 = 0xd7b1_a5c0;

fuzz_target!(|data: &[u8]| {
    if data.len() < 2 {
        return;
    }
    let bits = (data[0] % 8) + 1;
    let extra = data[1];
    let stored = &data[2..];
    let frame = bitpack_serial_frame(stored, bits, extra);
    let limits = Limits {
        max_frame_bytes: 8192,
        max_decoded_bytes: 4096,
        max_chunks: 1,
        max_nodes: 1,
        max_streams: 2,
        max_transform_header_bytes: 2,
        max_stored_stream_bytes: 8192,
        max_buffer_bytes: 4096,
        max_graph_depth: 1,
        max_expansion_ratio: 4096,
    };
    let mut output = Vec::new();
    let _ = ozlrip::decode_into(&frame, &mut output, limits);
});

fn bitpack_serial_frame(stored: &[u8], bits: u8, extra: u8) -> Vec<u8> {
    let mut input = Vec::new();
    input.extend_from_slice(&(MAGIC_BASE + 21).to_le_bytes());
    input.push(0);
    input.push(1);
    input.push(0);
    input.push(2);
    input.push(1);
    input.push(0);
    input.push(27);
    input.push(1);
    input.push(1);
    input.push(0);
    input.push(0);
    input.push(0);
    push_var_u64(&mut input, u64::try_from(stored.len()).unwrap());
    input.push(bits - 1);
    input.push(extra);
    input.extend_from_slice(stored);
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
