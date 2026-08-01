#![no_main]

use libfuzzer_sys::fuzz_target;
use ozlrip::Limits;

const MAGIC_BASE: u32 = 0xd7b1_a5c0;
const FSE_NCOUNT_ID: u8 = 52;

fuzz_target!(|data: &[u8]| {
    let decoded_len = data.get(..2).map_or(0, |bytes| {
        usize::from(u16::from_le_bytes([bytes[0], bytes[1]]) & 0x01ff)
    }) & !1;
    let stored = data.get(2..).unwrap_or_default();
    let frame = standard_transform_serial_frame(FSE_NCOUNT_ID, stored, decoded_len);
    let limits = Limits {
        max_frame_bytes: 8192,
        max_decoded_bytes: 4096,
        max_chunks: 1,
        max_nodes: 1,
        max_streams: 2,
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

fn standard_transform_serial_frame(transform_id: u8, stored: &[u8], decoded_len: usize) -> Vec<u8> {
    let mut input = Vec::new();
    input.extend_from_slice(&(MAGIC_BASE + 21).to_le_bytes());
    input.push(0);
    input.push(1);
    push_var_u64(&mut input, u64::try_from(decoded_len + 1).unwrap());
    input.push(2);
    input.push(1);
    input.push(0);
    input.push(transform_id);
    input.push(0);
    input.push(0);
    input.push(0);
    input.push(0);
    push_var_u64(&mut input, u64::try_from(stored.len()).unwrap());
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
