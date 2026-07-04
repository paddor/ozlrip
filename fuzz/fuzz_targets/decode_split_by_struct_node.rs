#![no_main]

use libfuzzer_sys::fuzz_target;
use ozlrip::Limits;

const MAGIC_BASE: u32 = 0xd7b1_a5c0;

fuzz_target!(|data: &[u8]| {
    let split = data.first().copied().map_or(0, usize::from) % (data.len().saturating_add(1));
    let payload = data.get(1..).unwrap_or_default();
    let split = split.min(payload.len());
    let field0 = &payload[..split];
    let field1 = &payload[split..];
    let element_count = field0.len().min(field1.len());
    let frame = single_transform_frame(41, 2, element_count * 2, &[
        &field1[..element_count],
        &field0[..element_count],
    ]);
    let limits = Limits {
        max_frame_bytes: 8192,
        max_decoded_bytes: 4096,
        max_chunks: 1,
        max_nodes: 1,
        max_streams: 4,
        max_transform_header_bytes: 0,
        max_stored_stream_bytes: 8192,
        max_buffer_bytes: 4096,
        max_graph_depth: 1,
        max_expansion_ratio: 4096,
    };
    let mut output = Vec::new();
    let _ = ozlrip::decode_into_with_options(&frame, &mut output, ozlrip::Options { limits });
});

fn single_transform_frame(
    transform_id: u8,
    variable_inputs: usize,
    decoded_len: usize,
    stored_streams: &[&[u8]],
) -> Vec<u8> {
    let mut input = Vec::new();
    input.extend_from_slice(&(MAGIC_BASE + 21).to_le_bytes());
    input.push(0);
    input.push(1);
    push_var_u64(&mut input, u64::try_from(decoded_len + 1).unwrap());
    input.push(2);
    push_var_u64(&mut input, u64::try_from(stored_streams.len()).unwrap());
    input.push(0);
    input.push(transform_id);
    input.push(0);
    if variable_inputs == 0 {
        input.push(0);
    } else {
        input.push(1);
        push_var_u64(&mut input, u64::try_from(variable_inputs - 1).unwrap());
    }
    input.push(0);
    input.push(0);
    for stream in stored_streams {
        push_var_u64(&mut input, u64::try_from(stream.len()).unwrap());
    }
    for stream in stored_streams {
        input.extend_from_slice(stream);
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
