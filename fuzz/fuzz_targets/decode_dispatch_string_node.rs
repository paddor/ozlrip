#![no_main]

use libfuzzer_sys::fuzz_target;
use ozlrip::Limits;

const MAGIC_BASE: u32 = 0xd7b1_a5c0;

fuzz_target!(|data: &[u8]| {
    let frame = dispatch_string_graph_frame(data);
    let limits = Limits {
        max_frame_bytes: 8192,
        max_decoded_bytes: 4096,
        max_chunks: 1,
        max_nodes: 3,
        max_streams: 8,
        max_transform_header_bytes: 0,
        max_stored_stream_bytes: 8192,
        max_buffer_bytes: 4096,
        max_graph_depth: 2,
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

fn dispatch_string_graph_frame(data: &[u8]) -> Vec<u8> {
    let split = data
        .first()
        .map_or(0, |&byte| usize::from(byte) % (data.len().saturating_add(1)));
    let content = data.get(1..).unwrap_or_default();
    let split = split.min(content.len());
    let first = &content[..split];
    let second = &content[split..];
    let first_lengths = component_lengths(first, data.get(1).copied());
    let second_lengths = component_lengths(second, data.get(2).copied());
    let indices = dispatch_indices(first_lengths.len(), second_lengths.len(), data);
    let decoded_len = first.len() + second.len();

    let stored_streams = [
        first_lengths.as_slice(),
        first,
        second_lengths.as_slice(),
        second,
        indices.as_slice(),
    ];

    let mut input = Vec::new();
    input.extend_from_slice(&(MAGIC_BASE + 21).to_le_bytes());
    input.push(0);
    input.push(1);
    push_var_u64(&mut input, u64::try_from(decoded_len + 1).unwrap());
    push_var_u64(&mut input, 4);
    push_var_u64(&mut input, 5);
    input.push(0);
    input.extend_from_slice(&pack_values(&[12, 12, 54], 6));
    input.push(0);
    input.push(0b0000_0100);
    input.push(1);
    input.push(0);
    input.extend_from_slice(&pack_values(&[3, 0, 0], 3));
    for stream in stored_streams {
        push_var_u64(&mut input, u64::try_from(stream.len()).unwrap());
    }
    input.extend_from_slice(&first_lengths);
    input.extend_from_slice(first);
    input.extend_from_slice(&second_lengths);
    input.extend_from_slice(second);
    input.extend_from_slice(&indices);
    input.push(0);
    input
}

fn component_lengths(content: &[u8], seed: Option<u8>) -> Vec<u8> {
    if content.is_empty() {
        return Vec::new();
    }
    let min_fields = content.len().div_ceil(usize::from(u8::MAX));
    let max_fields = content.len().min(min_fields + 3);
    let fields = min_fields + usize::from(seed.unwrap_or(0)) % (max_fields - min_fields + 1);
    let base = content.len() / fields;
    let extra = content.len() % fields;
    (0..fields)
        .map(|index| {
            let len = base + usize::from(index < extra);
            u8::try_from(len).expect("field count keeps u8 lengths representable")
        })
        .collect()
}

fn dispatch_indices(first_count: usize, second_count: usize, data: &[u8]) -> Vec<u8> {
    let mut first_left = first_count;
    let mut second_left = second_count;
    let mut indices = Vec::with_capacity((first_count + second_count) * 2);
    for index in 0..first_count + second_count {
        let prefer_second = data.get(index).copied().unwrap_or(0) & 1 != 0;
        let source = if (prefer_second && second_left > 0) || first_left == 0 {
            second_left -= 1;
            1u16
        } else {
            first_left -= 1;
            0u16
        };
        indices.extend_from_slice(&source.to_le_bytes());
    }
    indices
}

fn pack_values(values: &[u32], bits: usize) -> Vec<u8> {
    if bits == 0 || values.is_empty() {
        return Vec::new();
    }
    let mut out = vec![0; (values.len() * bits).div_ceil(8)];
    for (index, &value) in values.iter().enumerate() {
        let bit_offset = index * bits;
        let byte_offset = bit_offset / 8;
        let bit_shift = bit_offset % 8;
        let lane = u64::from(value) << bit_shift;
        let bytes = lane.to_le_bytes();
        let byte_count = (bit_shift + bits).div_ceil(8);
        for byte_index in 0..byte_count {
            out[byte_offset + byte_index] |= bytes[byte_index];
        }
    }
    out
}

fn push_var_u64(out: &mut Vec<u8>, mut value: u64) {
    while value >= 0x80 {
        out.push(u8::try_from(value & 0x7f).unwrap() | 0x80);
        value >>= 7;
    }
    out.push(u8::try_from(value).unwrap());
}
