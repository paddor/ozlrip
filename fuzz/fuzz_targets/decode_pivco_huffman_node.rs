#![no_main]

use libfuzzer_sys::fuzz_target;
use ozlrip::Limits;

const MAGIC_BASE: u32 = 0xd7b1_a5c0;

fuzz_target!(|data: &[u8]| {
    let (selector, rest) = data
        .split_first()
        .map_or((0, data), |(&first, rest)| (first, rest));
    let decoded_size = rest
        .get(..2)
        .map_or(4, |bytes| u16::from_le_bytes([bytes[0], bytes[1]]) as usize)
        & 0x0fff;
    let block_size = if selector & 0x80 == 0 {
        None
    } else {
        Some((usize::from(selector & 0x3f) + 1).min(decoded_size.max(1)))
    };
    let payload = rest.get(2..).unwrap_or_default();
    let split = payload.first().copied().map_or(0, usize::from) % (payload.len() + 1);
    let bitstream = &payload[split..];
    let weights = match selector & 3 {
        0 => vec![1],
        1 => vec![1, 1],
        2 => vec![2, 1, 1],
        _ => vec![1, 1, 1, 1],
    };

    let frame = pivco_huffman_frame(&weights, bitstream, decoded_size, block_size);
    let limits = Limits {
        max_frame_bytes: 8192,
        max_decoded_bytes: 4096,
        max_chunks: 1,
        max_nodes: 1,
        max_streams: 4,
        max_transform_header_bytes: 16,
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

fn pivco_huffman_frame(
    weights: &[u8],
    bitstream: &[u8],
    decoded_size: usize,
    block_size: Option<usize>,
) -> Vec<u8> {
    let mut transform_header = Vec::new();
    push_var_u64(&mut transform_header, u64::try_from(decoded_size).unwrap());
    if let Some(block_size) = block_size {
        push_var_u64(&mut transform_header, u64::try_from(block_size).unwrap());
    }

    let mut input = Vec::new();
    input.extend_from_slice(&(MAGIC_BASE + 27).to_le_bytes());
    input.push(0);
    input.push(1);
    push_var_u64(&mut input, u64::try_from(decoded_size + 1).unwrap());
    input.push(2);
    input.push(2);
    input.push(0);
    input.push(67);
    input.push(1);
    push_var_u64(
        &mut input,
        u64::try_from(transform_header.len() - 1).unwrap(),
    );
    input.push(0);
    input.push(0);
    input.push(0);
    push_var_u64(&mut input, u64::try_from(bitstream.len()).unwrap());
    push_var_u64(&mut input, u64::try_from(weights.len()).unwrap());
    input.extend_from_slice(&transform_header);
    input.extend_from_slice(bitstream);
    input.extend_from_slice(weights);
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
