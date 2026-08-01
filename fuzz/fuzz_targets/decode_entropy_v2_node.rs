#![no_main]

use libfuzzer_sys::fuzz_target;
use ozlrip::Limits;

const MAGIC_BASE: u32 = 0xd7b1_a5c0;
const FSE_V2_ID: u32 = 49;
const HUFFMAN_V2_ID: u32 = 50;
const HUFFMAN_STRUCT_V2_ID: u32 = 51;

fuzz_target!(|data: &[u8]| {
    let (selector, rest) = data
        .split_first()
        .map_or((0, data), |(&first, rest)| (first, rest));
    let decoded_elements = rest
        .get(..2)
        .map_or(2, |bytes| {
            usize::from(u16::from_le_bytes([bytes[0], bytes[1]]) & 0x07ff)
        })
        .max(2);
    let payload = rest.get(2..).unwrap_or_default();
    let split = payload.first().copied().map_or(0, usize::from) % (payload.len() + 1);
    let (table_seed, bits) = payload.split_at(split);

    let (transform_id, decoded_len, header, table) = match selector % 3 {
        0 => {
            let nb_states = if selector & 0x20 == 0 { 2 } else { 4 };
            (
                FSE_V2_ID,
                decoded_elements,
                entropy_v2_header(nb_states, decoded_elements, selector),
                fse_norm(selector, table_seed),
            )
        }
        1 => (
            HUFFMAN_V2_ID,
            decoded_elements,
            entropy_v2_header(selector & 1, decoded_elements, selector),
            huffman_weights(selector, table_seed),
        ),
        _ => (
            HUFFMAN_STRUCT_V2_ID,
            decoded_elements.saturating_mul(2),
            entropy_v2_header(selector & 1, decoded_elements, selector),
            huffman_weights(selector, table_seed),
        ),
    };

    let frame = entropy_v2_graph_frame(transform_id, decoded_len, &header, &[&table, bits]);
    let limits = Limits {
        max_frame_bytes: 8192,
        max_decoded_bytes: 4096,
        max_chunks: 1,
        max_nodes: 1,
        max_streams: 3,
        max_transform_header_bytes: 9,
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

fn fse_norm(selector: u8, seed: &[u8]) -> Vec<u8> {
    match selector & 0x18 {
        0x00 => [16i16, 16].into_iter().flat_map(i16::to_le_bytes).collect(),
        0x08 => [8i16, 8, 8, 8]
            .into_iter()
            .flat_map(i16::to_le_bytes)
            .collect(),
        0x10 => [1i16, 1, 1, 29]
            .into_iter()
            .flat_map(i16::to_le_bytes)
            .collect(),
        _ => {
            let len = seed.len().min(256);
            seed[..len].to_vec()
        }
    }
}

fn huffman_weights(selector: u8, seed: &[u8]) -> Vec<u8> {
    match selector & 0x18 {
        0x00 => vec![1, 1],
        0x08 => vec![2, 1, 1],
        0x10 => vec![1, 1, 1, 1],
        _ => {
            let len = seed.len().min(256);
            seed[..len].to_vec()
        }
    }
}

fn entropy_v2_header(first: u8, decoded_elements: usize, selector: u8) -> Vec<u8> {
    let byte_count = usize::from((selector >> 6) & 0x03) + 1;
    let mut header = Vec::with_capacity(byte_count + 1);
    header.push(first);
    let bytes = u64::try_from(decoded_elements).unwrap().to_le_bytes();
    header.extend_from_slice(&bytes[..byte_count]);
    header
}

fn entropy_v2_graph_frame(
    transform_id: u32,
    decoded_len: usize,
    transform_header: &[u8],
    logical_stored_streams: &[&[u8]],
) -> Vec<u8> {
    let mut input = Vec::new();
    input.extend_from_slice(&(MAGIC_BASE + 21).to_le_bytes());
    input.push(0);
    input.push(1);
    push_var_u64(&mut input, u64::try_from(decoded_len + 1).unwrap());
    push_var_u64(&mut input, 2);
    push_var_u64(
        &mut input,
        u64::try_from(logical_stored_streams.len()).unwrap(),
    );
    push_bitpacked_u32(&mut input, &[0], 1);
    push_bitpacked_u32(&mut input, &[transform_id], 6);
    push_bitpacked_u32(&mut input, &[1], 1);
    push_var_u64(
        &mut input,
        u64::try_from(transform_header.len() - 1).unwrap(),
    );
    push_bitpacked_u32(&mut input, &[0], 1);
    push_bitpacked_u32(&mut input, &[0], 1);
    push_bitpacked_u32(
        &mut input,
        &[0],
        bits_needed(logical_stored_streams.len() + 1),
    );
    for stream in logical_stored_streams.iter().rev() {
        push_var_u64(&mut input, u64::try_from(stream.len()).unwrap());
    }
    input.extend_from_slice(transform_header);
    for stream in logical_stored_streams.iter().rev() {
        input.extend_from_slice(stream);
    }
    input.push(0);
    input
}

fn push_bitpacked_u32(out: &mut Vec<u8>, values: &[u32], bits: usize) {
    if values.is_empty() || bits == 0 {
        return;
    }
    let mut packed = vec![0; (values.len() * bits).div_ceil(8)];
    for (index, &value) in values.iter().enumerate() {
        let bit_offset = index * bits;
        let byte_offset = bit_offset / 8;
        let bit_shift = bit_offset % 8;
        let lane = u64::from(value) << bit_shift;
        let lane_bytes = lane.to_le_bytes();
        let byte_count = (bit_shift + bits).div_ceil(8);
        for byte_index in 0..byte_count {
            packed[byte_offset + byte_index] |= lane_bytes[byte_index];
        }
    }
    out.extend_from_slice(&packed);
}

fn bits_needed(max_value: usize) -> usize {
    if max_value <= 1 {
        0
    } else {
        usize::BITS as usize - (max_value - 1).leading_zeros() as usize
    }
}

fn push_var_u64(out: &mut Vec<u8>, mut value: u64) {
    while value >= 0x80 {
        out.push(u8::try_from(value & 0x7f).unwrap() | 0x80);
        value >>= 7;
    }
    out.push(u8::try_from(value).unwrap());
}
