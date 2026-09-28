#![no_main]

use libfuzzer_sys::fuzz_target;
use ozlrip::Limits;
use ozlrip_test_support::{MAGIC_BASE, push_bitpacked_u32, push_var_u64};

fuzz_target!(|data: &[u8]| {
    let frame = field_lz_graph_frame(data);
    let mut limits = Limits::strict();
    limits.max_frame_bytes = 8192;
    limits.max_decoded_bytes = 4096;
    limits.max_chunks = 1;
    limits.max_nodes = 5;
    limits.max_streams = 10;
    limits.max_transform_header_bytes = 8;
    limits.max_stored_stream_bytes = 8192;
    limits.max_buffer_bytes = 4096;
    limits.max_graph_depth = 2;
    limits.max_expansion_ratio = 4096;
    let mut output = Vec::new();
    let _ = ozlrip::decode_into_with_options(&frame, &mut output, ozlrip::Options::from(limits));
});

fn field_lz_graph_frame(data: &[u8]) -> Vec<u8> {
    let decoded_elements = data.get(..2).map_or(0, |bytes| {
        u16::from_le_bytes([bytes[0], bytes[1]]) as usize & 0x0fff
    });
    let payload = data.get(2..).unwrap_or_default();
    let (tokens, rest) = take_aligned(payload, data.get(2).copied(), 2);
    let (offsets, rest) = take_aligned(rest, data.get(3).copied(), 4);
    let (extra_literals, rest) = take_aligned(rest, data.get(4).copied(), 4);
    let (extra_matches, literals) = take_aligned(rest, data.get(5).copied(), 4);

    let mut field_lz_header = Vec::new();
    push_var_u64(
        &mut field_lz_header,
        u64::try_from(decoded_elements).unwrap(),
    );

    let transform_headers = [1, 2, 2, 2]
        .into_iter()
        .chain(field_lz_header.iter().copied())
        .collect::<Vec<_>>();
    let stored_streams = [tokens, offsets, extra_literals, extra_matches, literals];
    let stored_size = stored_streams
        .iter()
        .map(|stream| stream.len())
        .sum::<usize>();

    let mut input = Vec::new();
    input.extend_from_slice(&(MAGIC_BASE + 24).to_le_bytes());
    input.push(0);
    input.push(1);
    push_var_u64(&mut input, u64::try_from(decoded_elements + 1).unwrap());
    push_var_u64(&mut input, 6);
    push_var_u64(&mut input, 5);
    input.push(0);
    push_bitpacked_u32(&mut input, &[10, 10, 10, 10, 24], 7);
    input.push(0b0001_1111);
    for size in [1usize, 1, 1, 1, field_lz_header.len()] {
        push_var_u64(&mut input, u64::try_from(size - 1).unwrap());
    }
    input.push(0);
    input.push(0);
    push_bitpacked_u32(&mut input, &[6, 4, 2, 0, 0], 4);
    for stream in stored_streams {
        push_var_u64(&mut input, u64::try_from(stream.len()).unwrap());
    }
    input.extend_from_slice(&transform_headers);
    input.extend_from_slice(tokens);
    input.extend_from_slice(offsets);
    input.extend_from_slice(extra_literals);
    input.extend_from_slice(extra_matches);
    input.extend_from_slice(literals);
    debug_assert!(input.len() >= stored_size);
    input.push(0);
    input
}

fn take_aligned(input: &[u8], seed: Option<u8>, align: usize) -> (&[u8], &[u8]) {
    if input.is_empty() {
        return (&[], input);
    }
    let len = usize::from(seed.unwrap_or(0)) % (input.len() + 1);
    let len = len - (len % align);
    input.split_at(len)
}
