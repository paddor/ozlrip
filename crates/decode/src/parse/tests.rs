use super::*;
use alloc::vec;
use ozlrip_test_support::{Chunk, FrameBuilder, OutputType};

fn magic(version: u32) -> [u8; 4] {
    (MAGIC_BASE + version).to_le_bytes()
}

fn push_bitpacked_u32(out: &mut Vec<u8>, values: &[u32], bits: usize) {
    let len = (values.len() * bits).div_ceil(8);
    let start = out.len();
    out.resize(start + len, 0);
    for (index, &value) in values.iter().enumerate() {
        for bit in 0..bits {
            if ((value >> bit) & 1) != 0 {
                let absolute = index * bits + bit;
                out[start + absolute / 8] |= 1 << (absolute % 8);
            }
        }
    }
}

fn push_var_u64(out: &mut Vec<u8>, mut value: u64) {
    while value >= 0x80 {
        out.push(u8::try_from(value & 0x7f).unwrap() | 0x80);
        value >>= 7;
    }
    out.push(u8::try_from(value).unwrap());
}

fn push_v21_output_sizes(out: &mut Vec<u8>, outputs: usize) {
    for _ in 0..outputs {
        out.push(1);
    }
}

fn v21_header_with_outputs(outputs: usize) -> Vec<u8> {
    let mut input = Vec::new();
    input.extend_from_slice(&magic(21));
    input.push(0);
    if outputs <= 14 {
        input.push(u8::try_from(outputs).unwrap());
        if outputs > 2 {
            input.resize(input.len() + (outputs - 2).div_ceil(4), 0);
        }
    } else {
        let encoded = outputs - 15;
        let high = encoded & 0x0f;
        let next = encoded >> 4;
        input.push(0x0f | u8::try_from(high << 4).unwrap());
        input.push(u8::try_from(next).unwrap());
        input.resize(input.len() + outputs.div_ceil(4), 0);
    }
    push_v21_output_sizes(&mut input, outputs);
    input.push(0);
    input
}

fn pivco_huffman_frame(version: u32) -> Vec<u8> {
    let mut input = Vec::new();
    input.extend_from_slice(&magic(version));
    input.push(0);
    input.push(1);
    input.push(1);
    input.push(2);
    input.push(2);
    input.push(0);
    input.push(67);
    input.push(1);
    input.push(0);
    input.push(0);
    input.push(0);
    input.push(0);
    input.push(0);
    input.push(0);
    input.push(0);
    input.push(0);
    input
}

fn assert_truncations_fail(input: &[u8], first_truncated_len: usize) {
    for end in first_truncated_len..input.len() {
        assert!(
            inspect_frame(&input[..end], Limits::default()).is_err(),
            "prefix len {end} unexpectedly parsed"
        );
    }
}

#[test]
fn rejects_truncated_magic() {
    let err = inspect_frame(&[0xd5, 0xa5], Limits::default()).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::Truncated);
    assert_eq!(err.offset(), Some(0));
}

#[test]
fn rejects_unknown_magic() {
    let err = inspect_frame(b"not-openzl", Limits::default()).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::Unsupported);
    assert_eq!(err.offset(), Some(0));
}

#[test]
fn rejects_format_versions_after_v27() {
    let err = inspect_frame(&magic(28), Limits::default()).unwrap_err();

    assert_eq!(err.kind(), ErrorKind::Unsupported);
    assert_eq!(err.offset(), Some(0));
}

#[test]
fn parses_v27_pivco_huffman_transform() {
    let input = pivco_huffman_frame(27);

    let info = inspect_frame(&input, Limits::default()).unwrap();

    assert_eq!(info.format_version, 27);
    assert_eq!(info.decoded_bytes, Some(0));
    assert_eq!(info.chunks, 1);
    assert_eq!(info.transforms, 1);
    assert_eq!(info.stored_streams, 2);
    assert_eq!(info.regenerated_streams, 1);
}

#[test]
fn rejects_overflowing_u64_varint() {
    let mut input = Vec::new();
    input.extend_from_slice(&magic(21));
    input.push(0);
    input.push(1);
    input.extend_from_slice(&[0xff; 9]);
    input.push(0x02);

    let err = inspect_frame(&input, Limits::default()).unwrap_err();

    assert_eq!(err.kind(), ErrorKind::IntegerOverflow);
}

#[test]
fn parses_v21_single_serial_known_size_header() {
    let mut input = Vec::new();
    input.extend_from_slice(&magic(21));
    input.push(0);
    input.push(1);
    input.push(4);
    input.push(0);

    let info = inspect_frame(&input, Limits::default()).unwrap();

    assert_eq!(info.format_version, 21);
    assert_eq!(info.header_bytes, input.len() - 1);
    assert_eq!(info.decoded_bytes, Some(3));
    assert_eq!(info.outputs, 1);
    assert_eq!(info.output_types, [FrameValueType::Serial]);
    assert_eq!(info.output_sizes, [Some(3)]);
    assert_eq!(info.output_elements, [Some(3)]);
}

#[test]
fn rejects_v21_unknown_output_size() {
    let mut input = Vec::new();
    input.extend_from_slice(&magic(21));
    input.push(0);
    input.push(1);
    input.push(0);

    let err = inspect_frame(&input, Limits::default()).unwrap_err();

    assert_eq!(err.kind(), ErrorKind::Unsupported);
    assert!(err.detail().unwrap().contains("unknown"));
}

#[cfg(feature = "zstd")]
#[test]
fn rejects_unknown_output_size_before_zstd_fast_path() {
    let mut input = Vec::new();
    input.extend_from_slice(&magic(21));
    input.push(0);
    input.push(1);
    input.push(0);

    let err = parse_single_zstd_frame(&input, Limits::default()).unwrap_err();

    assert_eq!(err.kind(), ErrorKind::Unsupported);
    assert!(err.detail().unwrap().contains("unknown"));
}

#[test]
fn parses_v14_single_typed_output_header() {
    let input = FrameBuilder::new(14)
        .output(OutputType::Numeric, 4)
        .chunk(Chunk::stored([1, 2, 3, 4]))
        .build();

    let info = inspect_frame(&input, Limits::default()).unwrap();

    assert_eq!(info.format_version, 14);
    assert_eq!(info.header_bytes, 9);
    assert_eq!(info.output_types, [FrameValueType::Numeric]);
    assert_eq!(info.output_sizes, [Some(4)]);
    assert_eq!(info.output_elements, [None]);
}

#[test]
fn parses_v20_single_serial_32_bit_output_size() {
    let input = FrameBuilder::new(20)
        .serial_output(3)
        .chunk(Chunk::stored(*b"abc"))
        .build();

    let info = inspect_frame(&input, Limits::default()).unwrap();

    assert_eq!(info.format_version, 20);
    assert_eq!(info.output_types, [FrameValueType::Serial]);
    assert_eq!(info.output_sizes, [Some(3)]);
    assert_eq!(info.output_elements, [Some(3)]);
}

#[test]
fn parses_v21_output_count_boundaries() {
    for outputs in [1, 2, 14, 15] {
        let input = v21_header_with_outputs(outputs);
        let info = inspect_frame(&input, Limits::default()).unwrap();
        assert_eq!(info.outputs, outputs);
        assert_eq!(info.output_types.len(), outputs);
        assert_eq!(info.output_sizes.len(), outputs);
    }
}

#[test]
fn rejects_v21_output_count_above_runtime_limit() {
    let input = v21_header_with_outputs(2049);

    let err = inspect_frame(&input, Limits::default()).unwrap_err();

    assert_eq!(err.kind(), ErrorKind::Malformed);
}

#[test]
fn parses_v21_typed_output_descriptors() {
    let mut input = Vec::new();
    input.extend_from_slice(&magic(21));
    input.push(0);
    input.push(0b1000_0010);
    input.push(4);
    input.push(5);
    input.push(0);

    let info = inspect_frame(&input, Limits::default()).unwrap();

    assert_eq!(
        info.output_types,
        [FrameValueType::Serial, FrameValueType::Numeric]
    );
    assert_eq!(info.output_sizes, [Some(3), Some(4)]);
    assert_eq!(info.output_elements, [Some(3), None]);
    assert_eq!(info.decoded_bytes, Some(7));
}

#[test]
fn enforces_output_buffer_limit() {
    let mut input = Vec::new();
    input.extend_from_slice(&magic(21));
    input.push(0);
    input.push(1);
    input.push(4);
    let mut limits = Limits::default();
    limits.max_buffer_bytes = 2;

    let err = inspect_frame(&input, limits).unwrap_err();

    assert_eq!(err.kind(), ErrorKind::LimitExceeded);
}

#[test]
fn rejects_output_size_sum_overflow() {
    let encoded_size = usize::MAX as u64;
    let mut input = Vec::new();
    input.extend_from_slice(&magic(21));
    input.push(0);
    input.push(2);
    push_var_u64(&mut input, encoded_size);
    push_var_u64(&mut input, encoded_size);
    let mut limits = Limits::default();
    limits.max_decoded_bytes = usize::MAX;
    limits.max_buffer_bytes = usize::MAX;

    let err = inspect_frame(&input, limits).unwrap_err();

    assert_eq!(err.kind(), ErrorKind::IntegerOverflow);
}

#[test]
fn parses_v21_eof_marker() {
    let mut input = Vec::new();
    input.extend_from_slice(&magic(21));
    input.push(0);
    input.push(1);
    input.push(4);
    input.push(0);

    let info = inspect_frame(&input, Limits::default()).unwrap();

    assert_eq!(info.header_bytes, 7);
    assert_eq!(info.chunks, 0);
}

/// Upstream reads the chunk marker unconditionally from v21 on, so a
/// frame that ends after its header is truncated, not empty.
#[test]
fn rejects_v21_frame_without_eof_marker() {
    let mut input = Vec::new();
    input.extend_from_slice(&magic(21));
    input.push(0);
    input.push(1);
    input.push(1);

    let err = inspect_frame(&input, Limits::default()).unwrap_err();

    assert_eq!(err.kind(), ErrorKind::Truncated);
    assert_eq!(err.offset(), Some(7));
}

#[test]
fn rejects_trailing_bytes_after_v21_eof_marker() {
    let mut input = Vec::new();
    input.extend_from_slice(&magic(21));
    input.push(0);
    input.push(1);
    input.push(4);
    input.push(0);
    input.push(99);

    let err = inspect_frame(&input, Limits::default()).unwrap_err();

    assert_eq!(err.kind(), ErrorKind::Malformed);
    assert_eq!(err.offset(), Some(8));
}

#[test]
fn rejects_v21_empty_chunk_without_final_stream() {
    let mut input = Vec::new();
    input.extend_from_slice(&magic(21));
    input.push(0);
    input.push(1);
    input.push(4);
    input.push(1);
    input.push(0);
    input.push(0);

    let err = inspect_frame(&input, Limits::default()).unwrap_err();

    assert_eq!(err.kind(), ErrorKind::InvalidGraph);
}

#[test]
fn parses_v21_standard_transform_chunk() {
    let mut input = Vec::new();
    input.extend_from_slice(&magic(21));
    input.push(0);
    input.push(1);
    input.push(4);
    input.push(2);
    input.push(1);
    input.push(0);
    input.push(22);
    input.push(0);
    input.push(0);
    input.push(0);
    input.push(0);
    input.push(3);
    input.extend_from_slice(&[1, 2, 3]);
    input.push(0);

    let info = inspect_frame(&input, Limits::default()).unwrap();

    assert_eq!(info.chunks, 1);
    assert_eq!(info.transforms, 1);
    assert_eq!(info.stored_streams, 1);
    assert_eq!(info.regenerated_streams, 1);
}

#[test]
fn rejects_reserved_standard_transform_id() {
    let mut input = Vec::new();
    input.extend_from_slice(&magic(21));
    input.push(0);
    input.push(1);
    input.push(4);
    input.push(2);
    input.push(1);
    input.push(0);
    input.push(0);
    input.push(0);
    input.push(0);
    input.push(0);
    input.push(0);
    input.push(3);
    input.extend_from_slice(&[1, 2, 3]);
    input.push(0);

    let err = inspect_frame(&input, Limits::default()).unwrap_err();

    assert_eq!(err.kind(), ErrorKind::Unsupported);
}

#[test]
fn rejects_custom_transform_id() {
    let mut input = Vec::new();
    input.extend_from_slice(&magic(21));
    input.push(0);
    input.push(1);
    input.push(4);
    input.push(2);
    input.push(1);
    input.push(1);
    input.push(1);

    let err = inspect_frame(&input, Limits::default()).unwrap_err();

    assert_eq!(err.kind(), ErrorKind::Unsupported);
}

#[test]
fn enforces_standard_transform_id_min_version() {
    let mut input = Vec::new();
    input.extend_from_slice(&magic(25));
    input.push(0);
    input.push(1);
    input.push(4);
    input.push(2);
    input.push(2);
    input.push(0);
    input.push(66);
    input.push(0);
    input.push(0);
    input.push(0);
    input.push(0);
    input.push(1);
    input.push(2);
    input.extend_from_slice(&[1, 2, 3]);
    input.push(0);

    let err = inspect_frame(&input, Limits::default()).unwrap_err();

    assert_eq!(err.kind(), ErrorKind::Unsupported);

    input[..4].copy_from_slice(&magic(26));
    let info = inspect_frame(&input, Limits::default()).unwrap();
    assert_eq!(info.transforms, 1);
}

#[test]
fn enforces_pivco_huffman_min_version() {
    let input = pivco_huffman_frame(26);

    let err = inspect_frame(&input, Limits::default()).unwrap_err();

    assert_eq!(err.kind(), ErrorKind::Unsupported);
}

#[test]
fn rejects_node_input_count_out_of_bounds() {
    let mut input = Vec::new();
    input.extend_from_slice(&magic(21));
    input.push(0);
    input.push(1);
    input.push(4);
    input.push(2);
    input.push(1);
    input.push(0);
    input.push(22);
    input.push(0);
    input.push(1);
    input.push(2);
    input.push(0);
    input.push(0);
    input.push(3);
    input.extend_from_slice(&[1, 2, 3]);
    input.push(0);

    let err = inspect_frame(&input, Limits::default()).unwrap_err();

    assert_eq!(err.kind(), ErrorKind::InvalidGraph);
}

#[test]
fn rejects_fixed_codec_variable_inputs() {
    let mut input = Vec::new();
    input.extend_from_slice(&magic(24));
    input.push(0);
    input.push(1);
    input.push(4);
    input.push(2);
    input.push(1);
    input.push(0);
    input.push(62);
    input.push(0);
    input.push(1);
    input.push(0);
    input.push(0);
    input.push(0);
    input.push(0);
    input.push(0);

    let err = inspect_frame(&input, Limits::default()).unwrap_err();

    assert_eq!(err.kind(), ErrorKind::InvalidGraph);
}

#[test]
fn rejects_duplicate_regen_stream_distance() {
    let mut input = Vec::new();
    input.extend_from_slice(&magic(21));
    input.push(0);
    input.push(1);
    input.push(4);
    input.push(2);
    input.push(2);
    push_bitpacked_u32(&mut input, &[0], 1);
    push_bitpacked_u32(&mut input, &[55], 6);
    push_bitpacked_u32(&mut input, &[0], 1);
    push_bitpacked_u32(&mut input, &[0], 1);
    push_bitpacked_u32(&mut input, &[1], 1);
    input.push(0);
    push_bitpacked_u32(&mut input, &[0, 0], 2);
    input.push(1);
    input.push(2);
    input.extend_from_slice(&[1, 2, 3]);
    input.push(0);

    let err = inspect_frame(&input, Limits::default()).unwrap_err();

    assert_eq!(err.kind(), ErrorKind::InvalidGraph);
}

#[test]
fn rejects_node_inputs_reaching_final_streams() {
    let mut input = Vec::new();
    input.extend_from_slice(&magic(21));
    input.push(0);
    input.push(1);
    input.push(4);
    input.push(2);
    input.push(1);
    input.push(0);
    input.push(29);
    input.push(0);
    input.push(0);
    input.push(0);
    input.push(0);
    input.push(3);
    input.extend_from_slice(&[1, 2, 3]);
    input.push(0);

    let err = inspect_frame(&input, Limits::default()).unwrap_err();

    assert_eq!(err.kind(), ErrorKind::InvalidGraph);
}

#[test]
fn rejects_duplicate_regen_stream_distance_across_nodes() {
    let mut input = Vec::new();
    input.extend_from_slice(&magic(21));
    input.push(0);
    input.push(1);
    input.push(4);
    input.push(3);
    input.push(1);
    push_bitpacked_u32(&mut input, &[0, 0], 1);
    push_bitpacked_u32(&mut input, &[22, 22], 6);
    push_bitpacked_u32(&mut input, &[0, 0], 1);
    push_bitpacked_u32(&mut input, &[0, 0], 1);
    push_bitpacked_u32(&mut input, &[0, 0], 1);
    push_bitpacked_u32(&mut input, &[1, 0], 2);
    input.push(3);
    input.extend_from_slice(&[1, 2, 3]);
    input.push(0);

    let err = inspect_frame(&input, Limits::default()).unwrap_err();

    assert_eq!(err.kind(), ErrorKind::InvalidGraph);
}

#[test]
fn enforces_graph_depth_limit() {
    let mut input = Vec::new();
    input.extend_from_slice(&magic(21));
    input.push(0);
    input.push(1);
    input.push(4);
    input.push(3);
    input.push(1);
    push_bitpacked_u32(&mut input, &[0, 0], 1);
    push_bitpacked_u32(&mut input, &[22, 22], 6);
    push_bitpacked_u32(&mut input, &[0, 0], 1);
    push_bitpacked_u32(&mut input, &[0, 0], 1);
    push_bitpacked_u32(&mut input, &[0, 0], 1);
    push_bitpacked_u32(&mut input, &[0, 0], 2);
    input.push(3);
    input.extend_from_slice(&[1, 2, 3]);
    input.push(0);

    let info = inspect_frame(&input, Limits::default()).unwrap();
    assert_eq!(info.transforms, 2);

    let mut limits = Limits::default();
    limits.max_graph_depth = 1;
    let err = inspect_frame(&input, limits).unwrap_err();

    assert_eq!(err.kind(), ErrorKind::LimitExceeded);
}

#[test]
fn enforces_transform_header_byte_limit() {
    let mut input = Vec::new();
    input.extend_from_slice(&magic(21));
    input.push(0);
    input.push(1);
    input.push(4);
    input.push(2);
    input.push(1);
    input.push(0);
    input.push(22);
    input.push(1);
    input.push(0);
    input.push(0);
    input.push(0);
    input.push(0);
    input.push(3);
    input.push(99);
    input.extend_from_slice(&[1, 2, 3]);
    input.push(0);
    let mut limits = Limits::default();
    limits.max_transform_header_bytes = 0;

    let err = inspect_frame(&input, limits).unwrap_err();

    assert_eq!(err.kind(), ErrorKind::LimitExceeded);
}

#[test]
fn rejects_transform_header_size_at_upstream_u32_sentinel() {
    let mut input = Vec::new();
    input.extend_from_slice(&magic(21));
    input.push(0);
    input.push(1);
    input.push(4);
    input.push(2);
    input.push(1);
    input.push(0);
    input.push(22);
    input.push(1);
    push_var_u64(&mut input, u64::from(u32::MAX - 1));

    let err = inspect_frame(&input, Limits::default()).unwrap_err();

    assert_eq!(err.kind(), ErrorKind::Malformed);
}

#[test]
fn enforces_stored_stream_buffer_limit() {
    let mut input = Vec::new();
    input.extend_from_slice(&magic(21));
    input.push(0);
    input.push(1);
    input.push(4);
    input.push(1);
    input.push(1);
    input.push(3);
    input.extend_from_slice(&[1, 2, 3]);
    input.push(0);
    let mut limits = Limits::default();
    limits.max_buffer_bytes = 2;

    let err = inspect_frame(&input, limits).unwrap_err();

    assert_eq!(err.kind(), ErrorKind::LimitExceeded);
}

#[test]
fn rejects_stored_stream_size_sum_overflow() {
    let encoded_size = usize::MAX as u64;
    let mut input = Vec::new();
    input.extend_from_slice(&magic(21));
    input.push(0);
    input.push(1);
    input.push(1);
    input.push(1);
    input.push(2);
    push_var_u64(&mut input, encoded_size);
    push_var_u64(&mut input, encoded_size);
    let mut limits = Limits::default();
    limits.max_stored_stream_bytes = usize::MAX;
    limits.max_buffer_bytes = usize::MAX;
    limits.max_decoded_bytes = usize::MAX;

    let err = inspect_frame(&input, limits).unwrap_err();

    assert_eq!(err.kind(), ErrorKind::IntegerOverflow);
}

#[test]
fn parses_v25_bundle_id() {
    let mut input = Vec::new();
    input.extend_from_slice(&magic(25));
    input.push(1 << 3);
    input.push(2);
    input.extend_from_slice(&[1, 2]);
    input.push(1);
    input.push(4);
    input.push(0);

    let info = inspect_frame(&input, Limits::default()).unwrap();

    assert_eq!(info.dictionary_bundle_id.as_deref(), Some(&[1, 2][..]));
}

#[test]
fn parses_v22_comment() {
    let mut input = Vec::new();
    input.extend_from_slice(&magic(22));
    input.push(1 << 2);
    input.push(1);
    input.push(4);
    input.push(3);
    input.extend_from_slice(b"abc");
    input.push(0);

    let info = inspect_frame(&input, Limits::default()).unwrap();

    assert!(info.has_comment);
    assert_eq!(info.comment.as_deref(), Some(b"abc".as_slice()));
    assert_eq!(info.header_bytes, input.len() - 1);
}

#[test]
fn rejects_zero_length_comment() {
    let mut input = Vec::new();
    input.extend_from_slice(&magic(22));
    input.push(1 << 2);
    input.push(1);
    input.push(4);
    input.push(0);

    let err = inspect_frame(&input, Limits::default()).unwrap_err();

    assert_eq!(err.kind(), ErrorKind::Malformed);
}

#[test]
fn rejects_zero_length_bundle_id() {
    let mut input = Vec::new();
    input.extend_from_slice(&magic(25));
    input.push(1 << 3);
    input.push(0);

    let err = inspect_frame(&input, Limits::default()).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::Malformed);
}

#[test]
fn rejects_all_zero_bundle_id() {
    let mut input = Vec::new();
    input.extend_from_slice(&magic(25));
    input.push(1 << 3);
    input.push(2);
    input.extend_from_slice(&[0, 0]);

    let err = inspect_frame(&input, Limits::default()).unwrap_err();

    assert_eq!(err.kind(), ErrorKind::Malformed);
}

#[test]
fn rejects_oversized_bundle_id() {
    let mut input = Vec::new();
    input.extend_from_slice(&magic(25));
    input.push(1 << 3);
    input.push(33);

    let err = inspect_frame(&input, Limits::default()).unwrap_err();

    assert_eq!(err.kind(), ErrorKind::Malformed);
}

#[test]
fn rejects_dict_index_bit_width_above_bundle_limit_encoding() {
    let mut input = Vec::new();
    input.extend_from_slice(&magic(25));
    input.push(1 << 3);
    input.push(1);
    input.push(1);
    input.push(1);
    input.push(4);
    input.push(2);
    input.push(1);
    input.push(0);
    input.push(22);
    input.push(0);
    input.push(0);
    input.push(0);
    input.push(1);
    input.push(17);

    let err = inspect_frame(&input, Limits::default()).unwrap_err();

    assert_eq!(err.kind(), ErrorKind::Malformed);
}

#[test]
fn rejects_committed_section_truncations_in_representative_frames() {
    let stored = {
        let mut input = Vec::new();
        input.extend_from_slice(&magic(21));
        input.push(0);
        input.push(1);
        input.push(4);
        input.push(1);
        input.push(1);
        input.push(3);
        input.extend_from_slice(&[1, 2, 3]);
        input.push(0);
        input
    };
    let transform = {
        let mut input = Vec::new();
        input.extend_from_slice(&magic(21));
        input.push(0);
        input.push(1);
        input.push(4);
        input.push(2);
        input.push(1);
        input.push(0);
        input.push(22);
        input.push(0);
        input.push(0);
        input.push(0);
        input.push(0);
        input.push(3);
        input.extend_from_slice(&[1, 2, 3]);
        input.push(0);
        input
    };
    let comment = {
        let mut input = Vec::new();
        input.extend_from_slice(&magic(22));
        input.push(1 << 2);
        input.push(1);
        input.push(4);
        input.push(3);
        input.extend_from_slice(b"abc");
        input.push(0);
        input
    };
    let bundle = {
        let mut input = Vec::new();
        input.extend_from_slice(&magic(25));
        input.push(1 << 3);
        input.push(2);
        input.extend_from_slice(&[1, 2]);
        input.push(1);
        input.push(4);
        input.push(0);
        input
    };
    #[allow(unused_mut)]
    let mut frames = vec![(stored, 8), (transform, 8)];
    #[cfg(feature = "checksum")]
    {
        let mut input = Vec::new();
        input.extend_from_slice(&magic(21));
        input.push(1 << 1);
        input.push(1);
        input.push(4);
        let header_checksum = (xxhash_rust::xxh3::xxh3_64(&input) & 0xff) as u8;
        input.push(header_checksum);
        input.push(1);
        input.push(1);
        input.push(3);
        input.extend_from_slice(&[1, 2, 3]);
        let checksum_start = 8;
        let checksum = (xxhash_rust::xxh3::xxh3_64(&input[checksum_start..]) & 0xffff_ffff) as u32;
        input.extend_from_slice(&checksum.to_le_bytes());
        input.push(0);
        frames.push((input, 9));
    }

    for (input, first_truncated_len) in frames {
        inspect_frame(&input, Limits::default()).unwrap();
        assert_truncations_fail(&input, first_truncated_len);
    }

    inspect_frame(&comment, Limits::default()).unwrap();
    let err = inspect_frame(&comment[..comment.len() - 1], Limits::default()).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::Truncated);

    inspect_frame(&bundle, Limits::default()).unwrap();
    let err = inspect_frame(&bundle[..bundle.len() - 1], Limits::default()).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::Truncated);
}

#[test]
fn enforces_frame_limit_before_parsing() {
    let mut limits = Limits::default();
    limits.max_frame_bytes = 1;
    let err = inspect_frame(&[0; 2], limits).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::LimitExceeded);
}

#[cfg(feature = "checksum")]
#[test]
fn verifies_v21_header_checksum() {
    let mut input = Vec::new();
    input.extend_from_slice(&magic(21));
    input.push(1 << 1);
    input.push(1);
    input.push(4);
    let checksum = (xxhash_rust::xxh3::xxh3_64(&input) & 0xff) as u8;
    input.push(checksum);
    input.push(0);

    let info = inspect_frame(&input, Limits::default()).unwrap();

    assert!(info.has_encoded_checksum);
    assert_eq!(info.header_bytes, input.len() - 1);
}

#[cfg(feature = "checksum")]
#[test]
fn rejects_bad_v21_header_checksum() {
    let mut input = Vec::new();
    input.extend_from_slice(&magic(21));
    input.push(1 << 1);
    input.push(1);
    input.push(4);
    input.push(0);

    let err = inspect_frame(&input, Limits::default()).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::ChecksumMismatch);
}
