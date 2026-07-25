use super::*;
use crate::parse::parse_frame_plan;
use alloc::vec;

const MAGIC_BASE: u32 = 0xd7b1_a5c0;

fn magic(version: u32) -> [u8; 4] {
    (MAGIC_BASE + version).to_le_bytes()
}

fn push_var_u64(out: &mut Vec<u8>, mut value: u64) {
    while value >= 0x80 {
        out.push(u8::try_from(value & 0x7f).unwrap() | 0x80);
        value >>= 7;
    }
    out.push(u8::try_from(value).unwrap());
}

fn lz4_serial_frame(stored: &[u8], decoded_len: usize) -> Vec<u8> {
    let mut transform_header = Vec::new();
    push_var_u64(&mut transform_header, u64::try_from(decoded_len).unwrap());
    let mut input = Vec::new();
    input.extend_from_slice(&magic(23));
    input.push(0);
    input.push(1);
    push_var_u64(&mut input, u64::try_from(decoded_len + 1).unwrap());
    input.push(2);
    input.push(1);
    input.push(0);
    input.push(62);
    input.push(1);
    push_var_u64(
        &mut input,
        u64::try_from(transform_header.len() - 1).unwrap(),
    );
    input.push(0);
    input.push(0);
    input.push(0);
    push_var_u64(&mut input, u64::try_from(stored.len()).unwrap());
    input.extend_from_slice(&transform_header);
    input.extend_from_slice(stored);
    input.push(0);
    input
}

fn standard_transform_serial_frame(
    version: u32,
    transform_id: u8,
    stored: &[u8],
    decoded_len: usize,
    transform_header: &[u8],
) -> Vec<u8> {
    let mut input = Vec::new();
    input.extend_from_slice(&magic(version));
    input.push(0);
    input.push(1);
    push_var_u64(&mut input, u64::try_from(decoded_len + 1).unwrap());
    append_standard_transform_chunk(&mut input, transform_id, stored, transform_header);
    input.push(0);
    input
}

fn append_standard_transform_chunk(
    input: &mut Vec<u8>,
    transform_id: u8,
    stored: &[u8],
    transform_header: &[u8],
) {
    input.push(2);
    input.push(1);
    input.push(0);
    input.push(transform_id);
    if transform_header.is_empty() {
        input.push(0);
    } else {
        input.push(1);
        push_var_u64(input, u64::try_from(transform_header.len() - 1).unwrap());
    }
    input.push(0);
    input.push(0);
    input.push(0);
    push_var_u64(input, u64::try_from(stored.len()).unwrap());
    input.extend_from_slice(transform_header);
    input.extend_from_slice(stored);
}

fn concat_serial_frame(payload: &[u8]) -> Vec<u8> {
    let size_stream = u32::try_from(payload.len()).unwrap().to_le_bytes();
    let mut input = Vec::new();
    input.extend_from_slice(&magic(21));
    input.push(0);
    input.push(1);
    push_var_u64(&mut input, u64::try_from(payload.len() + 1).unwrap());
    input.push(2);
    input.push(2);
    input.push(0);
    input.push(55);
    input.push(0);
    input.push(0);
    input.push(0);
    input.push(0);
    push_var_u64(&mut input, u64::try_from(payload.len()).unwrap());
    input.push(4);
    input.extend_from_slice(payload);
    input.extend_from_slice(&size_stream);
    input.push(0);
    input
}

fn splitn_serial_frame(streams: &[&[u8]]) -> Vec<u8> {
    let decoded_len = streams.iter().map(|stream| stream.len()).sum::<usize>();
    let mut input = Vec::new();
    input.extend_from_slice(&magic(21));
    input.push(0);
    input.push(1);
    push_var_u64(&mut input, u64::try_from(decoded_len + 1).unwrap());
    input.push(2);
    push_var_u64(&mut input, u64::try_from(streams.len()).unwrap());
    input.push(0);
    input.push(40);
    input.push(0);
    if streams.is_empty() {
        input.push(0);
    } else {
        input.push(1);
        push_var_u64(&mut input, u64::try_from(streams.len() - 1).unwrap());
    }
    input.push(0);
    if !streams.is_empty() {
        input.push(0);
    }
    for stream in streams.iter().rev() {
        push_var_u64(&mut input, u64::try_from(stream.len()).unwrap());
    }
    for stream in streams.iter().rev() {
        input.extend_from_slice(stream);
    }
    input.push(0);
    input
}

fn zstd_serial_frame(stored: &[u8], decoded_len: usize) -> Vec<u8> {
    standard_transform_serial_frame(21, 22, stored, decoded_len, &[])
}

#[cfg(feature = "zstd")]
fn zstd_stored_stream(decoded: &[u8]) -> Vec<u8> {
    let compressed = zrip::compress(decoded, 1).unwrap();
    let mut stored = Vec::new();
    push_var_u64(&mut stored, 1);
    stored.extend_from_slice(&compressed[4..]);
    stored
}

#[cfg(feature = "zstd")]
fn mixed_direct_append_frame() -> Vec<u8> {
    let zstd_output = b"zstd";
    let zstd_stored = zstd_stored_stream(zstd_output);
    let mut constant_header = Vec::new();
    push_var_u64(&mut constant_header, 3);

    let mut input = Vec::new();
    input.extend_from_slice(&magic(21));
    input.push(0);
    input.push(1);
    push_var_u64(
        &mut input,
        u64::try_from(zstd_output.len() + 3 + 1).unwrap(),
    );
    append_standard_transform_chunk(&mut input, 22, &zstd_stored, &[]);
    append_standard_transform_chunk(&mut input, 44, b"!", &constant_header);
    input.push(0);
    input
}

#[cfg(feature = "dev-format")]
fn pivco_huffman_frame() -> Vec<u8> {
    let mut input = Vec::new();
    input.extend_from_slice(&magic(27));
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

fn bitpack_serial_frame(values: &[u8], bits: u8) -> Vec<u8> {
    let stored = pack_lsb_bits(values, bits);
    let max_elements = (stored.len() * 8) / usize::from(bits);
    let extra = max_elements - values.len();
    let mut header = vec![bits - 1];
    if extra != 0 {
        header.push(u8::try_from(extra).unwrap());
    }
    standard_transform_serial_frame(21, 27, &stored, values.len(), &header)
}

fn bitpack_int_frame(values: &[u64], bits: u8, element_width: u8) -> Vec<u8> {
    let stored = pack_lsb_values(values, bits);
    let max_elements = (stored.len() * 8) / usize::from(bits);
    let extra = max_elements - values.len();
    let width_log = match element_width {
        1 => 0,
        2 => 1,
        4 => 2,
        8 => 3,
        _ => panic!("invalid element width"),
    };
    let mut header = vec![(width_log << 6) | (bits - 1)];
    if extra != 0 {
        header.push(u8::try_from(extra).unwrap());
    }
    standard_transform_serial_frame(
        21,
        28,
        &stored,
        values.len() * usize::from(element_width),
        &header,
    )
}

fn bitunpack_serial_frame(values: &[u8], bits: u8, trailing_bits: Option<u8>) -> Vec<u8> {
    let mut header = vec![bits];
    if let Some(trailing_bits) = trailing_bits {
        header.push(trailing_bits);
    }
    let decoded_len = (values.len() * usize::from(bits)).div_ceil(8);
    standard_transform_serial_frame(21, 34, values, decoded_len, &header)
}

fn range_pack_serial_frame(values: &[u8], min_value: Option<u8>) -> Vec<u8> {
    let mut header = vec![1];
    if let Some(min_value) = min_value {
        header.push(min_value);
    }
    standard_transform_serial_frame(21, 35, values, values.len(), &header)
}

fn constant_serial_frame(value: u8, count: usize) -> Vec<u8> {
    let mut header = Vec::new();
    push_var_u64(&mut header, u64::try_from(count).unwrap());
    standard_transform_serial_frame(21, 44, &[value], count, &header)
}

fn zigzag_serial_frame(stored: &[u8]) -> Vec<u8> {
    standard_transform_serial_frame(21, 3, stored, stored.len(), &[])
}

fn delta_serial_frame(first: Option<u8>, deltas: &[u8]) -> Vec<u8> {
    let header = first.map_or_else(Vec::new, |value| vec![value]);
    let decoded_len = deltas.len() + usize::from(first.is_some());
    standard_transform_serial_frame(21, 1, deltas, decoded_len, &header)
}

fn zigzag_delta_graph_frame(zigzag_encoded_deltas: &[u8], first: u8) -> Vec<u8> {
    let decoded_len = zigzag_encoded_deltas.len() + 1;
    let mut input = Vec::new();
    input.extend_from_slice(&magic(21));
    input.push(0);
    input.push(1);
    push_var_u64(&mut input, u64::try_from(decoded_len + 1).unwrap());
    input.push(3);
    input.push(1);
    input.push(0);
    input.extend_from_slice(&[67, 0]);
    input.push(2);
    input.push(0);
    input.push(0);
    input.push(0);
    input.push(0);
    push_var_u64(
        &mut input,
        u64::try_from(zigzag_encoded_deltas.len()).unwrap(),
    );
    input.push(first);
    input.extend_from_slice(zigzag_encoded_deltas);
    input.push(0);
    input
}

fn flatpack_serial_frame(alphabet: &[u8], indexes: &[u8]) -> Vec<u8> {
    let packed = pack_flatpack_indexes(alphabet.len(), indexes);
    let mut input = Vec::new();
    input.extend_from_slice(&magic(21));
    input.push(0);
    input.push(1);
    push_var_u64(&mut input, u64::try_from(indexes.len() + 1).unwrap());
    input.push(2);
    input.push(2);
    input.push(0);
    input.push(29);
    input.push(0);
    input.push(0);
    input.push(0);
    input.push(0);
    push_var_u64(&mut input, u64::try_from(packed.len()).unwrap());
    push_var_u64(&mut input, u64::try_from(alphabet.len()).unwrap());
    input.extend_from_slice(&packed);
    input.extend_from_slice(alphabet);
    input.push(0);
    input
}

fn transpose_split_frame(width: usize, lanes: &[&[u8]]) -> Vec<u8> {
    let decoded_len = lanes.first().map_or(0, |lane| lane.len() * width);
    let transform_id = match width {
        2 => 30,
        4 => 31,
        8 => 32,
        _ => unreachable!(),
    };
    let mut input = Vec::new();
    input.extend_from_slice(&magic(21));
    input.push(0);
    input.push(1);
    push_var_u64(&mut input, u64::try_from(decoded_len + 1).unwrap());
    input.push(2);
    push_var_u64(&mut input, u64::try_from(lanes.len()).unwrap());
    input.push(0);
    input.push(transform_id);
    input.push(0);
    input.push(0);
    input.push(0);
    input.push(0);
    for lane in lanes.iter().rev() {
        push_var_u64(&mut input, u64::try_from(lane.len()).unwrap());
    }
    for lane in lanes.iter().rev() {
        input.extend_from_slice(lane);
    }
    input.push(0);
    input
}

fn dynamic_transpose_split_frame(lanes: &[&[u8]]) -> Vec<u8> {
    let decoded_len = lanes.first().map_or(0, |lane| lane.len() * lanes.len());
    let mut input = Vec::new();
    input.extend_from_slice(&magic(21));
    input.push(0);
    input.push(1);
    push_var_u64(&mut input, u64::try_from(decoded_len + 1).unwrap());
    input.push(2);
    push_var_u64(&mut input, u64::try_from(lanes.len()).unwrap());
    input.push(0);
    input.push(4);
    input.push(0);
    if lanes.is_empty() {
        input.push(0);
    } else {
        input.push(1);
        push_var_u64(&mut input, u64::try_from(lanes.len() - 1).unwrap());
    }
    input.push(0);
    if !lanes.is_empty() {
        input.push(0);
    }
    for lane in lanes.iter().rev() {
        push_var_u64(&mut input, u64::try_from(lane.len()).unwrap());
    }
    for lane in lanes.iter().rev() {
        input.extend_from_slice(lane);
    }
    input.push(0);
    input
}

fn pack_flatpack_indexes(alphabet_len: usize, indexes: &[u8]) -> Vec<u8> {
    if indexes.is_empty() || alphabet_len == 0 {
        return Vec::new();
    }
    let bits = if alphabet_len <= 1 {
        alphabet_len
    } else {
        usize::BITS as usize - (alphabet_len - 1).leading_zeros() as usize
    };
    let packed_len = 1 + (bits * indexes.len()) / 8;
    let mut packed = vec![0; packed_len];
    let mut bit_offset = 0usize;
    for &index in indexes {
        let byte_offset = bit_offset / 8;
        let bit_shift = bit_offset % 8;
        let lane = u16::from(index) << bit_shift;
        let lane_bytes = lane.to_le_bytes();
        packed[byte_offset] |= lane_bytes[0];
        if bit_shift + bits > 8 {
            packed[byte_offset + 1] |= lane_bytes[1];
        }
        bit_offset += bits;
    }
    let byte_offset = bit_offset / 8;
    let bit_shift = bit_offset % 8;
    packed[byte_offset] |= 1 << bit_shift;
    packed
}

fn pack_lsb_bits(values: &[u8], bits: u8) -> Vec<u8> {
    let values = values.iter().copied().map(u64::from).collect::<Vec<_>>();
    pack_lsb_values(&values, bits)
}

fn pack_lsb_values(values: &[u64], bits: u8) -> Vec<u8> {
    let bits = usize::from(bits);
    let packed_len = (values.len() * bits).div_ceil(8);
    let mut output = vec![0; packed_len];
    let mask = if bits == 64 {
        u64::MAX
    } else {
        (1u64 << bits) - 1
    };
    for (index, &value) in values.iter().enumerate() {
        let bit_offset = index * bits;
        let byte_offset = bit_offset / 8;
        let bit_shift = bit_offset % 8;
        let lane = u128::from(value & mask) << bit_shift;
        let lane_bytes = lane.to_le_bytes();
        let byte_count = (bit_shift + bits).div_ceil(8);
        for byte_index in 0..byte_count {
            output[byte_offset + byte_index] |= lane_bytes[byte_index];
        }
    }
    output
}

#[test]
fn supported_standard_nodes_have_decode_coverage() {
    let mut supported = vec![
        standard::BITPACK_SERIAL_ID,
        standard::BITPACK_INT_ID,
        standard::BIT_SPLIT_ID,
        standard::BITUNPACK_ID,
        standard::CONCAT_SERIAL_ID,
        standard::CONCAT_NUM_ID,
        standard::CONCAT_STRUCT_ID,
        standard::CONSTANT_SERIAL_ID,
        standard::CONVERT_NUM_TO_SERIAL_LE_ID,
        standard::CONVERT_NUM_TO_STRUCT_LE_ID,
        standard::CONVERT_SERIAL_TO_NUM_BE_ID,
        standard::CONVERT_SERIAL_TO_NUM_LE_ID,
        standard::CONVERT_SERIAL_TO_STRUCT_ID,
        standard::CONVERT_STRING_TO_SERIAL_ID,
        standard::CONVERT_STRUCT_TO_NUM_BE_ID,
        standard::CONVERT_STRUCT_TO_NUM_LE_ID,
        standard::CONVERT_STRUCT_TO_SERIAL_ID,
        standard::DELTA_INT_ID,
        standard::DISPATCH_N_BY_TAG_ID,
        standard::DISPATCH_STRING_ID,
        standard::FIELD_LZ_ID,
        standard::FSE_V2_ID,
        standard::FSE_NCOUNT_ID,
        standard::HUFFMAN_V2_ID,
        standard::FLATPACK_ID,
        standard::LZ_ID,
        standard::MUX_LENGTHS_ID,
        standard::PARTITION_ID,
        standard::PARSE_INT_ID,
        standard::QUANTIZE_LENGTHS_ID,
        standard::QUANTIZE_OFFSETS_ID,
        standard::RANGE_PACK_ID,
        standard::SENTINEL_ID,
        standard::SEPARATE_STRING_COMPONENTS_ID,
        standard::SPARSE_NUM_ID,
        standard::SPLITN_ID,
        standard::SPLITN_STRUCT_ID,
        standard::SPLIT_BY_STRUCT_ID,
        standard::TOKENIZE_FIXED_ID,
        standard::TOKENIZE_NUMERIC_ID,
        standard::TRANSPOSE_SPLIT_ID,
        standard::TRANSPOSE_SPLIT2_ID,
        standard::TRANSPOSE_SPLIT4_ID,
        standard::TRANSPOSE_SPLIT8_ID,
        standard::ZIGZAG_ID,
    ];
    #[cfg(feature = "lz4")]
    supported.push(standard::LZ4_ID);
    #[cfg(feature = "zstd")]
    supported.push(standard::ZSTD_ID);

    let mut covered = vec![
        standard::BITPACK_SERIAL_ID,
        standard::BITPACK_INT_ID,
        standard::BIT_SPLIT_ID,
        standard::BITUNPACK_ID,
        standard::CONCAT_SERIAL_ID,
        standard::CONCAT_NUM_ID,
        standard::CONCAT_STRUCT_ID,
        standard::CONSTANT_SERIAL_ID,
        standard::CONVERT_NUM_TO_SERIAL_LE_ID,
        standard::CONVERT_NUM_TO_STRUCT_LE_ID,
        standard::CONVERT_SERIAL_TO_NUM_BE_ID,
        standard::CONVERT_SERIAL_TO_NUM_LE_ID,
        standard::CONVERT_SERIAL_TO_STRUCT_ID,
        standard::CONVERT_STRING_TO_SERIAL_ID,
        standard::CONVERT_STRUCT_TO_NUM_BE_ID,
        standard::CONVERT_STRUCT_TO_NUM_LE_ID,
        standard::CONVERT_STRUCT_TO_SERIAL_ID,
        standard::DELTA_INT_ID,
        standard::DISPATCH_N_BY_TAG_ID,
        standard::DISPATCH_STRING_ID,
        standard::FIELD_LZ_ID,
        standard::FSE_V2_ID,
        standard::FSE_NCOUNT_ID,
        standard::HUFFMAN_V2_ID,
        standard::FLATPACK_ID,
        standard::LZ_ID,
        standard::MUX_LENGTHS_ID,
        standard::PARTITION_ID,
        standard::PARSE_INT_ID,
        standard::QUANTIZE_LENGTHS_ID,
        standard::QUANTIZE_OFFSETS_ID,
        standard::RANGE_PACK_ID,
        standard::SENTINEL_ID,
        standard::SEPARATE_STRING_COMPONENTS_ID,
        standard::SPARSE_NUM_ID,
        standard::SPLITN_ID,
        standard::SPLITN_STRUCT_ID,
        standard::SPLIT_BY_STRUCT_ID,
        standard::TOKENIZE_FIXED_ID,
        standard::TOKENIZE_NUMERIC_ID,
        standard::TRANSPOSE_SPLIT_ID,
        standard::TRANSPOSE_SPLIT2_ID,
        standard::TRANSPOSE_SPLIT4_ID,
        standard::TRANSPOSE_SPLIT8_ID,
        standard::ZIGZAG_ID,
    ];
    #[cfg(feature = "lz4")]
    covered.push(standard::LZ4_ID);
    #[cfg(feature = "zstd")]
    covered.push(standard::ZSTD_ID);

    supported.sort_unstable();
    covered.sort_unstable();
    assert_eq!(supported, covered);
}

#[test]
fn decodes_v21_stored_serial_output() {
    let mut input = Vec::new();
    input.extend_from_slice(&magic(21));
    input.push(0);
    input.push(1);
    input.push(4);
    input.push(1);
    input.push(1);
    input.push(3);
    input.extend_from_slice(&[7, 8, 9]);
    input.push(0);
    let plan = parse_frame_plan(&input, Limits::default()).unwrap();
    let mut output = Vec::new();

    let written = decode_plan(&input, &plan, &mut output, Limits::default()).unwrap();

    assert_eq!(written, 3);
    assert_eq!(output, [7, 8, 9]);
}

#[test]
fn decodes_empty_v21_stored_serial_output() {
    let mut input = Vec::new();
    input.extend_from_slice(&magic(21));
    input.push(0);
    input.push(1);
    input.push(1);
    input.push(0);
    let plan = parse_frame_plan(&input, Limits::default()).unwrap();
    let mut output = vec![1, 2];

    let written = decode_plan(&input, &plan, &mut output, Limits::default()).unwrap();

    assert_eq!(written, 0);
    assert_eq!(output, [1, 2]);
}

#[test]
fn decodes_v21_stored_serial_chunks() {
    let mut input = Vec::new();
    input.extend_from_slice(&magic(21));
    input.push(0);
    input.push(1);
    input.push(8);
    input.push(1);
    input.push(1);
    input.push(3);
    input.extend_from_slice(&[7, 8, 9]);
    input.push(1);
    input.push(1);
    input.push(4);
    input.extend_from_slice(&[10, 11, 12, 13]);
    input.push(0);
    let plan = parse_frame_plan(&input, Limits::default()).unwrap();
    let mut output = Vec::new();

    let written = decode_plan(&input, &plan, &mut output, Limits::default()).unwrap();

    assert_eq!(written, 7);
    assert_eq!(output, [7, 8, 9, 10, 11, 12, 13]);
}

#[cfg(feature = "zstd")]
#[test]
fn prepares_mixed_direct_append_chunk_plans() {
    let input = mixed_direct_append_frame();
    let plan = parse_frame_plan(&input, Limits::default()).unwrap();

    let plans = prepare_direct_append_chunk_plans(&plan).unwrap().unwrap();

    assert_eq!(plans.chunk_plans.len(), 2);
    assert!(plans.chunk_plans[0].is_some());
    assert!(plans.chunk_plans[1].is_none());
}

#[cfg(feature = "zstd")]
#[test]
fn decodes_mixed_direct_append_and_fallback_chunks() {
    let input = mixed_direct_append_frame();
    let plan = parse_frame_plan(&input, Limits::default()).unwrap();
    let mut output = Vec::new();

    let written = decode_plan(&input, &plan, &mut output, Limits::default()).unwrap();

    assert_eq!(written, 7);
    assert_eq!(output, b"zstd!!!");
}

#[test]
fn decodes_v21_concat_serial_chunk() {
    let input = concat_serial_frame(b"openzl concat");
    let plan = parse_frame_plan(&input, Limits::default()).unwrap();
    let mut output = Vec::new();

    let written = decode_plan(&input, &plan, &mut output, Limits::default()).unwrap();

    assert_eq!(written, 13);
    assert_eq!(output, b"openzl concat");
}

#[test]
fn decodes_concat_typed_outputs() {
    let outputs = decode_concat_node(
        &[
            StreamInput {
                bytes: &[2, 0, 0, 0, 1, 0, 0, 0],
                element_width: 4,
                string_lengths: None,
            },
            StreamInput {
                bytes: &[1, 0, 2, 0, 3, 0],
                element_width: 2,
                string_lengths: None,
            },
        ],
        &[],
        Limits::default(),
    )
    .unwrap();

    assert_eq!(outputs.len(), 2);
    assert_eq!(outputs[0].element_width, 2);
    assert_eq!(outputs[0].bytes, [1, 0, 2, 0]);
    assert_eq!(outputs[1].element_width, 2);
    assert_eq!(outputs[1].bytes, [3, 0]);
}

#[test]
fn rejects_concat_typed_size_mismatch() {
    let err = decode_concat_node(
        &[
            StreamInput {
                bytes: &[2, 0, 0, 0],
                element_width: 4,
                string_lengths: None,
            },
            StreamInput {
                bytes: &[1, 0, 2, 0, 3, 0],
                element_width: 2,
                string_lengths: None,
            },
        ],
        &[],
        Limits::default(),
    )
    .unwrap_err();

    assert_eq!(err.kind(), ErrorKind::Malformed);
}

#[test]
fn rejects_concat_serial_output_limit_without_mutating_destination() {
    let input = concat_serial_frame(b"openzl concat");
    let plan = parse_frame_plan(&input, Limits::default()).unwrap();
    let mut output = vec![1, 2];
    let limits = Limits {
        max_decoded_bytes: 8,
        max_buffer_bytes: 8,
        ..Limits::default()
    };

    let err = decode_plan(&input, &plan, &mut output, limits).unwrap_err();

    assert_eq!(err.kind(), ErrorKind::LimitExceeded);
    assert_eq!(output, [1, 2]);
}

#[test]
fn decodes_v21_splitn_serial_chunk() {
    let input = splitn_serial_frame(&[b"open", b"zl", b" splitn"]);
    let plan = parse_frame_plan(&input, Limits::default()).unwrap();
    let mut output = Vec::new();

    let written = decode_plan(&input, &plan, &mut output, Limits::default()).unwrap();

    assert_eq!(written, 13);
    assert_eq!(output, b"openzl splitn");
}

#[test]
fn decodes_empty_v21_splitn_serial_chunk() {
    let input = splitn_serial_frame(&[]);
    let plan = parse_frame_plan(&input, Limits::default()).unwrap();
    let mut output = vec![1, 2];

    let written = decode_plan(&input, &plan, &mut output, Limits::default()).unwrap();

    assert_eq!(written, 0);
    assert_eq!(output, [1, 2]);
}

#[test]
fn decodes_split_by_struct_node() {
    let output = decode_split_by_struct_node(
        &[
            StreamInput {
                bytes: &[1, 2],
                element_width: 1,
                string_lengths: None,
            },
            StreamInput {
                bytes: &[3, 0, 4, 0],
                element_width: 2,
                string_lengths: None,
            },
        ],
        2,
        &[],
        Limits::default(),
    )
    .unwrap();

    assert_eq!(output.element_width, 1);
    assert_eq!(output.bytes, [1, 3, 0, 2, 4, 0]);
}

#[test]
fn rejects_split_by_struct_mismatched_element_counts() {
    let err = decode_split_by_struct_node(
        &[
            StreamInput {
                bytes: &[1, 2],
                element_width: 1,
                string_lengths: None,
            },
            StreamInput {
                bytes: &[3, 0],
                element_width: 2,
                string_lengths: None,
            },
        ],
        2,
        &[],
        Limits::default(),
    )
    .unwrap_err();

    assert_eq!(err.kind(), ErrorKind::Malformed);
}

#[test]
fn decodes_dispatch_n_by_tag_node() {
    let output = decode_dispatch_n_by_tag_node(
        &[
            StreamInput {
                bytes: &[0, 1, 0],
                element_width: 1,
                string_lengths: None,
            },
            StreamInput {
                bytes: &[2, 3, 1],
                element_width: 1,
                string_lengths: None,
            },
            StreamInput {
                bytes: b"abc",
                element_width: 1,
                string_lengths: None,
            },
            StreamInput {
                bytes: b"XYZ",
                element_width: 1,
                string_lengths: None,
            },
        ],
        2,
        &[],
        21,
        Limits::default(),
    )
    .unwrap();

    assert_eq!(output, b"abXYZc");
}

#[test]
fn rejects_dispatch_n_by_tag_invalid_tag() {
    let err = decode_dispatch_n_by_tag_node(
        &[
            StreamInput {
                bytes: &[2],
                element_width: 1,
                string_lengths: None,
            },
            StreamInput {
                bytes: &[1],
                element_width: 1,
                string_lengths: None,
            },
            StreamInput {
                bytes: b"a",
                element_width: 1,
                string_lengths: None,
            },
        ],
        1,
        &[],
        21,
        Limits::default(),
    )
    .unwrap_err();

    assert_eq!(err.kind(), ErrorKind::Malformed);
}

#[test]
fn rejects_dispatch_n_by_tag_size_mismatch() {
    let err = decode_dispatch_n_by_tag_node(
        &[
            StreamInput {
                bytes: &[0],
                element_width: 1,
                string_lengths: None,
            },
            StreamInput {
                bytes: &[2],
                element_width: 1,
                string_lengths: None,
            },
            StreamInput {
                bytes: b"a",
                element_width: 1,
                string_lengths: None,
            },
        ],
        1,
        &[],
        21,
        Limits::default(),
    )
    .unwrap_err();

    assert_eq!(err.kind(), ErrorKind::Malformed);
}

#[test]
fn rejects_splitn_output_limit_without_mutating_destination() {
    let input = splitn_serial_frame(&[b"open", b"zl", b" splitn"]);
    let plan = parse_frame_plan(&input, Limits::default()).unwrap();
    let mut output = vec![1, 2];
    let limits = Limits {
        max_decoded_bytes: 8,
        max_buffer_bytes: 8,
        ..Limits::default()
    };

    let err = decode_plan(&input, &plan, &mut output, limits).unwrap_err();

    assert_eq!(err.kind(), ErrorKind::LimitExceeded);
    assert_eq!(output, [1, 2]);
}

#[test]
fn decodes_v21_bitpack_serial_chunk() {
    let expected = [0, 1, 2, 3, 4, 5, 6, 7, 1];
    let input = bitpack_serial_frame(&expected, 3);
    let plan = parse_frame_plan(&input, Limits::default()).unwrap();
    let mut output = Vec::new();

    let written = decode_plan(&input, &plan, &mut output, Limits::default()).unwrap();

    assert_eq!(written, expected.len());
    assert_eq!(output, expected);
}

#[test]
fn decodes_v21_full_width_bitpack_serial_chunk() {
    let expected = b"bitpack";
    let input = bitpack_serial_frame(expected, 8);
    let plan = parse_frame_plan(&input, Limits::default()).unwrap();
    let mut output = Vec::new();

    let written = decode_plan(&input, &plan, &mut output, Limits::default()).unwrap();

    assert_eq!(written, expected.len());
    assert_eq!(output, expected);
}

#[test]
fn decodes_v21_bitpack_int16_chunk() {
    let input = bitpack_int_frame(&[0, 1, 255, 256, 1023], 10, 2);
    let plan = parse_frame_plan(&input, Limits::default()).unwrap();
    let mut output = Vec::new();

    let written = decode_plan(&input, &plan, &mut output, Limits::default()).unwrap();

    assert_eq!(written, 10);
    assert_eq!(output, [0, 0, 1, 0, 255, 0, 0, 1, 255, 3]);
}

#[test]
fn decodes_mux_lengths_inline_u16() {
    let muxed = [0x21];
    let long = [];
    let outputs = decode_mux_lengths_node(
        &[
            StreamInput {
                bytes: &muxed,
                element_width: 1,
                string_lengths: None,
            },
            StreamInput {
                bytes: &long,
                element_width: 2,
                string_lengths: None,
            },
        ],
        &[0x24],
        Limits::default(),
    )
    .unwrap();

    assert_eq!(outputs.len(), 2);
    assert_eq!(outputs[0].bytes, [1, 0]);
    assert_eq!(outputs[1].bytes, [4, 0]);
    assert_eq!(outputs[0].element_width, 2);
    assert_eq!(outputs[1].element_width, 2);
}

#[test]
fn decodes_mux_lengths_overflow_u16() {
    let muxed = [0xff];
    let long = [5, 0, 2, 0];
    let outputs = decode_mux_lengths_node(
        &[
            StreamInput {
                bytes: &muxed,
                element_width: 1,
                string_lengths: None,
            },
            StreamInput {
                bytes: &long,
                element_width: 2,
                string_lengths: None,
            },
        ],
        &[0x24],
        Limits::default(),
    )
    .unwrap();

    assert_eq!(outputs[0].bytes, [20, 0]);
    assert_eq!(outputs[1].bytes, [19, 0]);
}

#[test]
fn rejects_mux_lengths_exhausted_long_stream() {
    let muxed = [0xff];
    let long = [5, 0];
    let err = decode_mux_lengths_node(
        &[
            StreamInput {
                bytes: &muxed,
                element_width: 1,
                string_lengths: None,
            },
            StreamInput {
                bytes: &long,
                element_width: 2,
                string_lengths: None,
            },
        ],
        &[0x24],
        Limits::default(),
    )
    .unwrap_err();

    assert_eq!(err.kind(), ErrorKind::Malformed);
}

#[test]
fn decodes_bitsplit_bf16_node() {
    let mantissas = [0x01, 0x7f];
    let exponents = [0x02, 0xff];
    let signs = [0x00, 0x01];
    let output = decode_bitsplit_node(
        &[
            StreamInput {
                bytes: &mantissas,
                element_width: 1,
                string_lengths: None,
            },
            StreamInput {
                bytes: &exponents,
                element_width: 1,
                string_lengths: None,
            },
            StreamInput {
                bytes: &signs,
                element_width: 1,
                string_lengths: None,
            },
        ],
        3,
        &[2, 7, 8],
        Limits::default(),
    )
    .unwrap();

    assert_eq!(output.element_width, 2);
    assert_eq!(output.bytes, [0x01, 0x01, 0xff, 0xff]);
}

#[test]
fn rejects_bitsplit_mismatched_input_width() {
    let input = [0u8; 2];
    let err = decode_bitsplit_node(
        &[StreamInput {
            bytes: &input,
            element_width: 1,
            string_lengths: None,
        }],
        1,
        &[2, 9],
        Limits::default(),
    )
    .unwrap_err();

    assert_eq!(err.kind(), ErrorKind::Malformed);
}

#[test]
fn decodes_lz_node_with_trailing_literals() {
    let literals = b"abc!";
    let offsets = 3u16.to_le_bytes();
    let literal_lengths = 3u16.to_le_bytes();
    let match_lengths = 3u16.to_le_bytes();
    let output = decode_lz_node(
        &[
            StreamInput {
                bytes: literals,
                element_width: 1,
                string_lengths: None,
            },
            StreamInput {
                bytes: &offsets,
                element_width: 2,
                string_lengths: None,
            },
            StreamInput {
                bytes: &literal_lengths,
                element_width: 2,
                string_lengths: None,
            },
            StreamInput {
                bytes: &match_lengths,
                element_width: 2,
                string_lengths: None,
            },
        ],
        &[7],
        Limits::default(),
    )
    .unwrap();

    assert_eq!(output, b"abcabc!");
}

#[test]
fn decodes_lz_node_with_overlapping_match() {
    let literals = b"a";
    let offsets = 1u16.to_le_bytes();
    let literal_lengths = 1u16.to_le_bytes();
    let match_lengths = 4u16.to_le_bytes();
    let output = decode_lz_node(
        &[
            StreamInput {
                bytes: literals,
                element_width: 1,
                string_lengths: None,
            },
            StreamInput {
                bytes: &offsets,
                element_width: 2,
                string_lengths: None,
            },
            StreamInput {
                bytes: &literal_lengths,
                element_width: 2,
                string_lengths: None,
            },
            StreamInput {
                bytes: &match_lengths,
                element_width: 2,
                string_lengths: None,
            },
        ],
        &[5],
        Limits::default(),
    )
    .unwrap();

    assert_eq!(output, b"aaaaa");
}

#[test]
fn decodes_field_lz_node_with_last_literals() {
    let mut scratch = DecodeScratch::new();
    let output = decode_field_lz_node(
        &[
            StreamInput {
                bytes: b"abcdef",
                element_width: 1,
                string_lengths: None,
            },
            StreamInput {
                bytes: &[],
                element_width: 2,
                string_lengths: None,
            },
            StreamInput {
                bytes: &[],
                element_width: 4,
                string_lengths: None,
            },
            StreamInput {
                bytes: &[],
                element_width: 4,
                string_lengths: None,
            },
            StreamInput {
                bytes: &[],
                element_width: 4,
                string_lengths: None,
            },
        ],
        &[6],
        Limits::default(),
        &mut scratch,
    )
    .unwrap();

    assert_eq!(output.element_width, 1);
    assert_eq!(output.bytes, b"abcdef");
}

#[test]
fn decodes_field_lz_node_with_explicit_offset() {
    let mut scratch = DecodeScratch::new();
    let token = 3u16 | (3u16 << 2);
    let offset = 3u32.to_le_bytes();
    let output = decode_field_lz_node(
        &[
            StreamInput {
                bytes: b"abc!",
                element_width: 1,
                string_lengths: None,
            },
            StreamInput {
                bytes: &token.to_le_bytes(),
                element_width: 2,
                string_lengths: None,
            },
            StreamInput {
                bytes: &offset,
                element_width: 4,
                string_lengths: None,
            },
            StreamInput {
                bytes: &[],
                element_width: 4,
                string_lengths: None,
            },
            StreamInput {
                bytes: &[],
                element_width: 4,
                string_lengths: None,
            },
        ],
        &[8],
        Limits::default(),
        &mut scratch,
    )
    .unwrap();

    assert_eq!(output.element_width, 1);
    assert_eq!(output.bytes, b"abcabca!");
}

#[test]
fn decodes_separate_string_components_node() {
    let field_sizes = [1u16.to_le_bytes(), 3u16.to_le_bytes()].concat();
    let output = decode_separate_string_components_node(
        &[
            StreamInput {
                bytes: b"abcd",
                element_width: 1,
                string_lengths: None,
            },
            StreamInput {
                bytes: &field_sizes,
                element_width: 2,
                string_lengths: None,
            },
        ],
        &[],
        Limits::default(),
    )
    .unwrap();

    assert_eq!(output.element_width, 1);
    assert_eq!(output.bytes, b"abcd");
    assert_eq!(output.string_lengths.as_deref(), Some([1, 3].as_slice()));
}

#[test]
fn rejects_separate_string_components_size_mismatch() {
    let field_sizes = [2u16.to_le_bytes(), 3u16.to_le_bytes()].concat();
    let err = decode_separate_string_components_node(
        &[
            StreamInput {
                bytes: b"abcd",
                element_width: 1,
                string_lengths: None,
            },
            StreamInput {
                bytes: &field_sizes,
                element_width: 2,
                string_lengths: None,
            },
        ],
        &[],
        Limits::default(),
    )
    .unwrap_err();

    assert_eq!(err.kind(), ErrorKind::Malformed);
}

#[test]
fn decodes_dispatch_string_node() {
    let indices = [
        0u16.to_le_bytes(),
        1u16.to_le_bytes(),
        0u16.to_le_bytes(),
        1u16.to_le_bytes(),
    ]
    .concat();
    let first_lengths = [1, 1];
    let second_lengths = [1, 1];

    let output = decode_dispatch_string_node(
        &[
            StreamInput {
                bytes: &indices,
                element_width: 2,
                string_lengths: None,
            },
            StreamInput {
                bytes: b"ab",
                element_width: 1,
                string_lengths: Some(&first_lengths),
            },
            StreamInput {
                bytes: b"XY",
                element_width: 1,
                string_lengths: Some(&second_lengths),
            },
        ],
        2,
        &[],
        21,
        Limits::default(),
    )
    .unwrap();

    assert_eq!(output.element_width, 1);
    assert_eq!(output.bytes, b"aXbY");
    assert_eq!(
        output.string_lengths.as_deref(),
        Some([1, 1, 1, 1].as_slice())
    );
}

#[test]
fn decodes_dispatch_string_csv_pattern_to_serial_output() {
    let row_pattern = [0u16, 4, 1, 4, 2, 4, 3, 4]
        .into_iter()
        .flat_map(u16::to_le_bytes)
        .collect::<Vec<_>>();
    let indices = [row_pattern.as_slice(), row_pattern.as_slice()].concat();
    let first_lengths = [2, 2];
    let second_lengths = [1, 2];
    let third_lengths = [2, 1];
    let fourth_lengths = [1, 3];
    let delimiter_lengths = [1; 8];
    let mut output = b"pre".to_vec();

    decode_dispatch_string_node_to_serial_output(
        &[
            StreamInput {
                bytes: &indices,
                element_width: 2,
                string_lengths: None,
            },
            StreamInput {
                bytes: b"aaBB",
                element_width: 1,
                string_lengths: Some(&first_lengths),
            },
            StreamInput {
                bytes: b"xYZ",
                element_width: 1,
                string_lengths: Some(&second_lengths),
            },
            StreamInput {
                bytes: b"12q",
                element_width: 1,
                string_lengths: Some(&third_lengths),
            },
            StreamInput {
                bytes: b"kLMN",
                element_width: 1,
                string_lengths: Some(&fourth_lengths),
            },
            StreamInput {
                bytes: b",,;\n,,;\n",
                element_width: 1,
                string_lengths: Some(&delimiter_lengths),
            },
        ],
        5,
        &[],
        21,
        Limits::default(),
        &mut output,
    )
    .unwrap();

    assert_eq!(output, b"preaa,x,12;k\nBB,YZ,q;LMN\n");
}

#[test]
fn decodes_dispatch_string_csv_header_pattern_to_serial_output() {
    let header_pattern = [5u16; 7]
        .into_iter()
        .flat_map(u16::to_le_bytes)
        .collect::<Vec<_>>();
    let row_pattern = [4u16, 0, 4, 1, 4, 2, 4, 3]
        .into_iter()
        .flat_map(u16::to_le_bytes)
        .collect::<Vec<_>>();
    let trailing_delimiter = 4u16.to_le_bytes();
    let indices = [
        header_pattern.as_slice(),
        row_pattern.as_slice(),
        row_pattern.as_slice(),
        trailing_delimiter.as_slice(),
    ]
    .concat();
    let first_lengths = [2, 2];
    let second_lengths = [1, 2];
    let third_lengths = [2, 1];
    let fourth_lengths = [1, 3];
    let delimiter_lengths = [1; 9];
    let header_lengths = [1; 7];
    let mut output = b"pre".to_vec();

    decode_dispatch_string_node_to_serial_output(
        &[
            StreamInput {
                bytes: &indices,
                element_width: 2,
                string_lengths: None,
            },
            StreamInput {
                bytes: b"aaBB",
                element_width: 1,
                string_lengths: Some(&first_lengths),
            },
            StreamInput {
                bytes: b"xYZ",
                element_width: 1,
                string_lengths: Some(&second_lengths),
            },
            StreamInput {
                bytes: b"12q",
                element_width: 1,
                string_lengths: Some(&third_lengths),
            },
            StreamInput {
                bytes: b"kLMN",
                element_width: 1,
                string_lengths: Some(&fourth_lengths),
            },
            StreamInput {
                bytes: b"\n,,;\n,,;\n",
                element_width: 1,
                string_lengths: Some(&delimiter_lengths),
            },
            StreamInput {
                bytes: b"ABCDEFG",
                element_width: 1,
                string_lengths: Some(&header_lengths),
            },
        ],
        6,
        &[],
        21,
        Limits::default(),
        &mut output,
    )
    .unwrap();

    assert_eq!(output, b"preABCDEFG\naa,x,12;k\nBB,YZ,q;LMN\n");
}

#[test]
fn decodes_dispatch_string_csv_wide_header_pattern_to_serial_output() {
    let header_pattern = [7u16; 11]
        .into_iter()
        .flat_map(u16::to_le_bytes)
        .collect::<Vec<_>>();
    let row_pattern = [6u16, 0, 6, 1, 6, 2, 6, 3, 6, 4, 6, 5]
        .into_iter()
        .flat_map(u16::to_le_bytes)
        .collect::<Vec<_>>();
    let trailing_delimiter = 6u16.to_le_bytes();
    let indices = [
        header_pattern.as_slice(),
        row_pattern.as_slice(),
        row_pattern.as_slice(),
        trailing_delimiter.as_slice(),
    ]
    .concat();
    let field_lengths = [[1, 2], [2, 1], [1, 1], [3, 1], [1, 2], [2, 3]];
    let delimiter_lengths = [1; 13];
    let header_lengths = [1; 11];
    let mut output = b"pre".to_vec();

    decode_dispatch_string_node_to_serial_output(
        &[
            StreamInput {
                bytes: &indices,
                element_width: 2,
                string_lengths: None,
            },
            StreamInput {
                bytes: b"aAA",
                element_width: 1,
                string_lengths: Some(&field_lengths[0]),
            },
            StreamInput {
                bytes: b"bbB",
                element_width: 1,
                string_lengths: Some(&field_lengths[1]),
            },
            StreamInput {
                bytes: b"cd",
                element_width: 1,
                string_lengths: Some(&field_lengths[2]),
            },
            StreamInput {
                bytes: b"eeeF",
                element_width: 1,
                string_lengths: Some(&field_lengths[3]),
            },
            StreamInput {
                bytes: b"gHH",
                element_width: 1,
                string_lengths: Some(&field_lengths[4]),
            },
            StreamInput {
                bytes: b"ijKLM",
                element_width: 1,
                string_lengths: Some(&field_lengths[5]),
            },
            StreamInput {
                bytes: b"\n,,,,,\n,,,,,\n",
                element_width: 1,
                string_lengths: Some(&delimiter_lengths),
            },
            StreamInput {
                bytes: b"A,B,C,D,E,F",
                element_width: 1,
                string_lengths: Some(&header_lengths),
            },
        ],
        8,
        &[],
        21,
        Limits::default(),
        &mut output,
    )
    .unwrap();

    assert_eq!(
        output,
        b"preA,B,C,D,E,F\na,bb,c,eee,g,ij\nAA,B,d,F,HH,KLM\n"
    );
}

#[test]
fn decodes_dispatch_string_pums_style_wide_header_pattern_to_serial_output() {
    const DATA_SOURCES: u16 = 78;
    let sources = usize::from(DATA_SOURCES);
    let delimiter_source = DATA_SOURCES;
    let header_source = DATA_SOURCES + 1;
    let header_fields = sources * 2 - 1;

    let mut indices = Vec::new();
    for _ in 0..header_fields {
        indices.extend_from_slice(&header_source.to_le_bytes());
    }
    for source in 0..DATA_SOURCES {
        indices.extend_from_slice(&delimiter_source.to_le_bytes());
        indices.extend_from_slice(&source.to_le_bytes());
    }
    indices.extend_from_slice(&delimiter_source.to_le_bytes());

    let field_lengths = vec![[2u32]; sources];
    let field_bytes = (0..sources)
        .map(|source| format!("{source:02}").into_bytes())
        .collect::<Vec<_>>();
    let delimiter_lengths = vec![1u32; sources + 1];
    let delimiter_bytes = {
        let mut bytes = Vec::with_capacity(sources + 1);
        bytes.push(b'\n');
        bytes.extend(core::iter::repeat_n(b',', sources - 1));
        bytes.push(b'\n');
        bytes
    };
    let header_lengths = vec![1u32; header_fields];
    let header_bytes = (0..header_fields)
        .map(|field| b'A' + u8::try_from(field % 26).unwrap())
        .collect::<Vec<_>>();

    let mut inputs = Vec::with_capacity(sources + 3);
    inputs.push(StreamInput {
        bytes: &indices,
        element_width: 2,
        string_lengths: None,
    });
    for source in 0..sources {
        inputs.push(StreamInput {
            bytes: &field_bytes[source],
            element_width: 1,
            string_lengths: Some(&field_lengths[source]),
        });
    }
    inputs.push(StreamInput {
        bytes: &delimiter_bytes,
        element_width: 1,
        string_lengths: Some(&delimiter_lengths),
    });
    inputs.push(StreamInput {
        bytes: &header_bytes,
        element_width: 1,
        string_lengths: Some(&header_lengths),
    });

    let mut expected = b"pre".to_vec();
    expected.extend_from_slice(&header_bytes);
    expected.push(b'\n');
    for (source, field) in field_bytes.iter().enumerate() {
        if source > 0 {
            expected.push(b',');
        }
        expected.extend_from_slice(field);
    }
    expected.push(b'\n');

    let mut output = b"pre".to_vec();
    decode_dispatch_string_node_to_serial_output(
        &inputs,
        u32::from(DATA_SOURCES) + 2,
        &[],
        21,
        Limits::default(),
        &mut output,
    )
    .unwrap();

    assert_eq!(output, expected);
}

#[test]
fn rejects_dispatch_string_invalid_source_index() {
    let indices = 2u16.to_le_bytes();
    let lengths = [1];
    let err = decode_dispatch_string_node(
        &[
            StreamInput {
                bytes: &indices,
                element_width: 2,
                string_lengths: None,
            },
            StreamInput {
                bytes: b"a",
                element_width: 1,
                string_lengths: Some(&lengths),
            },
        ],
        1,
        &[],
        21,
        Limits::default(),
    )
    .unwrap_err();

    assert_eq!(err.kind(), ErrorKind::Malformed);
}

#[test]
fn decodes_string_to_serial_node() {
    let lengths = [1, 3];
    let output = decode_string_to_serial_node(
        StreamInput {
            bytes: b"abcd",
            element_width: 1,
            string_lengths: Some(&lengths),
        },
        &[],
        Limits::default(),
    )
    .unwrap();

    assert_eq!(output, b"abcd");
}

#[test]
fn decodes_sentinel_node_with_default_marker() {
    let exceptions = 300u16.to_le_bytes();
    let output = decode_sentinel_node(
        &[
            StreamInput {
                bytes: &[1, 255, 2],
                element_width: 1,
                string_lengths: None,
            },
            StreamInput {
                bytes: &exceptions,
                element_width: 2,
                string_lengths: None,
            },
        ],
        &[],
        Limits::default(),
    )
    .unwrap();

    assert_eq!(output.element_width, 2);
    assert_eq!(output.bytes, [1, 0, 44, 1, 2, 0]);
}

#[test]
fn rejects_sentinel_unconsumed_exception() {
    let exceptions = [300u16.to_le_bytes(), 301u16.to_le_bytes()].concat();
    let err = decode_sentinel_node(
        &[
            StreamInput {
                bytes: &[1, 255, 2],
                element_width: 1,
                string_lengths: None,
            },
            StreamInput {
                bytes: &exceptions,
                element_width: 2,
                string_lengths: None,
            },
        ],
        &[],
        Limits::default(),
    )
    .unwrap_err();

    assert_eq!(err.kind(), ErrorKind::Malformed);
}

#[test]
fn rejects_bitpack_output_limit_without_mutating_destination() {
    let expected = [0, 1, 2, 3, 4, 5, 6, 7, 1];
    let input = bitpack_serial_frame(&expected, 3);
    let plan = parse_frame_plan(&input, Limits::default()).unwrap();
    let mut output = vec![1, 2];
    let limits = Limits {
        max_decoded_bytes: 4,
        max_buffer_bytes: 4,
        ..Limits::default()
    };

    let err = decode_plan(&input, &plan, &mut output, limits).unwrap_err();

    assert_eq!(err.kind(), ErrorKind::LimitExceeded);
    assert_eq!(output, [1, 2]);
}

#[test]
fn decodes_v21_bitunpack_serial8_chunk() {
    let input = bitunpack_serial_frame(&[2, 7, 3, 4, 5, 1, 7, 6], 3, None);
    let plan = parse_frame_plan(&input, Limits::default()).unwrap();
    let mut output = Vec::new();

    let written = decode_plan(&input, &plan, &mut output, Limits::default()).unwrap();

    assert_eq!(written, 3);
    assert_eq!(output, [0xfa, 0xd8, 0xdc]);
}

#[test]
fn decodes_v21_bitunpack_serial8_trailing_bits() {
    let input = bitunpack_serial_frame(&[1], 3, Some(0b1_1111));
    let plan = parse_frame_plan(&input, Limits::default()).unwrap();
    let mut output = Vec::new();

    let written = decode_plan(&input, &plan, &mut output, Limits::default()).unwrap();

    assert_eq!(written, 1);
    assert_eq!(output, [0b1111_1001]);
}

#[test]
fn rejects_bitunpack_value_overflow_without_mutating_destination() {
    let input = bitunpack_serial_frame(&[8], 3, None);
    let plan = parse_frame_plan(&input, Limits::default()).unwrap();
    let mut output = vec![1, 2];

    let err = decode_plan(&input, &plan, &mut output, Limits::default()).unwrap_err();

    assert_eq!(err.kind(), ErrorKind::Malformed);
    assert_eq!(output, [1, 2]);
}

#[test]
fn rejects_bitunpack_output_limit_without_mutating_destination() {
    let input = bitunpack_serial_frame(&[2, 7, 3, 4, 5, 1, 7, 6], 3, None);
    let plan = parse_frame_plan(&input, Limits::default()).unwrap();
    let mut output = vec![1, 2];
    let limits = Limits {
        max_decoded_bytes: 2,
        max_buffer_bytes: 2,
        ..Limits::default()
    };

    let err = decode_plan(&input, &plan, &mut output, limits).unwrap_err();

    assert_eq!(err.kind(), ErrorKind::LimitExceeded);
    assert_eq!(output, [1, 2]);
}

#[test]
fn decodes_v21_range_pack_serial8_chunk() {
    let input = range_pack_serial_frame(&[0, 1, 5], Some(10));
    let plan = parse_frame_plan(&input, Limits::default()).unwrap();
    let mut output = Vec::new();

    let written = decode_plan(&input, &plan, &mut output, Limits::default()).unwrap();

    assert_eq!(written, 3);
    assert_eq!(output, [10, 11, 15]);
}

#[test]
fn decodes_v21_range_pack_serial8_without_minimum() {
    let input = range_pack_serial_frame(&[0, 1, 5], None);
    let plan = parse_frame_plan(&input, Limits::default()).unwrap();
    let mut output = Vec::new();

    let written = decode_plan(&input, &plan, &mut output, Limits::default()).unwrap();

    assert_eq!(written, 3);
    assert_eq!(output, [0, 1, 5]);
}

#[test]
fn rejects_range_pack_overflow_without_mutating_destination() {
    let input = range_pack_serial_frame(&[250], Some(10));
    let plan = parse_frame_plan(&input, Limits::default()).unwrap();
    let mut output = vec![1, 2];

    let err = decode_plan(&input, &plan, &mut output, Limits::default()).unwrap_err();

    assert_eq!(err.kind(), ErrorKind::Malformed);
    assert_eq!(output, [1, 2]);
}

#[test]
fn rejects_range_pack_output_limit_without_mutating_destination() {
    let input = range_pack_serial_frame(&[0, 1, 5], Some(10));
    let plan = parse_frame_plan(&input, Limits::default()).unwrap();
    let mut output = vec![1, 2];
    let limits = Limits {
        max_decoded_bytes: 2,
        max_buffer_bytes: 2,
        ..Limits::default()
    };

    let err = decode_plan(&input, &plan, &mut output, limits).unwrap_err();

    assert_eq!(err.kind(), ErrorKind::LimitExceeded);
    assert_eq!(output, [1, 2]);
}

#[test]
fn decodes_v21_constant_serial_chunk() {
    let input = constant_serial_frame(b'x', 6);
    let plan = parse_frame_plan(&input, Limits::default()).unwrap();
    let mut output = Vec::new();

    let written = decode_plan(&input, &plan, &mut output, Limits::default()).unwrap();

    assert_eq!(written, 6);
    assert_eq!(output, b"xxxxxx");
}

#[test]
fn rejects_zero_count_constant_serial_without_mutating_destination() {
    let input = constant_serial_frame(b'x', 0);
    let plan = parse_frame_plan(&input, Limits::default()).unwrap();
    let mut output = vec![1, 2];

    let err = decode_plan(&input, &plan, &mut output, Limits::default()).unwrap_err();

    assert_eq!(err.kind(), ErrorKind::Malformed);
    assert_eq!(output, [1, 2]);
}

#[test]
fn rejects_constant_serial_output_limit_without_mutating_destination() {
    let input = constant_serial_frame(b'x', 6);
    let plan = parse_frame_plan(&input, Limits::default()).unwrap();
    let mut output = vec![1, 2];
    let limits = Limits {
        max_decoded_bytes: 4,
        max_buffer_bytes: 4,
        ..Limits::default()
    };

    let err = decode_plan(&input, &plan, &mut output, limits).unwrap_err();

    assert_eq!(err.kind(), ErrorKind::LimitExceeded);
    assert_eq!(output, [1, 2]);
}

#[test]
fn decodes_v21_zigzag_serial8_chunk() {
    let input = zigzag_serial_frame(&[0, 1, 2, 3, 4, 5, 254, 255]);
    let plan = parse_frame_plan(&input, Limits::default()).unwrap();
    let mut output = Vec::new();

    let written = decode_plan(&input, &plan, &mut output, Limits::default()).unwrap();

    assert_eq!(written, 8);
    assert_eq!(output, [0, 255, 1, 254, 2, 253, 127, 128]);
}

#[test]
fn decodes_zigzag_numeric_i32_chunk() {
    let values = [0u32, 1, 2, 21, 244, 245, u32::MAX];
    let mut input = Vec::new();
    for value in values {
        input.extend_from_slice(&value.to_le_bytes());
    }

    let output = decode_zigzag_numeric_chunk(
        StreamInput {
            bytes: &input,
            element_width: 4,
            string_lengths: None,
        },
        &[],
        Limits::default(),
    )
    .unwrap();

    assert_eq!(output.element_width, 4);
    assert_eq!(
        output.bytes,
        [0i32, -1, 1, -11, 122, -123, i32::MIN,]
            .into_iter()
            .flat_map(i32::to_le_bytes)
            .collect::<Vec<_>>()
    );
}

#[test]
fn rejects_zigzag_header_without_mutating_destination() {
    let input = standard_transform_serial_frame(21, 3, b"bytes", 5, &[0]);
    let plan = parse_frame_plan(&input, Limits::default()).unwrap();
    let mut output = vec![1, 2];

    let err = decode_plan(&input, &plan, &mut output, Limits::default()).unwrap_err();

    assert_eq!(err.kind(), ErrorKind::Unsupported);
    assert_eq!(output, [1, 2]);
}

#[test]
fn rejects_zigzag_output_limit_without_mutating_destination() {
    let input = zigzag_serial_frame(b"bytes");
    let plan = parse_frame_plan(&input, Limits::default()).unwrap();
    let mut output = vec![1, 2];
    let limits = Limits {
        max_decoded_bytes: 4,
        max_buffer_bytes: 4,
        ..Limits::default()
    };

    let err = decode_plan(&input, &plan, &mut output, limits).unwrap_err();

    assert_eq!(err.kind(), ErrorKind::LimitExceeded);
    assert_eq!(output, [1, 2]);
}

#[test]
fn decodes_v21_delta_serial8_chunk() {
    let input = delta_serial_frame(Some(2), &[1, 1, 2, 250]);
    let plan = parse_frame_plan(&input, Limits::default()).unwrap();
    let mut output = Vec::new();

    let written = decode_plan(&input, &plan, &mut output, Limits::default()).unwrap();

    assert_eq!(written, 5);
    assert_eq!(output, [2, 3, 4, 6, 0]);
}

#[test]
fn decodes_v21_two_node_regenerated_stream_graph() {
    let input = zigzag_delta_graph_frame(&[2, 1, 6], 10);
    let plan = parse_frame_plan(&input, Limits::default()).unwrap();
    let mut output = Vec::new();

    let written = decode_plan(&input, &plan, &mut output, Limits::default()).unwrap();

    assert_eq!(written, 4);
    assert_eq!(output, [10, 11, 10, 13]);
}

#[test]
fn decodes_empty_v21_delta_serial8_chunk() {
    let input = delta_serial_frame(None, &[]);
    let plan = parse_frame_plan(&input, Limits::default()).unwrap();
    let mut output = vec![1, 2];

    let written = decode_plan(&input, &plan, &mut output, Limits::default()).unwrap();

    assert_eq!(written, 0);
    assert_eq!(output, [1, 2]);
}

#[test]
fn rejects_delta_without_first_value_without_mutating_destination() {
    let input = delta_serial_frame(None, &[1]);
    let plan = parse_frame_plan(&input, Limits::default()).unwrap();
    let mut output = vec![1, 2];

    let err = decode_plan(&input, &plan, &mut output, Limits::default()).unwrap_err();

    assert_eq!(err.kind(), ErrorKind::Malformed);
    assert_eq!(output, [1, 2]);
}

#[test]
fn rejects_delta_output_limit_without_mutating_destination() {
    let input = delta_serial_frame(Some(2), &[1, 1, 2, 250]);
    let plan = parse_frame_plan(&input, Limits::default()).unwrap();
    let mut output = vec![1, 2];
    let limits = Limits {
        max_decoded_bytes: 4,
        max_buffer_bytes: 4,
        ..Limits::default()
    };

    let err = decode_plan(&input, &plan, &mut output, limits).unwrap_err();

    assert_eq!(err.kind(), ErrorKind::LimitExceeded);
    assert_eq!(output, [1, 2]);
}

#[test]
fn decodes_v21_convert_serial_to_struct_chunk() {
    let expected = b"struct payload bytes";
    let input = standard_transform_serial_frame(21, 5, expected, expected.len(), &[]);
    let plan = parse_frame_plan(&input, Limits::default()).unwrap();
    let mut output = Vec::new();

    let written = decode_plan(&input, &plan, &mut output, Limits::default()).unwrap();

    assert_eq!(written, expected.len());
    assert_eq!(output, expected);
}

#[test]
fn decodes_v21_convert_struct_to_serial_chunk() {
    let expected = b"serial payload bytes";
    let input = standard_transform_serial_frame(21, 6, expected, expected.len(), &[1]);
    let plan = parse_frame_plan(&input, Limits::default()).unwrap();
    let mut output = Vec::new();

    let written = decode_plan(&input, &plan, &mut output, Limits::default()).unwrap();

    assert_eq!(written, expected.len());
    assert_eq!(output, expected);
}

#[test]
fn decodes_v21_convert_num_to_struct_le_chunk() {
    let expected = [1, 0, 2, 0, 3, 0, 4, 0];
    let input = standard_transform_serial_frame(21, 8, &expected, expected.len(), &[]);
    let plan = parse_frame_plan(&input, Limits::default()).unwrap();
    let mut output = Vec::new();

    let written = decode_plan(&input, &plan, &mut output, Limits::default()).unwrap();

    assert_eq!(written, expected.len());
    assert_eq!(output, expected);
}

#[test]
fn decodes_v21_convert_serial_to_num_le_chunk() {
    let expected = [1, 0, 2, 0, 3, 0, 4, 0];
    let input = standard_transform_serial_frame(21, 9, &expected, expected.len(), &[]);
    let plan = parse_frame_plan(&input, Limits::default()).unwrap();
    let mut output = Vec::new();

    let written = decode_plan(&input, &plan, &mut output, Limits::default()).unwrap();

    assert_eq!(written, expected.len());
    assert_eq!(output, expected);
}

#[test]
fn decodes_v21_convert_num_to_serial_le_chunk() {
    let expected = [1, 0, 2, 0, 3, 0, 4, 0];
    let input = standard_transform_serial_frame(21, 10, &expected, expected.len(), &[1]);
    let plan = parse_frame_plan(&input, Limits::default()).unwrap();
    let mut output = Vec::new();

    let written = decode_plan(&input, &plan, &mut output, Limits::default()).unwrap();

    assert_eq!(written, expected.len());
    assert_eq!(output, expected);
}

#[test]
fn rejects_convert_num_to_serial_bad_header_without_mutating_destination() {
    let input = standard_transform_serial_frame(21, 10, b"bytes", 5, &[]);
    let plan = parse_frame_plan(&input, Limits::default()).unwrap();
    let mut output = vec![1, 2];

    let err = decode_plan(&input, &plan, &mut output, Limits::default()).unwrap_err();

    assert_eq!(err.kind(), ErrorKind::Malformed);
    assert_eq!(output, [1, 2]);
}

#[test]
fn rejects_convert_num_to_serial_unaligned_size_without_mutating_destination() {
    let input = standard_transform_serial_frame(21, 10, b"bytes", 5, &[2]);
    let plan = parse_frame_plan(&input, Limits::default()).unwrap();
    let mut output = vec![1, 2];

    let err = decode_plan(&input, &plan, &mut output, Limits::default()).unwrap_err();

    assert_eq!(err.kind(), ErrorKind::Malformed);
    assert_eq!(output, [1, 2]);
}

#[test]
fn rejects_convert_serial_to_struct_header_without_mutating_destination() {
    let input = standard_transform_serial_frame(21, 5, b"bytes", 5, &[0]);
    let plan = parse_frame_plan(&input, Limits::default()).unwrap();
    let mut output = vec![1, 2];

    let err = decode_plan(&input, &plan, &mut output, Limits::default()).unwrap_err();

    assert_eq!(err.kind(), ErrorKind::Unsupported);
    assert_eq!(output, [1, 2]);
}

#[test]
fn rejects_convert_serial_to_struct_output_limit_without_mutating_destination() {
    let input = standard_transform_serial_frame(21, 5, b"bytes", 5, &[]);
    let plan = parse_frame_plan(&input, Limits::default()).unwrap();
    let mut output = vec![1, 2];
    let limits = Limits {
        max_decoded_bytes: 4,
        max_buffer_bytes: 4,
        ..Limits::default()
    };

    let err = decode_plan(&input, &plan, &mut output, limits).unwrap_err();

    assert_eq!(err.kind(), ErrorKind::LimitExceeded);
    assert_eq!(output, [1, 2]);
}

#[test]
fn rejects_convert_struct_to_serial_output_limit_without_mutating_destination() {
    let input = standard_transform_serial_frame(21, 6, b"bytes", 5, &[1]);
    let plan = parse_frame_plan(&input, Limits::default()).unwrap();
    let mut output = vec![1, 2];
    let limits = Limits {
        max_decoded_bytes: 4,
        max_buffer_bytes: 4,
        ..Limits::default()
    };

    let err = decode_plan(&input, &plan, &mut output, limits).unwrap_err();

    assert_eq!(err.kind(), ErrorKind::LimitExceeded);
    assert_eq!(output, [1, 2]);
}

#[test]
fn decodes_v21_flatpack_serial_chunk() {
    let input = flatpack_serial_frame(b"abc", &[0, 1, 2, 1, 0]);
    let plan = parse_frame_plan(&input, Limits::default()).unwrap();
    let mut output = Vec::new();

    let written = decode_plan(&input, &plan, &mut output, Limits::default()).unwrap();

    assert_eq!(written, 5);
    assert_eq!(output, b"abcba");
}

#[test]
fn decodes_empty_v21_flatpack_serial_chunk() {
    let input = flatpack_serial_frame(b"", &[]);
    let plan = parse_frame_plan(&input, Limits::default()).unwrap();
    let mut output = vec![1, 2];

    let written = decode_plan(&input, &plan, &mut output, Limits::default()).unwrap();

    assert_eq!(written, 0);
    assert_eq!(output, [1, 2]);
}

#[test]
fn rejects_flatpack_output_limit_without_mutating_destination() {
    let input = flatpack_serial_frame(b"abc", &[0, 1, 2, 1, 0]);
    let plan = parse_frame_plan(&input, Limits::default()).unwrap();
    let mut output = vec![1, 2];
    let limits = Limits {
        max_decoded_bytes: 4,
        max_buffer_bytes: 4,
        ..Limits::default()
    };

    let err = decode_plan(&input, &plan, &mut output, limits).unwrap_err();

    assert_eq!(err.kind(), ErrorKind::LimitExceeded);
    assert_eq!(output, [1, 2]);
}

#[test]
fn decodes_v21_transpose_split2_chunk() {
    let input = transpose_split_frame(2, &[b"ace", b"bdf"]);
    let plan = parse_frame_plan(&input, Limits::default()).unwrap();
    let mut output = Vec::new();

    let written = decode_plan(&input, &plan, &mut output, Limits::default()).unwrap();

    assert_eq!(written, 6);
    assert_eq!(output, b"abcdef");
}

#[test]
fn decodes_v21_dynamic_transpose_split_chunk() {
    let input = dynamic_transpose_split_frame(&[b"ace", b"bdf"]);
    let plan = parse_frame_plan(&input, Limits::default()).unwrap();
    let mut output = Vec::new();

    let written = decode_plan(&input, &plan, &mut output, Limits::default()).unwrap();

    assert_eq!(written, 6);
    assert_eq!(output, b"abcdef");
}

#[test]
fn decodes_v21_transpose_split4_chunk() {
    let input = transpose_split_frame(4, &[b"ae", b"bf", b"cg", b"dh"]);
    let plan = parse_frame_plan(&input, Limits::default()).unwrap();
    let mut output = Vec::new();

    let written = decode_plan(&input, &plan, &mut output, Limits::default()).unwrap();

    assert_eq!(written, 8);
    assert_eq!(output, b"abcdefgh");
}

#[test]
fn decodes_v21_transpose_split8_chunk() {
    let input = transpose_split_frame(8, &[b"a", b"b", b"c", b"d", b"e", b"f", b"g", b"h"]);
    let plan = parse_frame_plan(&input, Limits::default()).unwrap();
    let mut output = Vec::new();

    let written = decode_plan(&input, &plan, &mut output, Limits::default()).unwrap();

    assert_eq!(written, 8);
    assert_eq!(output, b"abcdefgh");
}

#[test]
fn rejects_transpose_split_mismatched_lanes_without_mutating_destination() {
    let input = transpose_split_frame(2, &[b"ace", b"bd"]);
    let plan = parse_frame_plan(&input, Limits::default()).unwrap();
    let mut output = vec![1, 2];

    let err = decode_plan(&input, &plan, &mut output, Limits::default()).unwrap_err();

    assert_eq!(err.kind(), ErrorKind::Malformed);
    assert_eq!(output, [1, 2]);
}

#[test]
fn decodes_partition_preset_varbyte16_node() {
    let output = decode_partition_node(
        &[
            StreamInput {
                bytes: &[0, 1, 2],
                element_width: 1,
                string_lengths: None,
            },
            StreamInput {
                bytes: &[0x0d],
                element_width: 1,
                string_lengths: None,
            },
        ],
        &[0x15],
        Limits::default(),
    )
    .unwrap();

    assert_eq!(output.element_width, 2);
    assert_eq!(
        output.bytes,
        [1u16, 2, 7]
            .into_iter()
            .flat_map(u16::to_le_bytes)
            .collect::<Vec<_>>()
    );
}

#[test]
fn decodes_partition_u32_node() {
    let output = decode_partition_node(
        &[
            StreamInput {
                bytes: &[0, 1],
                element_width: 1,
                string_lengths: None,
            },
            StreamInput {
                bytes: &[0x15],
                element_width: 1,
                string_lengths: None,
            },
        ],
        &[0x0a, 4, 8],
        Limits::default(),
    )
    .unwrap();

    assert_eq!(output.element_width, 4);
    assert_eq!(
        output.bytes,
        [1u32, 9]
            .into_iter()
            .flat_map(u32::to_le_bytes)
            .collect::<Vec<_>>()
    );
}

#[cfg(feature = "lz4")]
#[test]
fn decodes_v23_lz4_serial_chunk() {
    let expected = b"lz4-backed OpenZL serial chunk";
    let compressed = lz4rip::block::compress(expected);
    let input = lz4_serial_frame(&compressed, expected.len());
    let plan = parse_frame_plan(&input, Limits::default()).unwrap();
    let mut output = Vec::new();

    let written = decode_plan(&input, &plan, &mut output, Limits::default()).unwrap();

    assert_eq!(written, expected.len());
    assert_eq!(output, expected);
}

#[cfg(feature = "zstd")]
#[test]
fn decodes_v21_zstd_serial_chunk() {
    let expected = b"zstd-backed OpenZL serial chunk";
    let compressed = zrip::compress(expected, 1).unwrap();
    let mut stored = Vec::new();
    push_var_u64(&mut stored, 1);
    stored.extend_from_slice(&compressed[4..]);
    let input = zstd_serial_frame(&stored, expected.len());
    let plan = parse_frame_plan(&input, Limits::default()).unwrap();
    let mut output = Vec::new();

    let written = decode_plan(&input, &plan, &mut output, Limits::default()).unwrap();

    assert_eq!(written, expected.len());
    assert_eq!(output, expected);
}

#[cfg(feature = "zstd")]
#[test]
fn rejects_malformed_zstd_chunk_without_mutating_destination() {
    let mut stored = Vec::new();
    push_var_u64(&mut stored, 1);
    stored.extend_from_slice(&[0]);
    let input = zstd_serial_frame(&stored, 8);
    let plan = parse_frame_plan(&input, Limits::default()).unwrap();
    let mut output = vec![1, 2];

    let err = decode_plan(&input, &plan, &mut output, Limits::default()).unwrap_err();

    assert_eq!(err.kind(), ErrorKind::Malformed);
    assert_eq!(output, [1, 2]);
}

#[cfg(feature = "zstd")]
#[test]
fn rejects_zstd_non_byte_output_width_without_mutating_destination() {
    let expected = b"zstd-backed OpenZL serial chunk";
    let compressed = zrip::compress(expected, 1).unwrap();
    let mut stored = Vec::new();
    push_var_u64(&mut stored, 2);
    stored.extend_from_slice(&compressed[4..]);
    let input = zstd_serial_frame(&stored, expected.len());
    let plan = parse_frame_plan(&input, Limits::default()).unwrap();
    let mut output = vec![1, 2];

    let err = decode_plan(&input, &plan, &mut output, Limits::default()).unwrap_err();

    assert_eq!(err.kind(), ErrorKind::Unsupported);
    assert_eq!(output, [1, 2]);
}

#[cfg(feature = "zstd")]
#[test]
fn rejects_zstd_transform_header_without_mutating_destination() {
    let expected = b"zstd-backed OpenZL serial chunk";
    let compressed = zrip::compress(expected, 1).unwrap();
    let mut stored = Vec::new();
    push_var_u64(&mut stored, 1);
    stored.extend_from_slice(&compressed[4..]);
    let input = standard_transform_serial_frame(21, 22, &stored, expected.len(), &[0]);
    let plan = parse_frame_plan(&input, Limits::default()).unwrap();
    let mut output = vec![1, 2];

    let err = decode_plan(&input, &plan, &mut output, Limits::default()).unwrap_err();

    assert_eq!(err.kind(), ErrorKind::Unsupported);
    assert_eq!(output, [1, 2]);
}

#[cfg(feature = "dev-format")]
#[test]
fn decodes_empty_pivco_huffman_without_mutating_destination() {
    let input = pivco_huffman_frame();
    let plan = parse_frame_plan(&input, Limits::default()).unwrap();
    let mut output = vec![1, 2];

    let written = decode_plan(&input, &plan, &mut output, Limits::default()).unwrap();

    assert_eq!(written, 0);
    assert_eq!(output, [1, 2]);
}

#[cfg(feature = "zstd")]
#[test]
fn enforces_zstd_output_limit_without_mutating_destination() {
    let expected = b"zstd output larger than configured limits";
    let compressed = zrip::compress(expected, 1).unwrap();
    let mut stored = Vec::new();
    push_var_u64(&mut stored, 1);
    stored.extend_from_slice(&compressed[4..]);
    let input = zstd_serial_frame(&stored, expected.len());
    let plan = parse_frame_plan(&input, Limits::default()).unwrap();
    let mut output = vec![1, 2];
    let limits = Limits {
        max_decoded_bytes: 8,
        max_buffer_bytes: 8,
        ..Limits::default()
    };

    let err = decode_plan(&input, &plan, &mut output, limits).unwrap_err();

    assert_eq!(err.kind(), ErrorKind::LimitExceeded);
    assert_eq!(output, [1, 2]);
}

#[cfg(not(feature = "zstd"))]
#[test]
fn rejects_zstd_chunk_when_feature_is_disabled() {
    let input = zstd_serial_frame(&[1, 0], 8);
    let plan = parse_frame_plan(&input, Limits::default()).unwrap();
    let mut output = vec![1, 2];

    let err = decode_plan(&input, &plan, &mut output, Limits::default()).unwrap_err();

    assert_eq!(err.kind(), ErrorKind::Unsupported);
    assert_eq!(output, [1, 2]);
}

#[cfg(feature = "lz4")]
#[test]
fn rejects_malformed_lz4_chunk_without_mutating_destination() {
    let input = lz4_serial_frame(&[0], 8);
    let plan = parse_frame_plan(&input, Limits::default()).unwrap();
    let mut output = vec![1, 2];

    let err = decode_plan(&input, &plan, &mut output, Limits::default()).unwrap_err();

    assert_eq!(err.kind(), ErrorKind::Malformed);
    assert_eq!(output, [1, 2]);
}

#[cfg(feature = "lz4")]
#[test]
fn enforces_lz4_header_output_limit_without_mutating_destination() {
    let input = lz4_serial_frame(&[0], 4096);
    let plan = parse_frame_plan(&input, Limits::default()).unwrap();
    let mut output = vec![1, 2];
    let limits = Limits {
        max_decoded_bytes: 1024,
        max_buffer_bytes: 1024,
        ..Limits::default()
    };

    let err = decode_plan(&input, &plan, &mut output, limits).unwrap_err();

    assert_eq!(err.kind(), ErrorKind::LimitExceeded);
    assert_eq!(output, [1, 2]);
}

#[cfg(not(feature = "lz4"))]
#[test]
fn rejects_lz4_chunk_when_feature_is_disabled() {
    let input = lz4_serial_frame(&[0], 8);
    let plan = parse_frame_plan(&input, Limits::default()).unwrap();
    let mut output = vec![1, 2];

    let err = decode_plan(&input, &plan, &mut output, Limits::default()).unwrap_err();

    assert_eq!(err.kind(), ErrorKind::Unsupported);
    assert_eq!(output, [1, 2]);
}

#[test]
fn rejects_size_mismatch_without_mutating_destination() {
    let mut input = Vec::new();
    input.extend_from_slice(&magic(21));
    input.push(0);
    input.push(1);
    input.push(5);
    input.push(1);
    input.push(1);
    input.push(3);
    input.extend_from_slice(&[7, 8, 9]);
    input.push(0);
    let plan = parse_frame_plan(&input, Limits::default()).unwrap();
    let mut output = vec![1, 2];

    let err = decode_plan(&input, &plan, &mut output, Limits::default()).unwrap_err();

    assert_eq!(err.kind(), ErrorKind::Malformed);
    assert_eq!(output, [1, 2]);
}

#[test]
fn enforces_expansion_ratio_without_mutating_destination() {
    let mut input = Vec::new();
    input.extend_from_slice(&magic(21));
    input.push(0);
    input.push(1);
    input.push(4);
    input.push(1);
    input.push(1);
    input.push(3);
    input.extend_from_slice(&[7, 8, 9]);
    input.push(0);
    let plan = parse_frame_plan(&input, Limits::default()).unwrap();
    let mut output = vec![1, 2];
    let limits = Limits {
        max_expansion_ratio: 0,
        ..Limits::default()
    };

    let err = decode_plan(&input, &plan, &mut output, limits).unwrap_err();

    assert_eq!(err.kind(), ErrorKind::LimitExceeded);
    assert_eq!(output, [1, 2]);
}

#[cfg(feature = "checksum")]
#[test]
fn verifies_decoded_checksum() {
    let mut input = Vec::new();
    input.extend_from_slice(&magic(21));
    input.push(1);
    input.push(1);
    input.push(4);
    input.push(1);
    input.push(1);
    input.push(3);
    input.extend_from_slice(&[7, 8, 9]);
    let checksum = (xxhash_rust::xxh3::xxh3_64(&[7, 8, 9]) & 0xffff_ffff) as u32;
    input.extend_from_slice(&checksum.to_le_bytes());
    input.push(0);
    let plan = parse_frame_plan(&input, Limits::default()).unwrap();
    let mut output = Vec::new();

    let written = decode_plan(&input, &plan, &mut output, Limits::default()).unwrap();

    assert_eq!(written, 3);
    assert_eq!(output, [7, 8, 9]);
}

#[cfg(feature = "checksum")]
#[test]
fn rejects_decoded_checksum_mismatch_without_mutating_destination() {
    let mut input = Vec::new();
    input.extend_from_slice(&magic(21));
    input.push(1);
    input.push(1);
    input.push(4);
    input.push(1);
    input.push(1);
    input.push(3);
    input.extend_from_slice(&[7, 8, 9]);
    input.extend_from_slice(&0u32.to_le_bytes());
    input.push(0);
    let plan = parse_frame_plan(&input, Limits::default()).unwrap();
    let mut output = vec![1, 2];

    let err = decode_plan(&input, &plan, &mut output, Limits::default()).unwrap_err();

    assert_eq!(err.kind(), ErrorKind::ChecksumMismatch);
    assert_eq!(output, [1, 2]);
}

#[cfg(feature = "checksum")]
#[test]
fn verifies_compressed_checksum() {
    let mut input = Vec::new();
    input.extend_from_slice(&magic(21));
    input.push(1 << 1);
    input.push(1);
    input.push(4);
    let header_checksum = (xxhash_rust::xxh3::xxh3_64(&input) & 0xff) as u8;
    input.push(header_checksum);
    let chunk_start = input.len();
    input.push(1);
    input.push(1);
    input.push(3);
    input.extend_from_slice(&[7, 8, 9]);
    let checksum = (xxhash_rust::xxh3::xxh3_64(&input[chunk_start..]) & 0xffff_ffff) as u32;
    input.extend_from_slice(&checksum.to_le_bytes());
    input.push(0);
    let plan = parse_frame_plan(&input, Limits::default()).unwrap();
    let mut output = Vec::new();

    let written = decode_plan(&input, &plan, &mut output, Limits::default()).unwrap();

    assert_eq!(written, 3);
    assert_eq!(output, [7, 8, 9]);
}

#[cfg(feature = "checksum")]
#[test]
fn rejects_compressed_checksum_mismatch() {
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
    input.extend_from_slice(&[7, 8, 9]);
    input.extend_from_slice(&0u32.to_le_bytes());
    input.push(0);

    let err = parse_frame_plan(&input, Limits::default()).unwrap_err();

    assert_eq!(err.kind(), ErrorKind::ChecksumMismatch);
}

#[cfg(feature = "checksum")]
#[test]
fn rejects_compressed_checksum_before_decoded_checksum() {
    let mut input = Vec::new();
    input.extend_from_slice(&magic(21));
    input.push((1 << 0) | (1 << 1));
    input.push(1);
    input.push(4);
    let header_checksum = (xxhash_rust::xxh3::xxh3_64(&input) & 0xff) as u8;
    input.push(header_checksum);
    input.push(1);
    input.push(1);
    input.push(3);
    input.extend_from_slice(&[7, 8, 9]);
    input.extend_from_slice(&0u32.to_le_bytes());
    input.extend_from_slice(&0u32.to_le_bytes());
    input.push(0);

    let err = parse_frame_plan(&input, Limits::default()).unwrap_err();

    assert_eq!(err.kind(), ErrorKind::ChecksumMismatch);
    assert!(err.detail().unwrap().contains("compressed"));
}

#[test]
fn decodes_fse_ncount_node() {
    let distribution = [15, 8, 4, 3, 1, 1];
    let encoded = zrip_core::fse::table_builder::serialize_fse_table_description(&distribution, 5);
    let output = decode_fse_ncount_node(
        StreamInput {
            bytes: &encoded,
            element_width: 1,
            string_lengths: None,
        },
        &[],
        Limits::default(),
    )
    .unwrap();

    let decoded = output
        .bytes
        .chunks_exact(2)
        .map(|bytes| i16::from_le_bytes(bytes.try_into().unwrap()))
        .collect::<Vec<_>>();
    assert_eq!(output.element_width, 2);
    assert_eq!(decoded, distribution);
}

#[test]
fn rejects_fse_ncount_trailing_bytes() {
    let distribution = [15, 8, 4, 3, 1, 1];
    let mut encoded =
        zrip_core::fse::table_builder::serialize_fse_table_description(&distribution, 5);
    encoded.push(0);
    let err = decode_fse_ncount_node(
        StreamInput {
            bytes: &encoded,
            element_width: 1,
            string_lengths: None,
        },
        &[],
        Limits::default(),
    )
    .unwrap_err();

    assert_eq!(err.kind(), ErrorKind::Malformed);
}
