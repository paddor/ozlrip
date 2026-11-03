use super::*;

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

fn constant_fixed_frame(value: u8, count: usize) -> Vec<u8> {
    let mut header = Vec::new();
    push_var_u64(&mut header, u64::try_from(count).unwrap());
    standard_transform_serial_frame(21, 45, &[value], count, &header)
}

fn zigzag_serial_frame(stored: &[u8]) -> Vec<u8> {
    standard_transform_serial_frame(21, 3, stored, stored.len(), &[])
}

fn delta_serial_frame(first: Option<u8>, deltas: &[u8]) -> Vec<u8> {
    let header = first.map_or_else(Vec::new, |value| vec![value]);
    let decoded_len = deltas.len() + usize::from(first.is_some());
    standard_transform_serial_frame(21, 1, deltas, decoded_len, &header)
}

fn pack_lsb_bits(values: &[u8], bits: u8) -> Vec<u8> {
    let values = values.iter().copied().map(u64::from).collect::<Vec<_>>();
    pack_lsb_values(&values, bits)
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
fn rejects_bitpack_output_limit_without_mutating_destination() {
    let expected = [0, 1, 2, 3, 4, 5, 6, 7, 1];
    let input = bitpack_serial_frame(&expected, 3);
    let plan = parse_frame_plan(&input, Limits::default()).unwrap();
    let mut output = vec![1, 2];
    let mut limits = Limits::default();
    limits.max_decoded_bytes = 4;
    limits.max_buffer_bytes = 4;

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
    let mut limits = Limits::default();
    limits.max_decoded_bytes = 2;
    limits.max_buffer_bytes = 2;

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
    let mut limits = Limits::default();
    limits.max_decoded_bytes = 2;
    limits.max_buffer_bytes = 2;

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
fn decodes_v21_constant_fixed_chunk() {
    let input = constant_fixed_frame(b'y', 5);
    let plan = parse_frame_plan(&input, Limits::default()).unwrap();
    let mut output = Vec::new();

    let written = decode_plan(&input, &plan, &mut output, Limits::default()).unwrap();

    assert_eq!(written, 5);
    assert_eq!(output, b"yyyyy");
}

#[test]
fn decodes_constant_fixed_chunk() {
    let mut header = Vec::new();
    push_var_u64(&mut header, 3);
    let input = StreamInput {
        bytes: &[0xaa, 0xbb],
        element_width: 2,
        string_lengths: None,
    };

    let output =
        decode_constant_fixed_chunk(input, &header, Limits::default(), &mut DecodeScratch::new())
            .unwrap();

    assert_eq!(output.element_width, 2);
    assert_eq!(output.bytes, [0xaa, 0xbb, 0xaa, 0xbb, 0xaa, 0xbb]);
    assert_eq!(output.string_lengths, None);
}

#[test]
fn rejects_constant_fixed_partial_input() {
    let mut header = Vec::new();
    push_var_u64(&mut header, 3);
    let input = StreamInput {
        bytes: &[0xaa],
        element_width: 2,
        string_lengths: None,
    };

    let err =
        decode_constant_fixed_chunk(input, &header, Limits::default(), &mut DecodeScratch::new())
            .unwrap_err();

    assert_eq!(err.kind(), ErrorKind::Malformed);
}

#[test]
fn rejects_constant_fixed_output_limit() {
    let mut header = Vec::new();
    push_var_u64(&mut header, 3);
    let input = StreamInput {
        bytes: &[0xaa, 0xbb],
        element_width: 2,
        string_lengths: None,
    };
    let mut limits = Limits::default();
    limits.max_decoded_bytes = 5;
    limits.max_buffer_bytes = 5;

    let err =
        decode_constant_fixed_chunk(input, &header, limits, &mut DecodeScratch::new()).unwrap_err();

    assert_eq!(err.kind(), ErrorKind::LimitExceeded);
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
    let mut limits = Limits::default();
    limits.max_decoded_bytes = 4;
    limits.max_buffer_bytes = 4;

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
    let mut limits = Limits::default();
    limits.max_decoded_bytes = 4;
    limits.max_buffer_bytes = 4;

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

/// Wide delta elements are little-endian on every target, including the
/// first value copied from the header.
#[test]
fn decodes_wide_delta_elements_as_little_endian() {
    fn check<const W: usize>(first: u64, deltas: &[u64], expected: &[u64]) {
        let le = |values: &[u64]| -> Vec<u8> {
            values
                .iter()
                .flat_map(|value| value.to_le_bytes()[..W].to_vec())
                .collect()
        };
        let stored = le(deltas);
        let output = decode_delta_node(
            StreamInput {
                bytes: &stored,
                element_width: W,
                string_lengths: None,
            },
            &le(&[first]),
            13,
            Limits::default(),
            &mut DecodeScratch::new(),
        )
        .unwrap();
        assert_eq!(output.bytes, le(expected), "width {W}");
    }

    check::<2>(0x0102, &[0x0100, 0xffff], &[0x0102, 0x0202, 0x0201]);
    check::<4>(0x0102_0304, &[0x0100_0000], &[0x0102_0304, 0x0202_0304]);
    check::<8>(
        0x0102_0304_0506_0708,
        &[0x0100_0000_0000_0000],
        &[0x0102_0304_0506_0708, 0x0202_0304_0506_0708],
    );
}

fn delta(stored: &[u8], width: usize, header: &[u8], version: u32) -> Result<OwnedStream> {
    decode_delta_node(
        StreamInput {
            bytes: stored,
            element_width: width,
            string_lengths: None,
        },
        header,
        version,
        Limits::default(),
        &mut DecodeScratch::new(),
    )
}

/// Before format v13 the first value leads the delta stream.
#[test]
fn decodes_delta_streams_before_v13() {
    let stored = [0x02, 0x01, 0x00, 0x01, 0xff, 0xff];

    let output = delta(&stored, 2, &[], 12).unwrap();

    assert_eq!(output.element_width, 2);
    assert_eq!(output.bytes, [0x02, 0x01, 0x02, 0x02, 0x01, 0x02]);
    assert_eq!(delta(&[], 2, &[], 12).unwrap().bytes, b"");
}

#[test]
fn rejects_delta_headers_before_v13() {
    let err = delta(&[1, 2], 1, &[3], 12).unwrap_err();

    assert_eq!(err.kind(), ErrorKind::Unsupported);
}

fn range_pack(values: &[u8], width: usize, header: &[u8]) -> Result<OwnedStream> {
    decode_range_pack_node(
        StreamInput {
            bytes: values,
            element_width: width,
            string_lengths: None,
        },
        header,
        Limits::default(),
    )
}

#[test]
fn decodes_range_pack_to_wider_integers() {
    let min = 10_000u16.to_le_bytes();
    let output = range_pack(&[0, 5, 255], 1, &[2, min[0], min[1]]).unwrap();
    assert_eq!(output.element_width, 2);
    assert_eq!(
        output.bytes,
        [10_000u16, 10_005, 10_255]
            .into_iter()
            .flat_map(u16::to_le_bytes)
            .collect::<Vec<_>>()
    );

    let mut header = vec![8];
    header.extend_from_slice(&(1u64 << 40).to_le_bytes());
    let output = range_pack(&[1, 0, 0xff, 0xff], 2, &header).unwrap();
    assert_eq!(output.element_width, 8);
    assert_eq!(
        output.bytes,
        [(1u64 << 40) + 1, (1 << 40) + 0xffff]
            .into_iter()
            .flat_map(u64::to_le_bytes)
            .collect::<Vec<_>>()
    );

    let output = range_pack(&[1, 0, 0, 0], 4, &[4]).unwrap();
    assert_eq!(output.element_width, 4);
    assert_eq!(output.bytes, [1, 0, 0, 0]);
}

#[test]
fn rejects_malformed_range_pack_headers_and_values() {
    let cases: [(&[u8], usize, &[u8], &str); 5] = [
        (&[0, 0], 2, &[1], "range_pack output width is invalid"),
        (&[0], 1, &[3], "range_pack output width is invalid"),
        (&[0], 1, &[2, 1], "range_pack header is malformed"),
        (&[0xff, 0xff], 2, &[2, 1, 0], "range_pack value overflowed"),
        (&[], 1, &[], "range_pack header is malformed"),
    ];
    for (values, width, header, detail) in cases {
        let err = range_pack(values, width, header).unwrap_err();

        assert_eq!(err.kind(), ErrorKind::Malformed, "{detail}");
        assert_eq!(err.detail(), Some(detail));
    }
}

fn bitunpack(values: &[u8], width: usize, header: &[u8]) -> Result<Vec<u8>> {
    decode_bitunpack_node(
        StreamInput {
            bytes: values,
            element_width: width,
            string_lengths: None,
        },
        header,
        Limits::default(),
    )
}

#[test]
fn decodes_bitunpack_values_wider_than_a_byte() {
    let values = [0xabcu16, 0x123]
        .into_iter()
        .flat_map(u16::to_le_bytes)
        .collect::<Vec<_>>();
    assert_eq!(bitunpack(&values, 2, &[12]).unwrap(), [0xbc, 0x3a, 0x12]);

    let values = [u64::MAX, 1]
        .into_iter()
        .flat_map(u64::to_le_bytes)
        .collect::<Vec<_>>();
    let mut expected = vec![0xff; 8];
    expected.extend_from_slice(&[1, 0, 0, 0, 0, 0, 0, 0]);
    assert_eq!(bitunpack(&values, 8, &[64]).unwrap(), expected);

    // Two 32-bit values fill whole bytes, so no trailing bits fit.
    let values = [1u32 << 31, 1]
        .into_iter()
        .flat_map(u32::to_le_bytes)
        .collect::<Vec<_>>();
    assert_eq!(
        bitunpack(&values, 4, &[32, 0x2a]).unwrap_err().kind(),
        ErrorKind::Malformed
    );
    // Two 33-bit values leave 6 bits for the trailing bits.
    let values = [1u64 << 32, 1]
        .into_iter()
        .flat_map(u64::to_le_bytes)
        .collect::<Vec<_>>();
    assert_eq!(
        bitunpack(&values, 8, &[33, 0x2a]).unwrap(),
        [0, 0, 0, 0, 3, 0, 0, 0, 0x2a << 2]
    );
}

#[test]
fn rejects_malformed_bitunpack_widths_and_values() {
    let wide = 0x1000u16.to_le_bytes();
    let cases: [(&[u8], usize, &[u8], &str); 3] = [
        (&wide, 2, &[12], "bitunpack value exceeds bit width"),
        (&wide, 2, &[17], "bitunpack bit count is invalid"),
        (&[0], 1, &[0], "bitunpack bit count is invalid"),
    ];
    for (values, width, header, detail) in cases {
        let err = bitunpack(values, width, header).unwrap_err();

        assert_eq!(err.kind(), ErrorKind::Malformed, "{detail}");
        assert_eq!(err.detail(), Some(detail));
    }
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
    let mut limits = Limits::default();
    limits.max_decoded_bytes = 4;
    limits.max_buffer_bytes = 4;

    let err = decode_plan(&input, &plan, &mut output, limits).unwrap_err();

    assert_eq!(err.kind(), ErrorKind::LimitExceeded);
    assert_eq!(output, [1, 2]);
}

#[test]
fn decodes_divide_by_numeric_u16_node() {
    let quotients = [3u16.to_le_bytes(), 4u16.to_le_bytes()].concat();
    let output = decode_divide_by_node(
        StreamInput {
            bytes: &quotients,
            element_width: 2,
            string_lengths: None,
        },
        &[5],
        Limits::default(),
    )
    .unwrap();

    assert_eq!(output.element_width, 2);
    assert_eq!(
        output.bytes,
        [15u16.to_le_bytes(), 20u16.to_le_bytes()].concat()
    );
}

#[test]
fn decodes_v21_divide_by_graph() {
    let quotients = [3u16.to_le_bytes(), 4u16.to_le_bytes()].concat();
    let input = standard_graph_serial_frame(
        21,
        4,
        &[
            StandardGraphNode {
                transform_id: standard::CONVERT_NUM_TO_SERIAL_LE_ID,
                variable_inputs: 0,
                outputs: 1,
                header: &[1],
            },
            StandardGraphNode {
                transform_id: standard::DIVIDE_BY_ID,
                variable_inputs: 0,
                outputs: 1,
                header: &[5],
            },
        ],
        &[&quotients],
    );
    let plan = parse_frame_plan(&input, Limits::default()).unwrap();
    let mut output = Vec::new();

    let written = decode_plan(&input, &plan, &mut output, Limits::default()).unwrap();

    assert_eq!(written, 4);
    assert_eq!(output, [15u16.to_le_bytes(), 20u16.to_le_bytes()].concat());
}

#[test]
fn rejects_divide_by_overflow() {
    let err = decode_divide_by_node(
        StreamInput {
            bytes: &[128],
            element_width: 1,
            string_lengths: None,
        },
        &[2],
        Limits::default(),
    )
    .unwrap_err();

    assert_eq!(err.kind(), ErrorKind::Malformed);
}

#[test]
fn decodes_dedup_num_node() {
    let values = [9u16.to_le_bytes(), 10u16.to_le_bytes()].concat();
    let outputs = decode_dedup_num_node(
        StreamInput {
            bytes: &values,
            element_width: 2,
            string_lengths: None,
        },
        &[],
        3,
        Limits::default(),
    )
    .unwrap();

    assert_eq!(outputs.len(), 3);
    for output in outputs {
        assert_eq!(output.element_width, 2);
        assert_eq!(output.bytes, values);
    }
}

#[test]
fn decodes_v21_dedup_num_graph() {
    let values = [9u16.to_le_bytes(), 10u16.to_le_bytes()].concat();
    let input = standard_graph_serial_frame(
        21,
        values.len(),
        &[
            StandardGraphNode {
                transform_id: standard::CONVERT_NUM_TO_SERIAL_LE_ID,
                variable_inputs: 0,
                outputs: 1,
                header: &[1],
            },
            StandardGraphNode {
                transform_id: standard::DEDUP_NUM_ID,
                variable_inputs: 0,
                outputs: 2,
                header: &[],
            },
        ],
        &[&values],
    );
    let plan = parse_frame_plan(&input, Limits::default()).unwrap();
    let mut output = Vec::new();

    let written = decode_plan(&input, &plan, &mut output, Limits::default()).unwrap();

    assert_eq!(written, values.len());
    assert_eq!(output, values);
}

#[test]
fn rejects_dedup_num_header() {
    let err = decode_dedup_num_node(
        StreamInput {
            bytes: &[1, 2],
            element_width: 1,
            string_lengths: None,
        },
        &[0],
        1,
        Limits::default(),
    )
    .unwrap_err();

    assert_eq!(err.kind(), ErrorKind::Unsupported);
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
fn decodes_v21_convert_struct_to_num_be_graph() {
    let stored = [0x12, 0x34, 0xab, 0xcd, 0x01, 0x02, 0x03, 0x04];
    let input = standard_graph_serial_frame(
        21,
        stored.len(),
        &[
            StandardGraphNode {
                transform_id: standard::CONVERT_STRUCT_TO_SERIAL_ID,
                variable_inputs: 0,
                outputs: 1,
                header: &[2],
            },
            StandardGraphNode {
                transform_id: standard::CONVERT_STRUCT_TO_NUM_BE_ID,
                variable_inputs: 0,
                outputs: 1,
                header: &[],
            },
        ],
        &[&stored],
    );
    let plan = parse_frame_plan(&input, Limits::default()).unwrap();
    let mut output = Vec::new();

    let written = decode_plan(&input, &plan, &mut output, Limits::default()).unwrap();

    assert_eq!(written, stored.len());
    assert_eq!(output, [0x34, 0x12, 0xcd, 0xab, 0x02, 0x01, 0x04, 0x03]);
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
    let mut limits = Limits::default();
    limits.max_decoded_bytes = 4;
    limits.max_buffer_bytes = 4;

    let err = decode_plan(&input, &plan, &mut output, limits).unwrap_err();

    assert_eq!(err.kind(), ErrorKind::LimitExceeded);
    assert_eq!(output, [1, 2]);
}

#[test]
fn rejects_convert_struct_to_serial_output_limit_without_mutating_destination() {
    let input = standard_transform_serial_frame(21, 6, b"bytes", 5, &[1]);
    let plan = parse_frame_plan(&input, Limits::default()).unwrap();
    let mut output = vec![1, 2];
    let mut limits = Limits::default();
    limits.max_decoded_bytes = 4;
    limits.max_buffer_bytes = 4;

    let err = decode_plan(&input, &plan, &mut output, limits).unwrap_err();

    assert_eq!(err.kind(), ErrorKind::LimitExceeded);
    assert_eq!(output, [1, 2]);
}
