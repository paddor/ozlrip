use super::*;

const LEGACY_LZ_LAST_VERSION: u32 = 12;

fn deprecated_lz_stored_stream(decoded_size: usize, payload: &[u8]) -> Vec<u8> {
    let mut output = Vec::new();
    output.extend_from_slice(&u32::try_from(decoded_size).unwrap().to_le_bytes());
    output.extend_from_slice(payload);
    output
}

fn fastlz_deprecated_stream(
    decoded_size: usize,
    literal_entropy: &[u8],
    token_entropy: &[u8],
    offsets: &[u8],
    extras: &[u8],
) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend_from_slice(literal_entropy);
    payload.extend_from_slice(token_entropy);
    push_var_u64(&mut payload, u64::try_from(offsets.len()).unwrap());
    payload.extend_from_slice(offsets);
    push_var_u64(&mut payload, u64::try_from(extras.len()).unwrap());
    payload.extend_from_slice(extras);
    deprecated_lz_stored_stream(decoded_size, &payload)
}

fn fastlz_deprecated_literal_entropy_stream(
    decoded_size: usize,
    literal_entropy: &[u8],
) -> Vec<u8> {
    fastlz_deprecated_stream(
        decoded_size,
        literal_entropy,
        &legacy_entropy_raw_payload(&[], 2),
        &[],
        &[],
    )
}

fn fastlz_deprecated_literal_only_stream(literals: &[u8]) -> Vec<u8> {
    let literal_entropy = legacy_entropy_raw_payload(literals, 1);
    fastlz_deprecated_literal_entropy_stream(literals.len(), &literal_entropy)
}

fn empty_fastlz_deprecated_stream() -> Vec<u8> {
    fastlz_deprecated_literal_only_stream(&[])
}

const ROLZ_TEST_MARKOV_STATES: usize = 6;

fn rolz_deprecated_stream(
    decoded_size: usize,
    num_literals: usize,
    literal_entropy: &[u8],
    match_types: &[u8],
    literal_lengths: &[usize],
    match_lengths: &[usize],
    match_codes: &[usize],
) -> Vec<u8> {
    rolz_deprecated_stream_with_literal_order(
        decoded_size,
        num_literals,
        0,
        literal_entropy,
        match_types,
        literal_lengths,
        match_lengths,
        match_codes,
    )
}

#[expect(
    clippy::too_many_arguments,
    reason = "test frame builder mirrors deprecated ROLZ wire fields"
)]
fn rolz_deprecated_stream_with_literal_order(
    decoded_size: usize,
    num_literals: usize,
    literal_order: u8,
    literal_payload: &[u8],
    match_types: &[u8],
    literal_lengths: &[usize],
    match_lengths: &[usize],
    match_codes: &[usize],
) -> Vec<u8> {
    rolz_deprecated_stream_with_entropy(
        decoded_size,
        num_literals,
        literal_order,
        literal_payload,
        &legacy_entropy_raw_payload(match_types, 1),
        match_types,
        literal_lengths,
        match_lengths,
        match_codes,
    )
}

#[expect(
    clippy::too_many_arguments,
    reason = "test frame builder mirrors deprecated ROLZ wire fields"
)]
fn rolz_deprecated_stream_with_entropy(
    decoded_size: usize,
    num_literals: usize,
    literal_order: u8,
    literal_payload: &[u8],
    match_type_entropy: &[u8],
    match_types: &[u8],
    literal_lengths: &[usize],
    match_lengths: &[usize],
    match_codes: &[usize],
) -> Vec<u8> {
    let mut payload = vec![2, 12, 4, 3, 1, 7, 3];
    payload.extend_from_slice(&u32::try_from(num_literals).unwrap().to_le_bytes());
    payload.extend_from_slice(&u32::try_from(match_types.len()).unwrap().to_le_bytes());
    if num_literals != 0 {
        payload.push(literal_order);
        payload.extend_from_slice(literal_payload);
    }
    payload.extend_from_slice(match_type_entropy);
    if !match_types.is_empty() {
        payload.extend_from_slice(&rolz_deprecated_sequence_values(
            literal_lengths,
            match_types,
        ));
        payload.extend_from_slice(&rolz_deprecated_sequence_values(match_lengths, match_types));
        payload.extend_from_slice(&rolz_deprecated_sequence_values(match_codes, match_types));
    }
    deprecated_lz_stored_stream(decoded_size, &payload)
}

fn rolz_deprecated_o1_literal_payload(
    max_context: u8,
    contexts: &[(u8, u8)],
    clusters: &[Vec<u8>],
) -> Vec<u8> {
    let mut context_to_cluster = vec![0u8; usize::from(max_context) + 1];
    for &(context, cluster) in contexts {
        context_to_cluster[usize::from(context)] = cluster;
    }

    let mut output = Vec::new();
    output.push(max_context);
    output.extend_from_slice(&context_to_cluster);
    for cluster in clusters {
        output.extend_from_slice(&u32::try_from(cluster.len()).unwrap().to_le_bytes());
        output.extend_from_slice(&legacy_entropy_raw_payload(cluster, 1));
    }
    output
}

fn rolz_deprecated_sequence_values(values: &[usize], match_types: &[u8]) -> Vec<u8> {
    assert_eq!(values.len(), match_types.len());

    let mut states = Vec::new();
    let mut sizes = [0usize; ROLZ_TEST_MARKOV_STATES];
    let mut state = 0usize;
    for &match_type in match_types {
        state = rolz_test_next_state(state, match_type);
        states.push(state);
        sizes[state] += 1;
    }

    let mut codes = Vec::new();
    let mut widths = Vec::new();
    let mut extras = Vec::new();
    for &value in values {
        let (code, width, extra) = rolz_test_value_code(value);
        codes.push(code);
        widths.push(width);
        extras.push(extra);
    }

    let mut writer = zrip_core::bitstream::writer::BitWriter::new();
    for index in (0..values.len()).rev() {
        writer.write_bits(u32::try_from(extras[index]).unwrap(), widths[index]);
    }
    writer.close_reverse_stream();
    let bitstream = writer.into_bytes();

    let mut grouped = vec![Vec::new(); ROLZ_TEST_MARKOV_STATES];
    for index in 0..values.len() {
        grouped[states[index]].push(codes[index]);
    }

    let mut output = Vec::new();
    output.extend_from_slice(&u32::try_from(bitstream.len()).unwrap().to_le_bytes());
    let mut total = 0usize;
    for size in sizes {
        total += size;
        output.extend_from_slice(&u32::try_from(total).unwrap().to_le_bytes());
    }
    output.extend_from_slice(&bitstream);
    for state_codes in grouped {
        output.extend_from_slice(&legacy_entropy_raw_payload(&state_codes, 1));
    }
    output
}

fn rolz_test_next_state(state: usize, match_type: u8) -> usize {
    const NEXT: [[usize; 4]; ROLZ_TEST_MARKOV_STATES] = [
        [0, 1, 2, 5],
        [0, 1, 3, 5],
        [0, 1, 4, 5],
        [0, 1, 4, 5],
        [0, 1, 4, 5],
        [0, 1, 2, 5],
    ];
    NEXT[state][usize::from(match_type)]
}

fn rolz_test_value_code(value: usize) -> (u8, u8, usize) {
    if value < 32 {
        return (u8::try_from(value).unwrap(), 0, 0);
    }
    let highbit = usize::BITS - 1 - value.leading_zeros();
    let code = 27 + highbit;
    let width = u8::try_from(highbit).unwrap();
    let base = 1usize << highbit;
    (u8::try_from(code).unwrap(), width, value - base)
}

fn rolz_deprecated_literal_entropy_stream(decoded_size: usize, literal_entropy: &[u8]) -> Vec<u8> {
    rolz_deprecated_stream(
        decoded_size,
        decoded_size,
        literal_entropy,
        &[],
        &[],
        &[],
        &[],
    )
}

fn rolz_deprecated_literal_only_stream(literals: &[u8]) -> Vec<u8> {
    let literal_entropy = legacy_entropy_raw_payload(literals, 1);
    rolz_deprecated_literal_entropy_stream(literals.len(), &literal_entropy)
}

fn empty_rolz_deprecated_stream() -> Vec<u8> {
    rolz_deprecated_literal_only_stream(&[])
}

#[test]
fn decodes_empty_fastlz_deprecated_node() {
    let stored = empty_fastlz_deprecated_stream();
    let output = decode_fastlz_deprecated_node(
        StreamInput {
            bytes: &stored,
            element_width: 1,
            string_lengths: None,
        },
        &[],
        Limits::default(),
    )
    .unwrap();

    assert_eq!(output, b"");
}

#[test]
fn decodes_v12_empty_fastlz_deprecated_frame() {
    let stored = empty_fastlz_deprecated_stream();
    let input = standard_transform_serial_frame(
        LEGACY_LZ_LAST_VERSION,
        standard::FASTLZ_DEPRECATED_ID,
        &stored,
        0,
        &[],
    );
    let plan = parse_frame_plan(&input, Limits::default()).unwrap();
    let mut output = vec![1, 2];

    let written = decode_plan(&input, &plan, &mut output, Limits::default()).unwrap();

    assert_eq!(written, 0);
    assert_eq!(output, [1, 2]);
}

#[test]
fn decodes_v12_fastlz_deprecated_raw_literals_frame() {
    let expected = b"legacy fastlz literals";
    let stored = fastlz_deprecated_literal_only_stream(expected);
    let input = standard_transform_serial_frame(
        LEGACY_LZ_LAST_VERSION,
        standard::FASTLZ_DEPRECATED_ID,
        &stored,
        expected.len(),
        &[],
    );
    let plan = parse_frame_plan(&input, Limits::default()).unwrap();
    let mut output = Vec::new();

    let written = decode_plan(&input, &plan, &mut output, Limits::default()).unwrap();

    assert_eq!(written, expected.len());
    assert_eq!(output, expected);
}

#[test]
fn decodes_v12_fastlz_deprecated_constant_literals_frame() {
    let expected = vec![b'F'; 19];
    let literal_entropy = legacy_entropy_constant_payload(b"F", expected.len());
    let stored = fastlz_deprecated_literal_entropy_stream(expected.len(), &literal_entropy);
    let input = standard_transform_serial_frame(
        LEGACY_LZ_LAST_VERSION,
        standard::FASTLZ_DEPRECATED_ID,
        &stored,
        expected.len(),
        &[],
    );
    let plan = parse_frame_plan(&input, Limits::default()).unwrap();
    let mut output = Vec::new();

    let written = decode_plan(&input, &plan, &mut output, Limits::default()).unwrap();

    assert_eq!(written, expected.len());
    assert_eq!(output, expected);
}

#[test]
fn decodes_v12_fastlz_deprecated_bit_literals_frame() {
    let expected = [0u8, 1, 2, 3, 2, 1, 0];
    let values = expected.iter().copied().map(u64::from).collect::<Vec<_>>();
    let literal_entropy = legacy_entropy_bit_payload(&values, 2);
    let stored = fastlz_deprecated_literal_entropy_stream(expected.len(), &literal_entropy);
    let input = standard_transform_serial_frame(
        LEGACY_LZ_LAST_VERSION,
        standard::FASTLZ_DEPRECATED_ID,
        &stored,
        expected.len(),
        &[],
    );
    let plan = parse_frame_plan(&input, Limits::default()).unwrap();
    let mut output = Vec::new();

    let written = decode_plan(&input, &plan, &mut output, Limits::default()).unwrap();

    assert_eq!(written, expected.len());
    assert_eq!(output, expected);
}

#[test]
fn decodes_v12_fastlz_deprecated_fse_literals_frame() {
    let expected = [
        0, 1, 0, 1, 1, 0, 1, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 1, 1, 0, 1, 0, 1, 0, 1, 1, 0, 0,
        1, 1,
    ];
    let literal_entropy = legacy_entropy_fse_payload(&expected, 2);
    let stored = fastlz_deprecated_literal_entropy_stream(expected.len(), &literal_entropy);
    let input = standard_transform_serial_frame(
        LEGACY_LZ_LAST_VERSION,
        standard::FASTLZ_DEPRECATED_ID,
        &stored,
        expected.len(),
        &[],
    );
    let plan = parse_frame_plan(&input, Limits::default()).unwrap();
    let mut output = Vec::new();

    let written = decode_plan(&input, &plan, &mut output, Limits::default()).unwrap();

    assert_eq!(written, expected.len());
    assert_eq!(output, expected);
}

#[test]
fn decodes_v12_fastlz_deprecated_multi_literals_frame() {
    let expected = b"ab\x00\x01\x02";
    let literal_entropy = legacy_entropy_multi_payload(&[
        legacy_entropy_raw_payload(b"ab", 1),
        legacy_entropy_bit_payload(&[0, 1, 2], 2),
    ]);
    let stored = fastlz_deprecated_literal_entropy_stream(expected.len(), &literal_entropy);
    let input = standard_transform_serial_frame(
        LEGACY_LZ_LAST_VERSION,
        standard::FASTLZ_DEPRECATED_ID,
        &stored,
        expected.len(),
        &[],
    );
    let plan = parse_frame_plan(&input, Limits::default()).unwrap();
    let mut output = Vec::new();

    let written = decode_plan(&input, &plan, &mut output, Limits::default()).unwrap();

    assert_eq!(written, expected.len());
    assert_eq!(output, expected);
}

#[test]
fn decodes_v12_fastlz_deprecated_raw_sequence_frame() {
    let literals = b"abcdefghijklmnop!";
    let token = 1u16.to_le_bytes();
    let stored = fastlz_deprecated_stream(
        33,
        &legacy_entropy_raw_payload(literals, 1),
        &legacy_entropy_raw_payload(&token, 2),
        &[16],
        &[16, 16],
    );
    let input = standard_transform_serial_frame(
        LEGACY_LZ_LAST_VERSION,
        standard::FASTLZ_DEPRECATED_ID,
        &stored,
        33,
        &[],
    );
    let plan = parse_frame_plan(&input, Limits::default()).unwrap();
    let mut output = Vec::new();

    let written = decode_plan(&input, &plan, &mut output, Limits::default()).unwrap();

    assert_eq!(written, 33);
    assert_eq!(output, b"abcdefghijklmnopabcdefghijklmnop!");
}

#[test]
fn decodes_v12_fastlz_deprecated_bit_token_frame() {
    let literals = b"abcdefghijklmnop!";
    let stored = fastlz_deprecated_stream(
        33,
        &legacy_entropy_raw_payload(literals, 1),
        &legacy_entropy_bit_payload(&[1], 1),
        &[16],
        &[16, 16],
    );
    let input = standard_transform_serial_frame(
        LEGACY_LZ_LAST_VERSION,
        standard::FASTLZ_DEPRECATED_ID,
        &stored,
        33,
        &[],
    );
    let plan = parse_frame_plan(&input, Limits::default()).unwrap();
    let mut output = Vec::new();

    let written = decode_plan(&input, &plan, &mut output, Limits::default()).unwrap();

    assert_eq!(written, 33);
    assert_eq!(output, b"abcdefghijklmnopabcdefghijklmnop!");
}

#[test]
fn decodes_empty_rolz_deprecated_node() {
    let stored = empty_rolz_deprecated_stream();
    let output = decode_rolz_deprecated_node(
        StreamInput {
            bytes: &stored,
            element_width: 1,
            string_lengths: None,
        },
        &[],
        Limits::default(),
    )
    .unwrap();

    assert_eq!(output, b"");
}

#[test]
fn decodes_v12_empty_rolz_deprecated_frame() {
    let stored = empty_rolz_deprecated_stream();
    let input = standard_transform_serial_frame(
        LEGACY_LZ_LAST_VERSION,
        standard::ROLZ_DEPRECATED_ID,
        &stored,
        0,
        &[],
    );
    let plan = parse_frame_plan(&input, Limits::default()).unwrap();
    let mut output = vec![1, 2];

    let written = decode_plan(&input, &plan, &mut output, Limits::default()).unwrap();

    assert_eq!(written, 0);
    assert_eq!(output, [1, 2]);
}

#[test]
fn decodes_v12_rolz_deprecated_raw_literals_frame() {
    let expected = b"legacy rolz literals";
    let stored = rolz_deprecated_literal_only_stream(expected);
    let input = standard_transform_serial_frame(
        LEGACY_LZ_LAST_VERSION,
        standard::ROLZ_DEPRECATED_ID,
        &stored,
        expected.len(),
        &[],
    );
    let plan = parse_frame_plan(&input, Limits::default()).unwrap();
    let mut output = Vec::new();

    let written = decode_plan(&input, &plan, &mut output, Limits::default()).unwrap();

    assert_eq!(written, expected.len());
    assert_eq!(output, expected);
}

#[test]
fn decodes_v12_rolz_deprecated_constant_literals_frame() {
    let expected = vec![b'R'; 17];
    let literal_entropy = legacy_entropy_constant_payload(b"R", expected.len());
    let stored = rolz_deprecated_literal_entropy_stream(expected.len(), &literal_entropy);
    let input = standard_transform_serial_frame(
        LEGACY_LZ_LAST_VERSION,
        standard::ROLZ_DEPRECATED_ID,
        &stored,
        expected.len(),
        &[],
    );
    let plan = parse_frame_plan(&input, Limits::default()).unwrap();
    let mut output = Vec::new();

    let written = decode_plan(&input, &plan, &mut output, Limits::default()).unwrap();

    assert_eq!(written, expected.len());
    assert_eq!(output, expected);
}

#[test]
fn decodes_v12_rolz_deprecated_fse_literals_frame() {
    let expected = [
        0, 1, 0, 1, 1, 0, 1, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 1, 1, 0, 1, 0, 1, 0, 1, 1, 0, 0,
        1, 1,
    ];
    let literal_entropy = legacy_entropy_fse_payload(&expected, 2);
    let stored = rolz_deprecated_literal_entropy_stream(expected.len(), &literal_entropy);
    let input = standard_transform_serial_frame(
        LEGACY_LZ_LAST_VERSION,
        standard::ROLZ_DEPRECATED_ID,
        &stored,
        expected.len(),
        &[],
    );
    let plan = parse_frame_plan(&input, Limits::default()).unwrap();
    let mut output = Vec::new();

    let written = decode_plan(&input, &plan, &mut output, Limits::default()).unwrap();

    assert_eq!(written, expected.len());
    assert_eq!(output, expected);
}

#[test]
fn decodes_v12_rolz_deprecated_o1_literals_frame() {
    let expected = b"ababa!";
    let literal_payload = rolz_deprecated_o1_literal_payload(
        b'b',
        &[(0, 0), (b'a', 1), (b'b', 2)],
        &[b"a".to_vec(), b"bb!".to_vec(), b"aa".to_vec()],
    );
    let stored = rolz_deprecated_stream_with_literal_order(
        expected.len(),
        expected.len(),
        1,
        &literal_payload,
        &[],
        &[],
        &[],
        &[],
    );
    let input = standard_transform_serial_frame(
        LEGACY_LZ_LAST_VERSION,
        standard::ROLZ_DEPRECATED_ID,
        &stored,
        expected.len(),
        &[],
    );
    let plan = parse_frame_plan(&input, Limits::default()).unwrap();
    let mut output = Vec::new();

    let written = decode_plan(&input, &plan, &mut output, Limits::default()).unwrap();

    assert_eq!(written, expected.len());
    assert_eq!(output, expected);
}

#[test]
fn decodes_v12_rolz_deprecated_o1_rep0_sequence_frame() {
    let literal_payload = rolz_deprecated_o1_literal_payload(
        b'c',
        &[(0, 0), (b'a', 1), (b'b', 2), (b'c', 3)],
        &[b"a".to_vec(), b"b".to_vec(), b"c".to_vec(), b"!".to_vec()],
    );
    let stored = rolz_deprecated_stream_with_literal_order(
        7,
        4,
        1,
        &literal_payload,
        &[2],
        &[3],
        &[0],
        &[0],
    );
    let input = standard_transform_serial_frame(
        LEGACY_LZ_LAST_VERSION,
        standard::ROLZ_DEPRECATED_ID,
        &stored,
        7,
        &[],
    );
    let plan = parse_frame_plan(&input, Limits::default()).unwrap();
    let mut output = Vec::new();

    let written = decode_plan(&input, &plan, &mut output, Limits::default()).unwrap();

    assert_eq!(written, 7);
    assert_eq!(output, b"abcccc!");
}

#[test]
fn rejects_rolz_deprecated_o1_unknown_context_without_mutating_destination() {
    let literal_payload = rolz_deprecated_o1_literal_payload(
        b'a',
        &[(0, 0), (b'a', 1)],
        &[b"a".to_vec(), b"bx".to_vec()],
    );
    let stored =
        rolz_deprecated_stream_with_literal_order(3, 3, 1, &literal_payload, &[], &[], &[], &[]);
    let input = standard_transform_serial_frame(
        LEGACY_LZ_LAST_VERSION,
        standard::ROLZ_DEPRECATED_ID,
        &stored,
        3,
        &[],
    );
    let plan = parse_frame_plan(&input, Limits::default()).unwrap();
    let mut output = vec![1, 2];

    let err = decode_plan(&input, &plan, &mut output, Limits::default()).unwrap_err();

    assert_eq!(err.kind(), ErrorKind::Malformed);
    assert_eq!(output, [1, 2]);
}

#[test]
fn decodes_v12_rolz_deprecated_raw_lz_sequence_frame() {
    let literals = b"abcdefghijklmnopqrstuvwxyzABCDEFG!";
    let stored = rolz_deprecated_stream(
        41,
        literals.len(),
        &legacy_entropy_raw_payload(literals, 1),
        &[0],
        &[33],
        &[0],
        &[33],
    );
    let input = standard_transform_serial_frame(
        LEGACY_LZ_LAST_VERSION,
        standard::ROLZ_DEPRECATED_ID,
        &stored,
        41,
        &[],
    );
    let plan = parse_frame_plan(&input, Limits::default()).unwrap();
    let mut output = Vec::new();

    let written = decode_plan(&input, &plan, &mut output, Limits::default()).unwrap();

    assert_eq!(written, 41);
    assert_eq!(output, b"abcdefghijklmnopqrstuvwxyzABCDEFGabcdefg!");
}

#[test]
fn decodes_v12_rolz_deprecated_bit_match_type_frame() {
    let literals = b"abcdefghijklmnopqrstuvwxyzABCDEFG!";
    let stored = rolz_deprecated_stream_with_entropy(
        41,
        literals.len(),
        0,
        &legacy_entropy_raw_payload(literals, 1),
        &legacy_entropy_bit_payload(&[0], 1),
        &[0],
        &[33],
        &[0],
        &[33],
    );
    let input = standard_transform_serial_frame(
        LEGACY_LZ_LAST_VERSION,
        standard::ROLZ_DEPRECATED_ID,
        &stored,
        41,
        &[],
    );
    let plan = parse_frame_plan(&input, Limits::default()).unwrap();
    let mut output = Vec::new();

    let written = decode_plan(&input, &plan, &mut output, Limits::default()).unwrap();

    assert_eq!(written, 41);
    assert_eq!(output, b"abcdefghijklmnopqrstuvwxyzABCDEFGabcdefg!");
}

#[test]
fn decodes_v12_rolz_deprecated_multi_match_type_frame() {
    let literals = b"abcdefghijklmnopqrstuvwxyzABCDEFG!";
    let match_type_entropy =
        legacy_entropy_multi_payload(&[legacy_entropy_constant_payload(&[0], 1)]);
    let stored = rolz_deprecated_stream_with_entropy(
        41,
        literals.len(),
        0,
        &legacy_entropy_raw_payload(literals, 1),
        &match_type_entropy,
        &[0],
        &[33],
        &[0],
        &[33],
    );
    let input = standard_transform_serial_frame(
        LEGACY_LZ_LAST_VERSION,
        standard::ROLZ_DEPRECATED_ID,
        &stored,
        41,
        &[],
    );
    let plan = parse_frame_plan(&input, Limits::default()).unwrap();
    let mut output = Vec::new();

    let written = decode_plan(&input, &plan, &mut output, Limits::default()).unwrap();

    assert_eq!(written, 41);
    assert_eq!(output, b"abcdefghijklmnopqrstuvwxyzABCDEFGabcdefg!");
}

#[test]
fn decodes_v12_rolz_deprecated_rep0_sequence_frame() {
    let literals = b"abc!";
    let stored = rolz_deprecated_stream(
        7,
        literals.len(),
        &legacy_entropy_raw_payload(literals, 1),
        &[2],
        &[3],
        &[0],
        &[0],
    );
    let input = standard_transform_serial_frame(
        LEGACY_LZ_LAST_VERSION,
        standard::ROLZ_DEPRECATED_ID,
        &stored,
        7,
        &[],
    );
    let plan = parse_frame_plan(&input, Limits::default()).unwrap();
    let mut output = Vec::new();

    let written = decode_plan(&input, &plan, &mut output, Limits::default()).unwrap();

    assert_eq!(written, 7);
    assert_eq!(output, b"abcccc!");
}

/// A rep0 match whose code carries `delta` above the rep index bits.
fn rolz_deprecated_rep0_frame(delta: usize) -> Vec<u8> {
    let literals = b"abc!";
    let stored = rolz_deprecated_stream(
        7,
        literals.len(),
        &legacy_entropy_raw_payload(literals, 1),
        &[2],
        &[3],
        &[0],
        &[delta << 2],
    );
    standard_transform_serial_frame(
        LEGACY_LZ_LAST_VERSION,
        standard::ROLZ_DEPRECATED_ID,
        &stored,
        7,
        &[],
    )
}

/// Upstream `cfcdf49`: a rep0 code may carry the neutral delta `REP_SUB`,
/// but any other delta is rejected.
#[test]
fn rejects_rolz_deprecated_rep0_code_with_offset_delta() {
    let input = rolz_deprecated_rep0_frame(4);
    let plan = parse_frame_plan(&input, Limits::default()).unwrap();
    let mut output = Vec::new();
    decode_plan(&input, &plan, &mut output, Limits::default()).unwrap();
    assert_eq!(output, b"abcccc!");

    let input = rolz_deprecated_rep0_frame(5);
    let plan = parse_frame_plan(&input, Limits::default()).unwrap();
    let mut output = vec![1, 2];
    let err = decode_plan(&input, &plan, &mut output, Limits::default()).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::Malformed);
    assert_eq!(output, [1, 2]);
}

/// `kOobReadFrame` from upstream `tests/round_trip/rolz_test_data.h`: a ROLZ
/// payload that read out of bounds in the C decoder before `cfcdf49`.
const ROLZ_OOB_READ_FRAME: [u8; 915] = [
    0x02, 0x0c, 0x04, 0x03, 0x01, 0x07, 0x03, 0x04, 0x03, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,
    0xff, 0x00, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
    0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
    0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
    0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
    0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
    0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
    0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
    0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
    0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
    0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
    0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
    0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
    0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
    0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
    0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
    0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
    0x01, 0x05, 0x02, 0x00, 0x00, 0xab, 0x20, 0x00, 0x00, 0x00, 0x03, 0x00, 0x06, 0x00, 0x09, 0x00,
    0x0c, 0x00, 0x0f, 0x00, 0x12, 0x00, 0x15, 0x00, 0x18, 0x00, 0x1b, 0x00, 0x1e, 0x00, 0x21, 0x00,
    0x24, 0x00, 0x27, 0x00, 0x2a, 0x00, 0x2d, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
    0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
    0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x05, 0x02, 0x00, 0x00, 0xab, 0x20, 0x00, 0x00, 0x00, 0x03,
    0x00, 0x06, 0x00, 0x09, 0x00, 0x0c, 0x00, 0x0f, 0x00, 0x12, 0x00, 0x15, 0x00, 0x18, 0x00, 0x1b,
    0x00, 0x1e, 0x00, 0x21, 0x00, 0x24, 0x00, 0x27, 0x00, 0x2a, 0x00, 0x2d, 0x00, 0x30, 0x00, 0x33,
    0x00, 0x36, 0x00, 0x39, 0x00, 0x3c, 0x00, 0x3f, 0x00, 0x42, 0x00, 0x45, 0x00, 0x48, 0x00, 0x4b,
    0x00, 0x4e, 0x00, 0x51, 0x00, 0x54, 0x00, 0x57, 0x00, 0x5a, 0x00, 0x5d, 0x00, 0x60, 0x00, 0x63,
    0x00, 0x66, 0x00, 0x69, 0x00, 0x6c, 0x00, 0x6f, 0x00, 0x72, 0x00, 0x75, 0x00, 0x78, 0x00, 0x7b,
    0x00, 0x7e, 0x00, 0x81, 0x00, 0x84, 0x00, 0x87, 0x00, 0x8a, 0x00, 0x8d, 0x00, 0x90, 0x00, 0x93,
    0x00, 0x96, 0x00, 0x99, 0x00, 0x9c, 0x00, 0x9f, 0x00, 0xa2, 0x00, 0xa5, 0x00, 0xa8, 0x00, 0xab,
    0x00, 0xae, 0x00, 0xb1, 0x00, 0xb4, 0x00, 0xb7, 0x00, 0xba, 0x00, 0xbd, 0x00, 0xc0, 0x00, 0xc3,
    0x00, 0xc6, 0x00, 0xc9, 0x00, 0xcc, 0x00, 0xcf, 0x00, 0xd2, 0x00, 0xd5, 0x00, 0xd8, 0x00, 0xdb,
    0x00, 0xde, 0x00, 0xe1, 0x00, 0xe4, 0x00, 0xe7, 0x00, 0xea, 0x00, 0xed, 0x00, 0xf0, 0x00, 0xf3,
    0x00, 0xf6, 0x00, 0xf9, 0x00, 0xfc, 0x00, 0xff, 0x00, 0x02, 0x00, 0x05, 0x00, 0x08, 0x00, 0x0b,
    0x00, 0x0e, 0x00, 0x11, 0x00, 0x14, 0x00, 0x17, 0x00, 0x1a, 0x00, 0x1d, 0x00, 0x20, 0x00, 0x23,
    0x00, 0x26, 0x00, 0x29, 0x00, 0x2c, 0x00, 0x2f, 0x00, 0x32, 0x00, 0x35, 0x00, 0x38, 0x00, 0x3b,
    0x00, 0x3e, 0x00, 0x41, 0x00, 0x44, 0x00, 0x47, 0x00, 0x4a, 0x00, 0x4d, 0x00, 0x50, 0x00, 0x53,
    0x00, 0x56, 0x00, 0x59, 0x00, 0x5c, 0x00, 0x5f, 0x00, 0x62, 0x00, 0x65, 0x00, 0x68, 0x00, 0x6b,
    0x00, 0x6e, 0x00, 0x71, 0x00, 0x74, 0x00, 0x77, 0x00, 0x7a, 0x00, 0x7d, 0x00, 0x80, 0x00, 0x83,
    0x00, 0x86, 0x00, 0x89, 0x00, 0x8c, 0x00, 0x8f, 0x00, 0x92, 0x00, 0x95, 0x00, 0x98, 0x00, 0x9b,
    0x00, 0x9e, 0x00, 0xa1, 0x00, 0xa4, 0x00, 0xa7, 0x00, 0xaa, 0x00, 0xad, 0x00, 0xb0, 0x00, 0xb3,
    0x00, 0xb6, 0x00, 0xb9, 0x00, 0xbc, 0x00, 0xbf, 0x00, 0xc2, 0x00, 0xc5, 0x00, 0xc8, 0x00, 0xcb,
    0x00, 0xce, 0x00, 0xd1, 0x00, 0xd4, 0x00, 0xd7, 0x00, 0xda, 0x00, 0xdd, 0x00, 0xe0, 0x00, 0xe3,
    0x00, 0xe6, 0x00, 0xe9, 0x00, 0xec, 0x00, 0xef, 0x00, 0xf2, 0x00, 0xf5, 0x00, 0xf8, 0x00, 0xfb,
    0x00, 0xfe, 0x00, 0x01, 0x6a, 0x00, 0x6d, 0x00, 0x70, 0x00, 0x73, 0x00, 0x76, 0x00, 0x79, 0x00,
    0x7c, 0x00, 0x7f, 0x00, 0x82, 0x00, 0x85, 0x00, 0x88, 0x00, 0x8b, 0x00, 0x8e, 0x00, 0x91, 0x00,
    0x94, 0x00, 0x97, 0x00, 0x9a, 0x00, 0x9d, 0x00, 0xa0, 0x00, 0xa3, 0x00, 0xa6, 0x00, 0xa9, 0x00,
    0xac, 0x00, 0xaf, 0x00, 0xb2, 0x00, 0xb5, 0x00, 0xb8, 0x00, 0xbb, 0x00, 0xbe, 0x00, 0xc1, 0x00,
    0xc4, 0x00, 0xc7, 0x00, 0xca, 0x00, 0xcd, 0x00, 0xd0, 0x00, 0xd3, 0x00, 0xd6, 0x00, 0xd9, 0x00,
    0xdc, 0x00, 0xdf, 0x00, 0xe2, 0x00, 0xe5, 0x00, 0xe8, 0x00, 0xeb, 0x00, 0xee, 0x00, 0xf1, 0x00,
    0xf4, 0x00, 0xf7, 0x00, 0xfa, 0x00, 0xfd, 0x00, 0x00, 0x00, 0x00, 0x03, 0xff, 0x00, 0x00, 0x00,
    0xfa, 0x0f, 0x00, 0x0b, 0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
    0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
    0x00, 0x04, 0x03, 0x03, 0x0b, 0x24, 0x03, 0x03, 0x03, 0x03, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00,
    0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0xf9, 0x1c, 0x03, 0x0b, 0x27, 0x03, 0x03, 0x03, 0x03, 0x01,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,
    0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x03, 0x0b, 0x00, 0x03,
    0x03, 0x03, 0x03,
];

#[test]
fn rejects_upstream_rolz_oob_read_frame() {
    let mut stored = (8u32 << 20).to_le_bytes().to_vec();
    stored.extend_from_slice(&ROLZ_OOB_READ_FRAME);
    let source = StreamInput {
        bytes: &stored,
        element_width: 1,
        string_lengths: None,
    };

    assert!(decode_rolz_deprecated_node(source, &[], Limits::default()).is_err());
}

#[test]
fn rejects_rolz_deprecated_zero_rep_offset_without_mutating_destination() {
    let stored = rolz_deprecated_stream(
        7,
        4,
        &legacy_entropy_raw_payload(b"abcd", 1),
        &[3],
        &[4],
        &[0],
        &[1],
    );
    let input = standard_transform_serial_frame(
        LEGACY_LZ_LAST_VERSION,
        standard::ROLZ_DEPRECATED_ID,
        &stored,
        7,
        &[],
    );
    let plan = parse_frame_plan(&input, Limits::default()).unwrap();
    let mut output = vec![1, 2];

    let err = decode_plan(&input, &plan, &mut output, Limits::default()).unwrap_err();

    assert_eq!(err.kind(), ErrorKind::Malformed);
    assert_eq!(output, [1, 2]);
}

#[test]
fn decodes_v12_rolz_deprecated_rolz_sequence_frame() {
    let stored = rolz_deprecated_stream(
        8,
        5,
        &legacy_entropy_raw_payload(b"abcab", 1),
        &[1],
        &[5],
        &[0],
        &[0],
    );
    let input = standard_transform_serial_frame(
        LEGACY_LZ_LAST_VERSION,
        standard::ROLZ_DEPRECATED_ID,
        &stored,
        8,
        &[],
    );
    let plan = parse_frame_plan(&input, Limits::default()).unwrap();
    let mut output = Vec::new();

    let written = decode_plan(&input, &plan, &mut output, Limits::default()).unwrap();

    assert_eq!(written, 8);
    assert_eq!(output, b"abcabcab");
}

#[test]
fn rejects_fastlz_deprecated_short_offset_without_mutating_destination() {
    let token = 1u16.to_le_bytes();
    let stored = fastlz_deprecated_stream(
        33,
        &legacy_entropy_raw_payload(b"abcdefghijklmnop!", 1),
        &legacy_entropy_raw_payload(&token, 2),
        &[1],
        &[16, 16],
    );
    let input = standard_transform_serial_frame(
        LEGACY_LZ_LAST_VERSION,
        standard::FASTLZ_DEPRECATED_ID,
        &stored,
        33,
        &[],
    );
    let plan = parse_frame_plan(&input, Limits::default()).unwrap();
    let mut output = vec![1, 2];

    let err = decode_plan(&input, &plan, &mut output, Limits::default()).unwrap_err();

    assert_eq!(err.kind(), ErrorKind::Malformed);
    assert_eq!(output, [1, 2]);
}

#[test]
fn rejects_fastlz_deprecated_full_width_bit_literals_without_mutating_destination() {
    let literal_entropy = legacy_entropy_bit_payload(&[0], 8);
    let stored = fastlz_deprecated_literal_entropy_stream(1, &literal_entropy);
    let input = standard_transform_serial_frame(
        LEGACY_LZ_LAST_VERSION,
        standard::FASTLZ_DEPRECATED_ID,
        &stored,
        1,
        &[],
    );
    let plan = parse_frame_plan(&input, Limits::default()).unwrap();
    let mut output = vec![1, 2];

    let err = decode_plan(&input, &plan, &mut output, Limits::default()).unwrap_err();

    assert_eq!(err.kind(), ErrorKind::Malformed);
    assert_eq!(output, [1, 2]);
}

#[test]
fn rejects_fastlz_deprecated_empty_multi_block_without_mutating_destination() {
    let literal_entropy = legacy_entropy_multi_payload(&[legacy_entropy_raw_payload(&[], 1)]);
    let stored = fastlz_deprecated_literal_entropy_stream(0, &literal_entropy);
    let input = standard_transform_serial_frame(
        LEGACY_LZ_LAST_VERSION,
        standard::FASTLZ_DEPRECATED_ID,
        &stored,
        0,
        &[],
    );
    let plan = parse_frame_plan(&input, Limits::default()).unwrap();
    let mut output = vec![1, 2];

    let err = decode_plan(&input, &plan, &mut output, Limits::default()).unwrap_err();

    assert_eq!(err.kind(), ErrorKind::Malformed);
    assert_eq!(output, [1, 2]);
}
