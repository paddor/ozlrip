use super::*;

const LEGACY_ENTROPY_LAST_VERSION: u32 = 14;

/// Long streams take the batched FSE loop and short ones only the checked
/// tail; both must match the encoder, and a truncated stream must fail.
#[test]
fn decodes_interleaved_fse_streams_of_every_length() {
    let cases: [(u8, &[i16]); 2] = [
        (5, &[16, 8, 4, 2, 1, 1]),
        (12, &[2048, 1024, 512, 256, 128, 64, 32, 16, 8, 4, 2, 1, 1]),
    ];
    for (accuracy_log, distribution) in cases {
        let table =
            zrip_core::fse::table_builder::build_decode_table(distribution, accuracy_log).unwrap();
        // Symbols drawn with the distribution's skew, from a fixed LCG.
        let mut seed = 0x2545_f491_u32;
        let symbols: Vec<u8> = (0..3000)
            .map(|_| {
                seed = seed.wrapping_mul(1_103_515_245).wrapping_add(12_345);
                let mut pick = i32::try_from(seed >> 20).unwrap() % (1 << accuracy_log);
                let mut symbol = 0;
                while pick >= i32::from(distribution[symbol]) {
                    pick -= i32::from(distribution[symbol]);
                    symbol += 1;
                }
                u8::try_from(symbol).unwrap()
            })
            .collect();
        for nb_states in [2, 4] {
            for len in (nb_states..40).chain([100, 1000, 2999, 3000]) {
                let symbols = &symbols[..len];
                let bits = fse_multistate_bitstream(symbols, nb_states, distribution, accuracy_log);

                let decoded =
                    entropy::decode_fse_symbols(&bits, len, nb_states, &table, accuracy_log, "t")
                        .unwrap();
                assert_eq!(
                    decoded, symbols,
                    "log {accuracy_log} states {nb_states} len {len}"
                );

                if bits.len() > 1 {
                    assert!(
                        entropy::decode_fse_symbols(
                            &bits[1..],
                            len,
                            nb_states,
                            &table,
                            accuracy_log,
                            "t"
                        )
                        .is_err(),
                        "truncated log {accuracy_log} states {nb_states} len {len}"
                    );
                }
            }
        }
    }
}

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

#[test]
fn decodes_empty_pivco_huffman_without_mutating_destination() {
    let input = pivco_huffman_frame();
    let plan = parse_frame_plan(&input, Limits::default()).unwrap();
    let mut output = vec![1, 2];

    let written = decode_plan(&input, &plan, &mut output, Limits::default()).unwrap();

    assert_eq!(written, 0);
    assert_eq!(output, [1, 2]);
}

#[test]
fn decodes_legacy_fse_raw_node() {
    let expected = b"legacy fse raw";
    let payload = legacy_entropy_raw_payload(expected, 1);
    let output = decode_fse_deprecated_node(
        StreamInput {
            bytes: &payload,
            element_width: 1,
            string_lengths: None,
        },
        &[],
        Limits::default(),
    )
    .unwrap();

    assert_eq!(output, expected);
}

#[test]
fn decodes_v14_fse_deprecated_raw_frame() {
    let expected = b"legacy fse raw frame";
    let payload = legacy_entropy_raw_payload(expected, 1);
    let input = standard_transform_serial_frame(
        LEGACY_ENTROPY_LAST_VERSION,
        standard::FSE_DEPRECATED_ID,
        &payload,
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
fn decodes_v14_fse_deprecated_bit_frame() {
    let expected = [0, 1, 2, 3, 4, 5];
    let payload = legacy_entropy_bit_payload(&[0, 1, 2, 3, 4, 5], 3);
    let input = standard_transform_serial_frame(
        LEGACY_ENTROPY_LAST_VERSION,
        standard::FSE_DEPRECATED_ID,
        &payload,
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
fn decodes_v14_fse_deprecated_fse_frame() {
    let expected = [
        0, 1, 0, 1, 1, 0, 1, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 1, 1, 0, 1, 0, 1, 0, 1, 1, 0, 0,
        1, 1, 0, 1, 0, 1, 1, 0, 1, 0,
    ];
    let payload = legacy_entropy_fse_payload(&expected, 4);
    let input = standard_transform_serial_frame(
        LEGACY_ENTROPY_LAST_VERSION,
        standard::FSE_DEPRECATED_ID,
        &payload,
        expected.len(),
        &[4],
    );
    let plan = parse_frame_plan(&input, Limits::default()).unwrap();
    let mut output = Vec::new();

    let written = decode_plan(&input, &plan, &mut output, Limits::default()).unwrap();

    assert_eq!(written, expected.len());
    assert_eq!(output, expected);
}

#[test]
fn rejects_fse_deprecated_invalid_state_count_without_mutating_destination() {
    let payload = legacy_entropy_raw_payload(b"state", 1);
    let input = standard_transform_serial_frame(
        LEGACY_ENTROPY_LAST_VERSION,
        standard::FSE_DEPRECATED_ID,
        &payload,
        5,
        &[3],
    );
    let plan = parse_frame_plan(&input, Limits::default()).unwrap();
    let mut output = vec![1, 2];

    let err = decode_plan(&input, &plan, &mut output, Limits::default()).unwrap_err();

    assert_eq!(err.kind(), ErrorKind::Malformed);
    assert_eq!(output, [1, 2]);
}

#[test]
fn decodes_v14_huffman_deprecated_constant_frame() {
    let expected = vec![b'Z'; 19];
    let payload = legacy_entropy_constant_payload(b"Z", expected.len());
    let input = standard_transform_serial_frame(
        LEGACY_ENTROPY_LAST_VERSION,
        standard::HUFFMAN_DEPRECATED_ID,
        &payload,
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
fn decodes_v14_huffman_deprecated_multi_frame() {
    let expected = b"abZZ\x01\x02";
    let payload = legacy_entropy_multi_payload(&[
        legacy_entropy_raw_payload(b"ab", 1),
        legacy_entropy_constant_payload(b"Z", 2),
        legacy_entropy_bit_payload(&[1, 2], 2),
    ]);
    let input = standard_transform_serial_frame(
        LEGACY_ENTROPY_LAST_VERSION,
        standard::HUFFMAN_DEPRECATED_ID,
        &payload,
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
fn decodes_huffman_fixed_deprecated_raw_node() {
    let expected = [0x34, 0x12, 0x78, 0x56];
    let payload = legacy_entropy_raw_payload(&expected, 2);
    let output = decode_huffman_fixed_deprecated_node(
        StreamInput {
            bytes: &payload,
            element_width: 1,
            string_lengths: None,
        },
        &[0, 2],
        21,
        Limits::default(),
    )
    .unwrap();

    assert_eq!(output.element_width, 2);
    assert_eq!(output.bytes, expected);
}

#[test]
fn decodes_huffman_fixed_deprecated_bit_node() {
    let expected = [1, 0, 2, 0, 3, 0];
    let payload = legacy_entropy_bit_payload(&[1, 2, 3], 2);
    let output = decode_huffman_fixed_deprecated_node(
        StreamInput {
            bytes: &payload,
            element_width: 1,
            string_lengths: None,
        },
        &[0, 2],
        21,
        Limits::default(),
    )
    .unwrap();

    assert_eq!(output.element_width, 2);
    assert_eq!(output.bytes, expected);
}

#[test]
fn decodes_v14_huffman_fixed_deprecated_raw_frame() {
    let expected = [0x34, 0x12, 0x78, 0x56];
    let payload = legacy_entropy_raw_payload(&expected, 2);
    let input = standard_transform_serial_frame(
        LEGACY_ENTROPY_LAST_VERSION,
        standard::HUFFMAN_FIXED_DEPRECATED_ID,
        &payload,
        expected.len(),
        &[0, 2],
    );
    let plan = parse_frame_plan(&input, Limits::default()).unwrap();
    let mut output = Vec::new();

    let written = decode_plan(&input, &plan, &mut output, Limits::default()).unwrap();

    assert_eq!(written, expected.len());
    assert_eq!(output, expected);
}

#[test]
fn rejects_truncated_legacy_huffman_header_without_mutating_destination() {
    let input = standard_transform_serial_frame(
        LEGACY_ENTROPY_LAST_VERSION,
        standard::HUFFMAN_DEPRECATED_ID,
        &[0],
        2,
        &[],
    );
    let plan = parse_frame_plan(&input, Limits::default()).unwrap();
    let mut output = vec![1, 2];

    let err = decode_plan(&input, &plan, &mut output, Limits::default()).unwrap_err();

    assert_eq!(err.kind(), ErrorKind::Malformed);
    assert_eq!(output, [1, 2]);
}

/// A legacy Huffman block holding zstd Huffman literals: the tree
/// description, then four streams.
fn legacy_entropy_huffman_payload(symbols: &[u8]) -> Vec<u8> {
    let table = zrip_core::huffman::encode::HuffmanEncodeTable::from_data(symbols).unwrap();
    let mut encoded = table.serialize_weights();
    encoded.extend_from_slice(&table.encode_4_streams(symbols));
    legacy_compressed_entropy_payload(0, symbols.len(), &encoded)
}

fn decode_huffman_deprecated(payload: &[u8]) -> Result<Vec<u8>> {
    decode_huffman_deprecated_node(
        StreamInput {
            bytes: payload,
            element_width: 1,
            string_lengths: None,
        },
        &[],
        Limits::default(),
    )
}

#[test]
fn decodes_v14_huffman_deprecated_huffman_frame() {
    let expected = b"legacy Huffman symbols: aaaaaaaabbbbccd, aaaaaaaabbbbccd".repeat(5);
    let payload = legacy_entropy_huffman_payload(&expected);
    let input = standard_transform_serial_frame(
        LEGACY_ENTROPY_LAST_VERSION,
        standard::HUFFMAN_DEPRECATED_ID,
        &payload,
        expected.len(),
        &[],
    );
    let plan = parse_frame_plan(&input, Limits::default()).unwrap();
    let mut output = Vec::new();

    let written = decode_plan(&input, &plan, &mut output, Limits::default()).unwrap();

    assert_eq!(written, expected.len());
    assert_eq!(output, expected);
}

/// Like upstream `HUF_decompress`, a block as large as its output is a copy
/// and a one-byte block is that byte repeated.
#[test]
fn decodes_legacy_huffman_copies_and_repeats() {
    let copy = legacy_compressed_entropy_payload(0, 3, b"abc");
    let repeat = legacy_compressed_entropy_payload(0, 4, b"z");

    assert_eq!(decode_huffman_deprecated(&copy).unwrap(), b"abc");
    assert_eq!(decode_huffman_deprecated(&repeat).unwrap(), b"zzzz");
}

#[test]
fn rejects_legacy_huffman_blocks_larger_than_their_output() {
    let payload = legacy_compressed_entropy_payload(0, 2, b"abc");

    let err = decode_huffman_deprecated(&payload).unwrap_err();

    assert_eq!(err.kind(), ErrorKind::Malformed);
}

/// Upstream `HUF_readStats` requires an even number of weight-one symbols,
/// at least two. Weight 2 and the implied last weight 2 have none.
#[test]
fn rejects_legacy_huffman_weights_without_weight_one_pairs() {
    let mut encoded = vec![128, 0x20];
    encoded.extend_from_slice(&[0; 10]);
    let payload = legacy_compressed_entropy_payload(0, 64, &encoded);

    let err = decode_huffman_deprecated(&payload).unwrap_err();

    assert_eq!(err.kind(), ErrorKind::Malformed);
    assert_eq!(
        err.detail(),
        Some("huffman_deprecated huffman weights are invalid")
    );
}

/// Weights 12 down to 1 and the implied last weight 1 fill a table of log
/// 12, which upstream accepts but zrip cannot decode.
#[test]
fn reports_legacy_huffman_table_log_12_as_unsupported() {
    let mut encoded = vec![127 + 12, 0xcb, 0xa9, 0x87, 0x65, 0x43, 0x21];
    encoded.extend_from_slice(&[0; 10]);
    let payload = legacy_compressed_entropy_payload(0, 64, &encoded);

    let err = decode_huffman_deprecated(&payload).unwrap_err();

    assert_eq!(err.kind(), ErrorKind::Unsupported);
}

#[test]
fn reports_legacy_avx2_huffman_layout_as_unsupported() {
    let mut payload = legacy_compressed_entropy_payload(0, 3, b"abc");
    payload[0] |= 1 << 5;

    let err = decode_huffman_deprecated(&payload).unwrap_err();

    assert_eq!(err.kind(), ErrorKind::Unsupported);
}

fn decode_huffman_fixed_deprecated_u16(payload: &[u8]) -> Result<OwnedStream> {
    decode_huffman_fixed_deprecated_node(
        StreamInput {
            bytes: payload,
            element_width: 1,
            string_lengths: None,
        },
        &[0, 2],
        LEGACY_ENTROPY_LAST_VERSION,
        Limits::default(),
    )
}

fn u16_bytes(values: &[u16]) -> Vec<u8> {
    values
        .iter()
        .flat_map(|value| value.to_le_bytes())
        .collect()
}

/// A 16-bit legacy Huffman block with two one-bit symbols.
fn legacy_entropy_large_huffman_payload(symbols: &[u16], x4: bool) -> Vec<u8> {
    legacy_compressed_entropy_payload(0, symbols.len(), &large_huffman_block(symbols, x4))
}

/// Upstream `ZS_largeHuffmanDecode` input: the Huffman prefix, table log 1,
/// largest symbol 1, raw weights, the stream layout and the streams.
fn large_huffman_block(symbols: &[u16], x4: bool) -> Vec<u8> {
    let mut encoded = vec![0, 1, 1, 0];
    encoded.extend_from_slice(&legacy_entropy_raw_payload(&[1, 1], 1));
    encoded.push(u8::from(x4));
    if x4 {
        let quarter = symbols.len().div_ceil(4);
        let mut chunks = symbols.chunks(quarter);
        let chunks = [(); 4].map(|()| chunks.next().unwrap_or(&[]));
        encoded.extend_from_slice(&huffman_struct_v2_x4_bits(&chunks));
    } else {
        encoded.extend_from_slice(&huffman_struct_v2_bits(symbols));
    }
    encoded
}

#[test]
fn decodes_legacy_huffman_16_bit_blocks() {
    let symbols = [0u16, 1, 1, 0, 1, 0, 0, 1, 1];
    for x4 in [false, true] {
        let payload = legacy_entropy_large_huffman_payload(&symbols, x4);

        let output = decode_huffman_fixed_deprecated_u16(&payload).unwrap();

        assert_eq!(output.element_width, 2);
        assert_eq!(output.bytes, u16_bytes(&symbols), "x4 {x4}");
    }
}

#[test]
fn decodes_v14_huffman_fixed_deprecated_huffman_frame() {
    let symbols = [1u16, 0, 0, 1, 1, 1];
    let payload = legacy_entropy_large_huffman_payload(&symbols, false);
    let input = standard_transform_serial_frame(
        LEGACY_ENTROPY_LAST_VERSION,
        standard::HUFFMAN_FIXED_DEPRECATED_ID,
        &payload,
        symbols.len() * 2,
        &[0, 2],
    );
    let plan = parse_frame_plan(&input, Limits::default()).unwrap();
    let mut output = Vec::new();

    decode_plan(&input, &plan, &mut output, Limits::default()).unwrap();

    assert_eq!(output, u16_bytes(&symbols));
}

#[test]
fn decodes_legacy_huffman_16_bit_literals_and_constants() {
    let literal = legacy_compressed_entropy_payload(0, 2, &[1, 2, 0x34, 0x12, 0x78, 0x56]);
    let constant = legacy_compressed_entropy_payload(0, 3, &[2, 3, 0x34, 0x12]);

    let literal = decode_huffman_fixed_deprecated_u16(&literal).unwrap();
    let constant = decode_huffman_fixed_deprecated_u16(&constant).unwrap();

    assert_eq!(literal.bytes, u16_bytes(&[0x1234, 0x5678]));
    assert_eq!(constant.bytes, u16_bytes(&[0x1234; 3]));
}

#[test]
fn rejects_malformed_legacy_huffman_16_bit_blocks() {
    let mut wrong_table_log = large_huffman_block(&[0, 1], false);
    wrong_table_log[1] = 2;
    let cases = [
        (&[3, 1, 0, 0][..], 1, "huffman block prefix is invalid"),
        (&[1, 1, 0, 0], 2, "huffman symbol count is invalid"),
        (&[2, 2, 0], 2, "huffman constant size is invalid"),
        (&wrong_table_log, 2, "huffman weights are not normalized"),
    ];
    for (encoded, symbols, detail) in cases {
        let payload = legacy_compressed_entropy_payload(0, symbols, encoded);

        let err = decode_huffman_fixed_deprecated_u16(&payload).unwrap_err();

        assert_eq!(err.kind(), ErrorKind::Malformed, "{detail}");
        assert_eq!(
            err.detail(),
            Some(format!("huffman_fixed_deprecated {detail}").as_str())
        );
    }
}

#[test]
fn rejects_deprecated_entropy_full_width_bit_mode_without_mutating_destination() {
    let payload = legacy_entropy_bit_payload(&[0], 8);
    let input = standard_transform_serial_frame(
        LEGACY_ENTROPY_LAST_VERSION,
        standard::HUFFMAN_DEPRECATED_ID,
        &payload,
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
fn rejects_deprecated_entropy_empty_multi_block_without_mutating_destination() {
    let payload = legacy_entropy_multi_payload(&[legacy_entropy_raw_payload(&[], 1)]);
    let input = standard_transform_serial_frame(
        LEGACY_ENTROPY_LAST_VERSION,
        standard::HUFFMAN_DEPRECATED_ID,
        &payload,
        0,
        &[],
    );
    let plan = parse_frame_plan(&input, Limits::default()).unwrap();
    let mut output = vec![1, 2];

    let err = decode_plan(&input, &plan, &mut output, Limits::default()).unwrap_err();

    assert_eq!(err.kind(), ErrorKind::Malformed);
    assert_eq!(output, [1, 2]);
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
        .as_chunks::<2>()
        .0
        .iter()
        .map(|bytes| i16::from_le_bytes(*bytes))
        .collect::<Vec<_>>();
    assert_eq!(output.element_width, 2);
    assert_eq!(decoded, distribution);
}

#[test]
fn decodes_v21_fse_ncount_frame() {
    let distribution = [15, 8, 4, 3, 1, 1];
    let encoded = zrip_core::fse::table_builder::serialize_fse_table_description(&distribution, 5);
    let input = standard_transform_serial_frame(21, 52, &encoded, 12, &[]);
    let plan = parse_frame_plan(&input, Limits::default()).unwrap();
    let mut output = Vec::new();

    let written = decode_plan(&input, &plan, &mut output, Limits::default()).unwrap();

    assert_eq!(written, 12);
    assert_eq!(
        output,
        distribution
            .into_iter()
            .flat_map(i16::to_le_bytes)
            .collect::<Vec<_>>()
    );
}

#[test]
fn decodes_v21_fse_v2_frame() {
    let distribution = [16i16, 16];
    let norm = distribution
        .into_iter()
        .flat_map(i16::to_le_bytes)
        .collect::<Vec<_>>();
    let accuracy_log = 5;
    let table =
        zrip_core::fse::table_builder::build_decode_table(&distribution, accuracy_log).unwrap();
    let expected = [0, 1];
    let states = expected
        .iter()
        .copied()
        .map(|symbol| {
            table
                .iter()
                .position(|entry| entry.symbol == symbol)
                .unwrap()
        })
        .collect::<Vec<_>>();
    let bits = reverse_bitstream(&states, accuracy_log);
    let output_len = u8::try_from(expected.len()).unwrap();
    let input = standard_graph_serial_frame_with_distances(
        21,
        expected.len(),
        &[
            StandardGraphNode {
                transform_id: standard::CONVERT_NUM_TO_SERIAL_LE_ID,
                variable_inputs: 0,
                outputs: 1,
                header: &[1],
            },
            StandardGraphNode {
                transform_id: standard::FSE_V2_ID,
                variable_inputs: 0,
                outputs: 1,
                header: &[2, output_len],
            },
        ],
        &[&bits, &norm],
        &[1, 0],
    );
    let plan = parse_frame_plan(&input, Limits::default()).unwrap();
    let mut output = Vec::new();

    let written = decode_plan(&input, &plan, &mut output, Limits::default()).unwrap();

    assert_eq!(written, expected.len());
    assert_eq!(output, expected);
}

#[test]
fn rejects_fse_v2_output_shorter_than_state_count() {
    let distribution = [16i16, 16];
    let norm = distribution
        .into_iter()
        .flat_map(i16::to_le_bytes)
        .collect::<Vec<_>>();

    let err = decode_fse_v2_node(
        &[
            StreamInput {
                bytes: &norm,
                element_width: 2,
                string_lengths: None,
            },
            StreamInput {
                bytes: &[],
                element_width: 1,
                string_lengths: None,
            },
        ],
        &[4, 2],
        Limits::default(),
    )
    .unwrap_err();

    assert_eq!(err.kind(), ErrorKind::Malformed);
}

#[test]
fn decodes_v21_huffman_v2_frame() {
    let expected = [0, 1, 1, 0];
    let output_len = u8::try_from(expected.len()).unwrap();
    let mut writer = zrip_core::bitstream::writer::BitWriter::new();
    for &symbol in expected.iter().rev() {
        writer.write_bits(u32::from(symbol), 1);
    }
    writer.close_reverse_stream();
    let bits = writer.into_bytes();
    let input = standard_graph_serial_frame(
        21,
        expected.len(),
        &[StandardGraphNode {
            transform_id: standard::HUFFMAN_V2_ID,
            variable_inputs: 0,
            outputs: 1,
            header: &[0, output_len],
        }],
        &[&[1, 1], &bits],
    );
    let plan = parse_frame_plan(&input, Limits::default()).unwrap();
    let mut output = Vec::new();

    let written = decode_plan(&input, &plan, &mut output, Limits::default()).unwrap();

    assert_eq!(written, expected.len());
    assert_eq!(output, expected);
}

/// The format allows table log 12, but upstream encoders never exceed 11 and
/// zrip decodes at most 11, so log 12 is a typed `Unsupported`.
#[test]
fn reports_huffman_v2_table_log_12_as_unsupported() {
    let err = decode_huffman_v2_node(
        &[
            StreamInput {
                bytes: &[12, 12],
                element_width: 1,
                string_lengths: None,
            },
            StreamInput {
                bytes: &[0x80],
                element_width: 1,
                string_lengths: None,
            },
        ],
        &[0, 2],
        Limits::default(),
    )
    .unwrap_err();

    assert_eq!(err.kind(), ErrorKind::Unsupported, "{err}");
}

/// zrip's x4 decoder indexes a fixed-size table, so a table log below its
/// maximum still needs a full-size table.
#[test]
fn decodes_huffman_v2_x4_node_with_small_table_log() {
    let expected = [0u8, 1, 1, 0, 1, 0, 0, 1];
    let streams: Vec<_> = expected
        .as_chunks::<2>()
        .0
        .iter()
        .map(|symbols| {
            let mut writer = zrip_core::bitstream::writer::BitWriter::new();
            for &symbol in symbols.iter().rev() {
                writer.write_bits(u32::from(symbol), 1);
            }
            writer.close_reverse_stream();
            writer.into_bytes()
        })
        .collect();
    let mut bits = Vec::new();
    for stream in &streams[..3] {
        bits.extend_from_slice(&u16::try_from(stream.len()).unwrap().to_le_bytes());
    }
    for stream in &streams {
        bits.extend_from_slice(stream);
    }

    let output = decode_huffman_v2_node(
        &[
            StreamInput {
                bytes: &[1, 1],
                element_width: 1,
                string_lengths: None,
            },
            StreamInput {
                bytes: &bits,
                element_width: 1,
                string_lengths: None,
            },
        ],
        &[1, u8::try_from(expected.len()).unwrap()],
        Limits::default(),
    )
    .unwrap();

    assert_eq!(output, expected);
}

#[test]
fn decodes_huffman_struct_v2_node() {
    let expected = [0u16, 1, 1, 0];
    let bits = huffman_struct_v2_bits(&expected);
    let output = decode_huffman_struct_v2_node(
        &[
            StreamInput {
                bytes: &[1, 1],
                element_width: 1,
                string_lengths: None,
            },
            StreamInput {
                bytes: &bits,
                element_width: 1,
                string_lengths: None,
            },
        ],
        &[0, u8::try_from(expected.len()).unwrap()],
        Limits::default(),
    )
    .unwrap();

    assert_eq!(output.element_width, 2);
    assert_eq!(
        output.bytes,
        expected
            .into_iter()
            .flat_map(u16::to_le_bytes)
            .collect::<Vec<_>>()
    );
}

#[test]
fn decodes_huffman_struct_v2_x4_node() {
    let expected = [0u16, 1, 1, 0];
    let chunks = [
        &expected[0..1],
        &expected[1..2],
        &expected[2..3],
        &expected[3..4],
    ];
    let bits = huffman_struct_v2_x4_bits(&chunks);
    let output = decode_huffman_struct_v2_node(
        &[
            StreamInput {
                bytes: &[1, 1],
                element_width: 1,
                string_lengths: None,
            },
            StreamInput {
                bytes: &bits,
                element_width: 1,
                string_lengths: None,
            },
        ],
        &[1, u8::try_from(expected.len()).unwrap()],
        Limits::default(),
    )
    .unwrap();

    assert_eq!(output.element_width, 2);
    assert_eq!(
        output.bytes,
        expected
            .into_iter()
            .flat_map(u16::to_le_bytes)
            .collect::<Vec<_>>()
    );
}

#[test]
fn decodes_v21_huffman_struct_v2_frame() {
    let expected = [0u16, 1, 1, 0];
    let bits = huffman_struct_v2_bits(&expected);
    let output_len = u8::try_from(expected.len()).unwrap();
    let input = standard_graph_serial_frame(
        21,
        expected.len() * 2,
        &[StandardGraphNode {
            transform_id: standard::HUFFMAN_STRUCT_V2_ID,
            variable_inputs: 0,
            outputs: 1,
            header: &[0, output_len],
        }],
        &[&[1, 1], &bits],
    );
    let plan = parse_frame_plan(&input, Limits::default()).unwrap();
    let mut output = Vec::new();

    let written = decode_plan(&input, &plan, &mut output, Limits::default()).unwrap();

    assert_eq!(written, expected.len() * 2);
    assert_eq!(
        output,
        expected
            .into_iter()
            .flat_map(u16::to_le_bytes)
            .collect::<Vec<_>>()
    );
}

fn huffman_struct_v2_bits(symbols: &[u16]) -> Vec<u8> {
    let stream = huffman_struct_v2_stream(symbols);
    let mut bits = Vec::new();
    bits.extend_from_slice(&u32::try_from(symbols.len()).unwrap().to_le_bytes());
    bits.extend_from_slice(&u32::try_from(stream.len()).unwrap().to_le_bytes());
    bits.extend_from_slice(&stream);
    bits
}

fn huffman_struct_v2_x4_bits(chunks: &[&[u16]; 4]) -> Vec<u8> {
    let mut bits = Vec::new();
    for symbols in chunks {
        let stream = huffman_struct_v2_stream(symbols);
        bits.extend_from_slice(&u32::try_from(symbols.len()).unwrap().to_le_bytes());
        bits.extend_from_slice(&u32::try_from(stream.len()).unwrap().to_le_bytes());
        bits.extend_from_slice(&stream);
    }
    bits
}

fn huffman_struct_v2_stream(symbols: &[u16]) -> Vec<u8> {
    let mut writer = zrip_core::bitstream::writer::BitWriter::new();
    for &symbol in symbols.iter().rev() {
        writer.write_bits(u32::from(symbol), 1);
    }
    writer.close_reverse_stream();
    writer.into_bytes()
}

fn reverse_bitstream(values: &[usize], bits: u8) -> Vec<u8> {
    let mut writer = zrip_core::bitstream::writer::BitWriter::new();
    for &value in values.iter().rev() {
        writer.write_bits(u32::try_from(value).unwrap(), bits);
    }
    writer.close_reverse_stream();
    writer.into_bytes()
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
