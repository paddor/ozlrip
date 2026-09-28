use super::*;

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
        2,
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
fn decodes_float_deconstruct_outputs() {
    let float32 = decode_float_deconstruct_node(
        &[
            StreamInput {
                bytes: &[0, 0, 0, 1, 0, 0x40],
                element_width: 3,
                string_lengths: None,
            },
            StreamInput {
                bytes: &[0x7f, 0x80],
                element_width: 1,
                string_lengths: None,
            },
        ],
        &[0],
        21,
        Limits::default(),
    )
    .unwrap();
    assert_eq!(float32.element_width, 4);
    assert_eq!(float32.bytes, [0, 0, 0x80, 0x3f, 0, 0, 0x20, 0xc0]);

    let bfloat16 = decode_float_deconstruct_node(
        &[
            StreamInput {
                bytes: &[0, 0x41],
                element_width: 1,
                string_lengths: None,
            },
            StreamInput {
                bytes: &[0x7f, 0x80],
                element_width: 1,
                string_lengths: None,
            },
        ],
        &[1],
        21,
        Limits::default(),
    )
    .unwrap();
    assert_eq!(bfloat16.element_width, 2);
    assert_eq!(bfloat16.bytes, [0x80, 0x3f, 0x20, 0xc0]);

    let float16 = decode_float_deconstruct_node(
        &[
            StreamInput {
                bytes: &[0, 0, 1, 2],
                element_width: 2,
                string_lengths: None,
            },
            StreamInput {
                bytes: &[0x0f, 0x10],
                element_width: 1,
                string_lengths: None,
            },
        ],
        &[2],
        21,
        Limits::default(),
    )
    .unwrap();
    assert_eq!(float16.element_width, 2);
    assert_eq!(float16.bytes, [0, 0x3c, 0, 0xc1]);
}

#[test]
fn decodes_v4_float_deconstruct_default_float32() {
    let output = decode_float_deconstruct_node(
        &[
            StreamInput {
                bytes: &[0, 0, 0],
                element_width: 3,
                string_lengths: None,
            },
            StreamInput {
                bytes: &[0x7f],
                element_width: 1,
                string_lengths: None,
            },
        ],
        &[],
        4,
        Limits::default(),
    )
    .unwrap();

    assert_eq!(output.element_width, 4);
    assert_eq!(output.bytes, [0, 0, 0x80, 0x3f]);
}

#[test]
fn decodes_merge_sorted_outputs() {
    let merged = [1u32, 2, 3, 5, 9]
        .into_iter()
        .flat_map(u32::to_le_bytes)
        .collect::<Vec<_>>();
    let output = decode_merge_sorted_node(
        &[
            StreamInput {
                bytes: &[1, 2, 3, 3, 2],
                element_width: 1,
                string_lengths: None,
            },
            StreamInput {
                bytes: &merged,
                element_width: 4,
                string_lengths: None,
            },
        ],
        &[3, 4],
        Limits::default(),
    )
    .unwrap();

    assert_eq!(output.element_width, 4);
    assert_eq!(
        output.bytes,
        [1u32, 3, 5, 2, 3, 5, 9]
            .into_iter()
            .flat_map(u32::to_le_bytes)
            .collect::<Vec<_>>()
    );
}

/// A size table longer than the graph's output list is rejected before any
/// output is reserved, for typed and string concat.
#[test]
fn rejects_concat_size_table_longer_than_graph_outputs() {
    let sizes = [0u32; 1024].map(u32::to_le_bytes).concat();
    let sizes = StreamInput {
        bytes: &sizes,
        element_width: 4,
        string_lengths: None,
    };
    let typed = StreamInput {
        bytes: &[],
        element_width: 2,
        string_lengths: None,
    };
    let strings = StreamInput {
        bytes: &[],
        element_width: 1,
        string_lengths: Some(&[]),
    };

    let err = decode_concat_node(&[sizes, typed], &[], 1, Limits::default()).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::InvalidGraph);
    let err = decode_concat_string_node(&[sizes, strings], &[], 1, Limits::default()).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::InvalidGraph);
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
        1,
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
    let mut limits = Limits::default();
    limits.max_decoded_bytes = 8;
    limits.max_buffer_bytes = 8;

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
fn decodes_splitn_num_node() {
    let mut scratch = DecodeScratch::new();
    let mut dict_store = DictionaryStore::new();
    #[cfg(feature = "zstd")]
    let mut zstd = None;
    let mut ctx = StandardNodeContext {
        format_version: 21,
        limits: Limits::default(),
        scratch: &mut scratch,
        dictionary_bundle_id: None,
        dict_store: &mut dict_store,
        #[cfg(feature = "zstd")]
        zstd: &mut zstd,
    };
    let outputs = execute_standard_node(
        standard::SPLITN_NUM_ID,
        &[
            StreamInput {
                bytes: &[1, 0, 2, 0],
                element_width: 2,
                string_lengths: None,
            },
            StreamInput {
                bytes: &[3, 0],
                element_width: 2,
                string_lengths: None,
            },
        ],
        2,
        1,
        None,
        &[],
        &mut ctx,
    )
    .unwrap();
    assert_eq!(outputs.len(), 1);
    let output = &outputs[0];

    assert_eq!(output.element_width, 2);
    assert_eq!(output.bytes, [1, 0, 2, 0, 3, 0]);
}

#[test]
fn decodes_v21_splitn_struct_graph() {
    let input = standard_graph_serial_frame(
        21,
        6,
        &[StandardGraphNode {
            transform_id: standard::SPLITN_STRUCT_ID,
            variable_inputs: 2,
            outputs: 1,
            header: &[],
        }],
        &[b"abc", b"def"],
    );
    let plan = parse_frame_plan(&input, Limits::default()).unwrap();
    let mut output = Vec::new();

    let written = decode_plan(&input, &plan, &mut output, Limits::default()).unwrap();

    assert_eq!(written, 6);
    assert_eq!(output, b"abcdef");
}

#[test]
fn decodes_v21_splitn_num_graph() {
    let input = standard_graph_serial_frame(
        21,
        4,
        &[StandardGraphNode {
            transform_id: standard::SPLITN_NUM_ID,
            variable_inputs: 2,
            outputs: 1,
            header: &[],
        }],
        &[&[1, 2], &[3, 4]],
    );
    let plan = parse_frame_plan(&input, Limits::default()).unwrap();
    let mut output = Vec::new();

    let written = decode_plan(&input, &plan, &mut output, Limits::default()).unwrap();

    assert_eq!(written, 4);
    assert_eq!(output, [1, 2, 3, 4]);
}

#[test]
fn decodes_empty_splitn_num_header_width() {
    let output = decode_splitn_typed_node(&[], 0, &[4], Limits::default()).unwrap();

    assert_eq!(output.element_width, 4);
    assert!(output.bytes.is_empty());
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

/// The split_by_struct -> splitn direct-append tail applies splitn's width
/// check: a 2-byte struct stream cannot join split_by_struct's byte output.
#[test]
fn split_by_struct_splitn_tail_rejects_mismatched_input_widths() {
    let input = standard_graph_serial_frame_with_distances(
        21,
        6,
        &[
            // Decodes serial to 2-byte structs.
            StandardGraphNode {
                transform_id: standard::CONVERT_STRUCT_TO_SERIAL_ID,
                variable_inputs: 0,
                outputs: 1,
                header: &[2],
            },
            StandardGraphNode {
                transform_id: standard::SPLIT_BY_STRUCT_ID,
                variable_inputs: 2,
                outputs: 1,
                header: &[],
            },
            StandardGraphNode {
                transform_id: standard::SPLITN_ID,
                variable_inputs: 2,
                outputs: 1,
                header: &[],
            },
        ],
        &[b"ab", b"cd", b"ef"],
        &[2, 1, 0],
    );
    let plan = parse_frame_plan(&input, Limits::default()).unwrap();
    let mut output = Vec::new();

    let err = decode_plan(&input, &plan, &mut output, Limits::default()).unwrap_err();

    assert_eq!(err.kind(), ErrorKind::InvalidType, "{err}");
    assert!(output.is_empty());
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
    let mut limits = Limits::default();
    limits.max_decoded_bytes = 8;
    limits.max_buffer_bytes = 8;

    let err = decode_plan(&input, &plan, &mut output, limits).unwrap_err();

    assert_eq!(err.kind(), ErrorKind::LimitExceeded);
    assert_eq!(output, [1, 2]);
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
fn decodes_v24_mux_lengths_graph_final_match_lengths() {
    let input = standard_graph_serial_frame(
        24,
        1,
        &[StandardGraphNode {
            transform_id: standard::MUX_LENGTHS_ID,
            variable_inputs: 0,
            outputs: 2,
            header: &[0x24],
        }],
        &[&[0x21], &[]],
    );
    let plan = parse_frame_plan(&input, Limits::default()).unwrap();
    let mut output = Vec::new();

    let written = decode_plan(&input, &plan, &mut output, Limits::default()).unwrap();

    assert_eq!(written, 1);
    assert_eq!(output, [4]);
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
fn decodes_v24_bitsplit_bf16_graph() {
    let input = standard_graph_serial_frame(
        24,
        4,
        &[StandardGraphNode {
            transform_id: standard::BIT_SPLIT_ID,
            variable_inputs: 3,
            outputs: 1,
            header: &[2, 7, 8],
        }],
        &[&[0x01, 0x7f], &[0x02, 0xff], &[0x00, 0x01]],
    );
    let plan = parse_frame_plan(&input, Limits::default()).unwrap();
    let mut output = Vec::new();

    let written = decode_plan(&input, &plan, &mut output, Limits::default()).unwrap();

    assert_eq!(written, 4);
    assert_eq!(output, [0x01, 0x01, 0xff, 0xff]);
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
fn decodes_v24_sentinel_graph() {
    let input = standard_graph_serial_frame(
        24,
        3,
        &[StandardGraphNode {
            transform_id: standard::SENTINEL_ID,
            variable_inputs: 0,
            outputs: 1,
            header: &[],
        }],
        &[&[1, 255, 2], &[42]],
    );
    let plan = parse_frame_plan(&input, Limits::default()).unwrap();
    let mut output = Vec::new();

    let written = decode_plan(&input, &plan, &mut output, Limits::default()).unwrap();

    assert_eq!(written, 3);
    assert_eq!(output, [1, 42, 2]);
}

#[test]
fn decodes_v26_sparse_num_graph() {
    let input = standard_graph_serial_frame(
        26,
        5,
        &[StandardGraphNode {
            transform_id: standard::SPARSE_NUM_ID,
            variable_inputs: 0,
            outputs: 1,
            header: &[7],
        }],
        &[&[2, 0, 1], &[1, 2]],
    );
    let plan = parse_frame_plan(&input, Limits::default()).unwrap();
    let mut output = Vec::new();

    let written = decode_plan(&input, &plan, &mut output, Limits::default()).unwrap();

    assert_eq!(written, 5);
    assert_eq!(output, [7, 7, 1, 2, 7]);
}

#[test]
fn decodes_v21_float_deconstruct_graph_to_serial() {
    let input = standard_graph_serial_frame_with_distances(
        21,
        8,
        &[
            StandardGraphNode {
                transform_id: standard::CONVERT_STRUCT_TO_SERIAL_ID,
                variable_inputs: 0,
                outputs: 1,
                header: &[3],
            },
            StandardGraphNode {
                transform_id: standard::FLOAT_DECONSTRUCT_ID,
                variable_inputs: 0,
                outputs: 1,
                header: &[0],
            },
            StandardGraphNode {
                transform_id: standard::CONVERT_NUM_TO_SERIAL_LE_ID,
                variable_inputs: 0,
                outputs: 1,
                header: &[2],
            },
        ],
        &[&[0x7f, 0x80], &[0, 0, 0, 1, 0, 0x40]],
        &[1, 0, 0],
    );
    let plan = parse_frame_plan(&input, Limits::default()).unwrap();
    let mut output = Vec::new();

    let written = decode_plan(&input, &plan, &mut output, Limits::default()).unwrap();

    assert_eq!(written, 8);
    assert_eq!(output, [0, 0, 0x80, 0x3f, 0, 0, 0x20, 0xc0]);
}

#[test]
fn decodes_v21_merge_sorted_graph_to_serial() {
    let merged = [1u32, 2, 3, 5, 9]
        .into_iter()
        .flat_map(u32::to_le_bytes)
        .collect::<Vec<_>>();
    let input = standard_graph_serial_frame_with_distances(
        21,
        28,
        &[
            StandardGraphNode {
                transform_id: standard::CONVERT_STRUCT_TO_SERIAL_ID,
                variable_inputs: 0,
                outputs: 1,
                header: &[1],
            },
            StandardGraphNode {
                transform_id: standard::CONVERT_STRUCT_TO_SERIAL_ID,
                variable_inputs: 0,
                outputs: 1,
                header: &[4],
            },
            StandardGraphNode {
                transform_id: standard::MERGE_SORTED_ID,
                variable_inputs: 0,
                outputs: 1,
                header: &[3, 4],
            },
            StandardGraphNode {
                transform_id: standard::CONVERT_NUM_TO_SERIAL_LE_ID,
                variable_inputs: 0,
                outputs: 1,
                header: &[2],
            },
        ],
        &[&merged, &[1, 2, 3, 3, 2]],
        &[2, 0, 0, 0],
    );
    let plan = parse_frame_plan(&input, Limits::default()).unwrap();
    let mut output = Vec::new();

    let written = decode_plan(&input, &plan, &mut output, Limits::default()).unwrap();

    assert_eq!(written, 28);
    assert_eq!(
        output,
        [1u32, 3, 5, 2, 3, 5, 9]
            .into_iter()
            .flat_map(u32::to_le_bytes)
            .collect::<Vec<_>>()
    );
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
fn decodes_v21_concat_num_graph_final_output() {
    let sizes = [2u32.to_le_bytes(), 3u32.to_le_bytes()].concat();
    let input = standard_graph_serial_frame(
        21,
        3,
        &[StandardGraphNode {
            transform_id: standard::CONCAT_NUM_ID,
            variable_inputs: 0,
            outputs: 2,
            header: &[],
        }],
        &[&sizes, &[10, 11, 12, 13, 14]],
    );
    let plan = parse_frame_plan(&input, Limits::default()).unwrap();
    let mut output = Vec::new();

    let written = decode_plan(&input, &plan, &mut output, Limits::default()).unwrap();

    assert_eq!(written, 3);
    assert_eq!(output, [12, 13, 14]);
}

#[test]
fn decodes_v21_concat_struct_graph_final_output() {
    let sizes = [1u32.to_le_bytes(), 2u32.to_le_bytes()].concat();
    let input = standard_graph_serial_frame(
        21,
        2,
        &[StandardGraphNode {
            transform_id: standard::CONCAT_STRUCT_ID,
            variable_inputs: 0,
            outputs: 2,
            header: &[],
        }],
        &[&sizes, b"abc"],
    );
    let plan = parse_frame_plan(&input, Limits::default()).unwrap();
    let mut output = Vec::new();

    let written = decode_plan(&input, &plan, &mut output, Limits::default()).unwrap();

    assert_eq!(written, 2);
    assert_eq!(output, b"bc");
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
    let mut limits = Limits::default();
    limits.max_decoded_bytes = 4;
    limits.max_buffer_bytes = 4;

    let err = decode_plan(&input, &plan, &mut output, limits).unwrap_err();

    assert_eq!(err.kind(), ErrorKind::LimitExceeded);
    assert_eq!(output, [1, 2]);
}

#[test]
fn decodes_transpose_node() {
    let mut scratch = DecodeScratch::new();
    let output = decode_transpose_node(
        StreamInput {
            bytes: b"13572468",
            element_width: 4,
            string_lengths: None,
        },
        &[],
        Limits::default(),
        &mut scratch,
    )
    .unwrap();

    assert_eq!(output.element_width, 2);
    assert_eq!(output.bytes, b"12345678");
}

#[test]
fn decodes_v21_transpose_graph() {
    let input = standard_graph_serial_frame_with_distances(
        21,
        8,
        &[
            StandardGraphNode {
                transform_id: standard::BITPACK_INT_ID,
                variable_inputs: 0,
                outputs: 1,
                header: &[0x9f],
            },
            StandardGraphNode {
                transform_id: standard::TRANSPOSE_ID,
                variable_inputs: 0,
                outputs: 1,
                header: &[],
            },
        ],
        &[b"13572468"],
        &[0, 0],
    );
    let plan = parse_frame_plan(&input, Limits::default()).unwrap();
    let mut output = Vec::new();

    let written = decode_plan(&input, &plan, &mut output, Limits::default()).unwrap();

    assert_eq!(written, 8);
    assert_eq!(output, b"12345678");
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
fn decodes_v21_tokenize_fixed_graph() {
    let input = standard_graph_serial_frame(
        21,
        3,
        &[StandardGraphNode {
            transform_id: standard::TOKENIZE_FIXED_ID,
            variable_inputs: 0,
            outputs: 1,
            header: &[],
        }],
        &[b"abc", &[2, 0, 1]],
    );
    let plan = parse_frame_plan(&input, Limits::default()).unwrap();
    let mut output = Vec::new();

    let written = decode_plan(&input, &plan, &mut output, Limits::default()).unwrap();

    assert_eq!(written, 3);
    assert_eq!(output, b"cab");
}

#[test]
fn decodes_v21_tokenize_numeric_graph() {
    let input = standard_graph_serial_frame(
        21,
        3,
        &[StandardGraphNode {
            transform_id: standard::TOKENIZE_NUMERIC_ID,
            variable_inputs: 0,
            outputs: 1,
            header: &[],
        }],
        &[b"wxy", &[1, 2, 0]],
    );
    let plan = parse_frame_plan(&input, Limits::default()).unwrap();
    let mut output = Vec::new();

    let written = decode_plan(&input, &plan, &mut output, Limits::default()).unwrap();

    assert_eq!(written, 3);
    assert_eq!(output, b"xyw");
}
