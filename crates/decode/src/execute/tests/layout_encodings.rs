use super::*;

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
