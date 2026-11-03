use super::*;

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

#[test]
fn decodes_v24_partition_graph() {
    let input = standard_graph_serial_frame(
        24,
        6,
        &[StandardGraphNode {
            transform_id: standard::PARTITION_ID,
            variable_inputs: 0,
            outputs: 1,
            header: &[0x15],
        }],
        &[&[0, 1, 2], &[0x0d]],
    );
    let plan = parse_frame_plan(&input, Limits::default()).unwrap();
    let mut output = Vec::new();

    let written = decode_plan(&input, &plan, &mut output, Limits::default()).unwrap();

    assert_eq!(written, 6);
    assert_eq!(output, [1, 0, 2, 0, 7, 0]);
}

#[test]
fn decodes_quantize_offsets_node() {
    let inputs = [
        StreamInput {
            bytes: &[0, 1, 4],
            element_width: 1,
            string_lengths: None,
        },
        StreamInput {
            bytes: &[0b0000_1011],
            element_width: 1,
            string_lengths: None,
        },
    ];

    let output = decode_quantize_node(&inputs, &[], Limits::default(), &QUANTIZE_OFFSETS).unwrap();

    assert_eq!(output.element_width, 4);
    assert_eq!(output.bytes, [1, 0, 0, 0, 3, 0, 0, 0, 21, 0, 0, 0]);
}

#[test]
fn decodes_v21_quantize_offsets_graph() {
    let input = standard_graph_serial_frame(
        21,
        12,
        &[StandardGraphNode {
            transform_id: standard::QUANTIZE_OFFSETS_ID,
            variable_inputs: 0,
            outputs: 1,
            header: &[],
        }],
        &[&[0, 1, 4], &[0b0000_1011]],
    );
    let plan = parse_frame_plan(&input, Limits::default()).unwrap();
    let mut output = Vec::new();

    let written = decode_plan(&input, &plan, &mut output, Limits::default()).unwrap();

    assert_eq!(written, 12);
    assert_eq!(output, [1, 0, 0, 0, 3, 0, 0, 0, 21, 0, 0, 0]);
}

#[test]
fn decodes_quantize_lengths_node() {
    let inputs = [
        StreamInput {
            bytes: &[0, 15, 16],
            element_width: 1,
            string_lengths: None,
        },
        StreamInput {
            bytes: &[0b0000_0111],
            element_width: 1,
            string_lengths: None,
        },
    ];

    let output = decode_quantize_node(&inputs, &[], Limits::default(), &QUANTIZE_LENGTHS).unwrap();

    assert_eq!(output.element_width, 4);
    assert_eq!(output.bytes, [0, 0, 0, 0, 15, 0, 0, 0, 23, 0, 0, 0]);
}

#[test]
fn decodes_v21_quantize_lengths_graph() {
    let input = standard_graph_serial_frame(
        21,
        12,
        &[StandardGraphNode {
            transform_id: standard::QUANTIZE_LENGTHS_ID,
            variable_inputs: 0,
            outputs: 1,
            header: &[],
        }],
        &[&[0, 15, 16], &[0b0000_0111]],
    );
    let plan = parse_frame_plan(&input, Limits::default()).unwrap();
    let mut output = Vec::new();

    let written = decode_plan(&input, &plan, &mut output, Limits::default()).unwrap();

    assert_eq!(written, 12);
    assert_eq!(output, [0, 0, 0, 0, 15, 0, 0, 0, 23, 0, 0, 0]);
}

#[test]
fn rejects_quantize_out_of_range_code() {
    let inputs = [
        StreamInput {
            bytes: &[32],
            element_width: 1,
            string_lengths: None,
        },
        StreamInput {
            bytes: &[],
            element_width: 1,
            string_lengths: None,
        },
    ];

    let err = decode_quantize_node(&inputs, &[], Limits::default(), &QUANTIZE_OFFSETS).unwrap_err();

    assert_eq!(err.kind(), ErrorKind::Malformed);
}

#[test]
fn rejects_quantize_nonzero_padding() {
    let inputs = [
        StreamInput {
            bytes: &[1],
            element_width: 1,
            string_lengths: None,
        },
        StreamInput {
            bytes: &[0b0000_0011],
            element_width: 1,
            string_lengths: None,
        },
    ];

    let err = decode_quantize_node(&inputs, &[], Limits::default(), &QUANTIZE_OFFSETS).unwrap_err();

    assert_eq!(err.kind(), ErrorKind::Malformed);
}
