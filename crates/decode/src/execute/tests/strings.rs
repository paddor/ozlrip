use super::*;

#[test]
fn decodes_concat_string_outputs() {
    let sizes = [2u32.to_le_bytes(), 1u32.to_le_bytes()].concat();
    let string_lengths = [1, 2, 3];
    let outputs = decode_concat_string_node(
        &[
            StreamInput {
                bytes: &sizes,
                element_width: 4,
                string_lengths: None,
            },
            StreamInput {
                bytes: b"aBBccc",
                element_width: 1,
                string_lengths: Some(&string_lengths),
            },
        ],
        &[],
        2,
        Limits::default(),
    )
    .unwrap();

    assert_eq!(outputs.len(), 2);
    assert_eq!(outputs[0].bytes, b"aBB");
    assert_eq!(
        outputs[0].string_lengths.as_deref(),
        Some([1, 2].as_slice())
    );
    assert_eq!(outputs[1].bytes, b"ccc");
    assert_eq!(outputs[1].string_lengths.as_deref(), Some([3].as_slice()));
}

#[test]
fn decodes_interleave_string_outputs() {
    let string_lengths = [1, 1, 2, 2];
    let outputs = decode_interleave_string_node(
        StreamInput {
            bytes: b"aXbbYZ",
            element_width: 1,
            string_lengths: Some(&string_lengths),
        },
        &2u32.to_le_bytes(),
        Limits::default(),
    )
    .unwrap();

    assert_eq!(outputs.len(), 2);
    assert_eq!(outputs[0].bytes, b"abb");
    assert_eq!(
        outputs[0].string_lengths.as_deref(),
        Some([1, 2].as_slice())
    );
    assert_eq!(outputs[1].bytes, b"XYZ");
    assert_eq!(
        outputs[1].string_lengths.as_deref(),
        Some([1, 2].as_slice())
    );
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
    let row_pattern = [4u16, 0, 4, 1, 4, 2, 4, 3];
    let indices = le_u16_stream(&[&[5; 7], &row_pattern, &row_pattern, &[4]]);
    let delimiter_lengths = [1; 9];
    let header_lengths = [1; 7];

    let output = dispatch_strings_to_serial(
        &[
            index_input(&indices),
            string_input(b"aaBB", &[2, 2]),
            string_input(b"xYZ", &[1, 2]),
            string_input(b"12q", &[2, 1]),
            string_input(b"kLMN", &[1, 3]),
            string_input(b"\n,,;\n,,;\n", &delimiter_lengths),
            string_input(b"ABCDEFG", &header_lengths),
        ],
        6,
    );

    assert_eq!(output, b"preABCDEFG\naa,x,12;k\nBB,YZ,q;LMN\n");
}

#[test]
fn decodes_dispatch_string_csv_wide_header_pattern_to_serial_output() {
    let row_pattern = [6u16, 0, 6, 1, 6, 2, 6, 3, 6, 4, 6, 5];
    let indices = le_u16_stream(&[&[7; 11], &row_pattern, &row_pattern, &[6]]);
    let field_lengths = [[1, 2], [2, 1], [1, 1], [3, 1], [1, 2], [2, 3]];
    let delimiter_lengths = [1; 13];
    let header_lengths = [1; 11];

    let output = dispatch_strings_to_serial(
        &[
            index_input(&indices),
            string_input(b"aAA", &field_lengths[0]),
            string_input(b"bbB", &field_lengths[1]),
            string_input(b"cd", &field_lengths[2]),
            string_input(b"eeeF", &field_lengths[3]),
            string_input(b"gHH", &field_lengths[4]),
            string_input(b"ijKLM", &field_lengths[5]),
            string_input(b"\n,,,,,\n,,,,,\n", &delimiter_lengths),
            string_input(b"A,B,C,D,E,F", &header_lengths),
        ],
        8,
    );

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

    let mut index_values = vec![header_source; header_fields];
    for source in 0..DATA_SOURCES {
        index_values.extend([delimiter_source, source]);
    }
    index_values.push(delimiter_source);
    let indices = le_u16_stream(&[&index_values]);

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

    let mut inputs = vec![index_input(&indices)];
    for (bytes, lengths) in field_bytes.iter().zip(&field_lengths) {
        inputs.push(string_input(bytes, lengths));
    }
    inputs.push(string_input(&delimiter_bytes, &delimiter_lengths));
    inputs.push(string_input(&header_bytes, &header_lengths));

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

    let output = dispatch_strings_to_serial(&inputs, u32::from(DATA_SOURCES) + 2);

    assert_eq!(output, expected);
}

/// Concatenates `u16` values from all parts as little-endian bytes.
fn le_u16_stream(parts: &[&[u16]]) -> Vec<u8> {
    parts
        .iter()
        .flat_map(|part| part.iter())
        .flat_map(|value| value.to_le_bytes())
        .collect()
}

/// Builds a dispatch index input with `u16` elements.
fn index_input(bytes: &[u8]) -> StreamInput<'_> {
    StreamInput {
        bytes,
        element_width: 2,
        string_lengths: None,
    }
}

/// Builds a string input with one-byte elements.
fn string_input<'a>(bytes: &'a [u8], string_lengths: &'a [u32]) -> StreamInput<'a> {
    StreamInput {
        bytes,
        element_width: 1,
        string_lengths: Some(string_lengths),
    }
}

/// Runs the v21 dispatch string node into a serial output that starts with
/// `pre` and returns that output.
fn dispatch_strings_to_serial(inputs: &[StreamInput<'_>], variable_inputs: u32) -> Vec<u8> {
    let mut output = b"pre".to_vec();
    decode_dispatch_string_node_to_serial_output(
        inputs,
        variable_inputs,
        &[],
        21,
        Limits::default(),
        &mut output,
    )
    .unwrap();
    output
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
fn decodes_prefix_node() {
    let suffix_lengths = [5, 2, 1, 2];
    let match_sizes = [0u32, 3, 2, 3]
        .into_iter()
        .flat_map(u32::to_le_bytes)
        .collect::<Vec<_>>();
    let output = decode_prefix_node(
        &[
            StreamInput {
                bytes: b"applelytly",
                element_width: 1,
                string_lengths: Some(&suffix_lengths),
            },
            StreamInput {
                bytes: &match_sizes,
                element_width: 4,
                string_lengths: None,
            },
        ],
        &[],
        Limits::default(),
    )
    .unwrap();

    assert_eq!(output.element_width, 1);
    assert_eq!(output.bytes, b"appleapplyaptaptly");
    assert_eq!(
        output.string_lengths.as_deref(),
        Some([5, 5, 3, 5].as_slice())
    );
}

#[test]
fn rejects_prefix_match_longer_than_previous_string() {
    let match_sizes = 1u32.to_le_bytes();
    let err = decode_prefix_node(
        &[
            StreamInput {
                bytes: b"a",
                element_width: 1,
                string_lengths: Some(&[1]),
            },
            StreamInput {
                bytes: &match_sizes,
                element_width: 4,
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
fn decodes_v21_prefix_graph_to_serial() {
    let field_sizes = [5, 2, 1, 2];
    let match_sizes = [0u32, 3, 2, 3]
        .into_iter()
        .flat_map(u32::to_le_bytes)
        .collect::<Vec<_>>();
    let expected = b"appleapplyaptaptly";
    let input = standard_graph_serial_frame_with_distances(
        21,
        expected.len(),
        &[
            StandardGraphNode {
                transform_id: standard::SEPARATE_STRING_COMPONENTS_ID,
                variable_inputs: 0,
                outputs: 1,
                header: &[],
            },
            StandardGraphNode {
                transform_id: standard::CONVERT_NUM_TO_SERIAL_LE_ID,
                variable_inputs: 0,
                outputs: 1,
                header: &[2],
            },
            StandardGraphNode {
                transform_id: standard::PREFIX_ID,
                variable_inputs: 0,
                outputs: 1,
                header: &[],
            },
            StandardGraphNode {
                transform_id: standard::CONVERT_STRING_TO_SERIAL_ID,
                variable_inputs: 0,
                outputs: 1,
                header: &[],
            },
        ],
        &[&match_sizes, b"applelytly", &field_sizes],
        &[2, 0, 0, 0],
    );
    let plan = parse_frame_plan(&input, Limits::default()).unwrap();
    let mut output = Vec::new();

    let written = decode_plan(&input, &plan, &mut output, Limits::default()).unwrap();

    assert_eq!(written, expected.len());
    assert_eq!(output, expected);
}

#[test]
fn decodes_v21_string_components_to_serial_graph() {
    let field_sizes = [1u16.to_le_bytes(), 3u16.to_le_bytes()].concat();
    let input = standard_graph_serial_frame(
        21,
        4,
        &[
            StandardGraphNode {
                transform_id: standard::SEPARATE_STRING_COMPONENTS_ID,
                variable_inputs: 0,
                outputs: 1,
                header: &[],
            },
            StandardGraphNode {
                transform_id: standard::CONVERT_STRING_TO_SERIAL_ID,
                variable_inputs: 0,
                outputs: 1,
                header: &[],
            },
        ],
        &[b"abcd", &field_sizes],
    );
    let plan = parse_frame_plan(&input, Limits::default()).unwrap();
    let mut output = Vec::new();

    let written = decode_plan(&input, &plan, &mut output, Limits::default()).unwrap();

    assert_eq!(written, 4);
    assert_eq!(output, b"abcd");
}

#[test]
fn decodes_v21_concat_string_graph_to_serial() {
    let sizes = [2u32.to_le_bytes(), 1u32.to_le_bytes()].concat();
    let field_sizes = [1, 2, 3];
    let input = standard_graph_serial_frame_with_distances(
        21,
        3,
        &[
            StandardGraphNode {
                transform_id: standard::SEPARATE_STRING_COMPONENTS_ID,
                variable_inputs: 0,
                outputs: 1,
                header: &[],
            },
            StandardGraphNode {
                transform_id: standard::CONVERT_NUM_TO_SERIAL_LE_ID,
                variable_inputs: 0,
                outputs: 1,
                header: &[2],
            },
            StandardGraphNode {
                transform_id: standard::CONCAT_STRING_ID,
                variable_inputs: 0,
                outputs: 2,
                header: &[],
            },
            StandardGraphNode {
                transform_id: standard::CONVERT_STRING_TO_SERIAL_ID,
                variable_inputs: 0,
                outputs: 1,
                header: &[],
            },
        ],
        &[&sizes, b"aBBccc", &field_sizes],
        &[1, 1, 0, 1, 1],
    );
    let plan = parse_frame_plan(&input, Limits::default()).unwrap();
    let mut output = Vec::new();

    let written = decode_plan(&input, &plan, &mut output, Limits::default()).unwrap();

    assert_eq!(written, 3);
    assert_eq!(output, b"aBB");
}

#[test]
fn decodes_v21_interleave_string_graph_to_serial() {
    let field_sizes = [1, 1, 2, 2];
    let input = standard_graph_serial_frame_with_distances(
        21,
        3,
        &[
            StandardGraphNode {
                transform_id: standard::SEPARATE_STRING_COMPONENTS_ID,
                variable_inputs: 0,
                outputs: 1,
                header: &[],
            },
            StandardGraphNode {
                transform_id: standard::INTERLEAVE_STRING_ID,
                variable_inputs: 0,
                outputs: 2,
                header: &2u32.to_le_bytes(),
            },
            StandardGraphNode {
                transform_id: standard::CONVERT_STRING_TO_SERIAL_ID,
                variable_inputs: 0,
                outputs: 1,
                header: &[],
            },
        ],
        &[b"aXbbYZ", &field_sizes],
        &[0, 0, 1, 1],
    );
    let plan = parse_frame_plan(&input, Limits::default()).unwrap();
    let mut output = Vec::new();

    let written = decode_plan(&input, &plan, &mut output, Limits::default()).unwrap();

    assert_eq!(written, 3);
    assert_eq!(output, b"abb");
}

#[test]
fn decodes_v21_parse_int_graph() {
    let input_values = [0i64, -12, 345];
    let numeric_bytes = input_values
        .into_iter()
        .flat_map(i64::to_le_bytes)
        .collect::<Vec<_>>();
    let input = standard_graph_serial_frame(
        21,
        7,
        &[
            StandardGraphNode {
                transform_id: standard::CONVERT_NUM_TO_SERIAL_LE_ID,
                variable_inputs: 0,
                outputs: 1,
                header: &[3],
            },
            StandardGraphNode {
                transform_id: standard::PARSE_INT_ID,
                variable_inputs: 0,
                outputs: 1,
                header: &[],
            },
        ],
        &[&numeric_bytes],
    );
    let plan = parse_frame_plan(&input, Limits::default()).unwrap();
    let mut output = Vec::new();

    let written = decode_plan(&input, &plan, &mut output, Limits::default()).unwrap();

    assert_eq!(written, 7);
    assert_eq!(output, b"0-12345");
}

#[test]
fn decodes_tokenize_string_node() {
    let alphabet_lengths = [1, 2, 0];
    let output = decode_tokenize_string_node(
        &[
            StreamInput {
                bytes: b"aBB",
                element_width: 1,
                string_lengths: Some(&alphabet_lengths),
            },
            StreamInput {
                bytes: &[1, 0, 1, 2],
                element_width: 1,
                string_lengths: None,
            },
        ],
        &[],
        Limits::default(),
    )
    .unwrap();

    assert_eq!(output.element_width, 1);
    assert_eq!(output.bytes, b"BBaBB");
    assert_eq!(
        output.string_lengths.as_deref(),
        Some([2, 1, 2, 0].as_slice())
    );
}

#[test]
fn decodes_v21_tokenize_string_graph() {
    let alphabet_lengths = [1, 2, 0];
    let input = standard_graph_serial_frame_with_distances(
        21,
        5,
        &[
            StandardGraphNode {
                transform_id: standard::SEPARATE_STRING_COMPONENTS_ID,
                variable_inputs: 0,
                outputs: 1,
                header: &[],
            },
            StandardGraphNode {
                transform_id: standard::TOKENIZE_STRING_ID,
                variable_inputs: 0,
                outputs: 1,
                header: &[],
            },
            StandardGraphNode {
                transform_id: standard::CONVERT_STRING_TO_SERIAL_ID,
                variable_inputs: 0,
                outputs: 1,
                header: &[],
            },
        ],
        &[&[1, 0, 1, 2], b"aBB", &alphabet_lengths],
        &[1, 0, 0],
    );
    let plan = parse_frame_plan(&input, Limits::default()).unwrap();
    let mut output = Vec::new();

    let written = decode_plan(&input, &plan, &mut output, Limits::default()).unwrap();

    assert_eq!(written, 5);
    assert_eq!(output, b"BBaBB");
}
