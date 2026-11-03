use super::*;

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
fn decodes_v24_lz_graph_with_trailing_literals() {
    let input = standard_graph_serial_frame(
        24,
        7,
        &[StandardGraphNode {
            transform_id: standard::LZ_ID,
            variable_inputs: 0,
            outputs: 1,
            header: &[7],
        }],
        &[b"abc!", &[3], &[3], &[3]],
    );
    let plan = parse_frame_plan(&input, Limits::default()).unwrap();
    let mut output = Vec::new();

    let written = decode_plan(&input, &plan, &mut output, Limits::default()).unwrap();

    assert_eq!(written, 7);
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

/// Runs an LZ node with 8-byte offset and length streams through both the
/// owned-output path and the direct-append path.
fn decode_lz_u64(
    literals: &[u8],
    offsets: &[u64],
    literal_lengths: &[u64],
    match_lengths: &[u64],
    output_len: u64,
) -> [Result<Vec<u8>>; 2] {
    let le = |values: &[u64]| {
        values
            .iter()
            .flat_map(|v| v.to_le_bytes())
            .collect::<Vec<_>>()
    };
    let (offsets, literal_lengths, match_lengths) =
        (le(offsets), le(literal_lengths), le(match_lengths));
    let stream = |bytes, element_width| StreamInput {
        bytes,
        element_width,
        string_lengths: None,
    };
    let inputs = [
        stream(literals, 1),
        stream(&offsets, 8),
        stream(&literal_lengths, 8),
        stream(&match_lengths, 8),
    ];
    let mut header = Vec::new();
    push_var_u64(&mut header, output_len);

    let owned = decode_lz_node(&inputs, &header, Limits::default());
    let mut output = Vec::new();
    let appended = decode_lz_node_to_output(&inputs, &header, Limits::default(), &mut output, 0)
        .map(|()| output);
    [owned, appended]
}

/// Ports upstream `eafc5fc` (LZ integer overflows): lengths and offsets with
/// the high bit set, or large enough to wrap a position, are rejected.
#[test]
fn rejects_lz_lengths_and_offsets_that_overflow_positions() {
    const HIGH: u64 = 1 << 63;
    const MAX: u64 = i64::MAX as u64;
    for result in decode_lz_u64(b"ABCD", &[3], &[4], &[2], 6) {
        assert_eq!(result.unwrap(), b"ABCDBC");
    }

    let rejects = |literals: &[u8],
                   offsets: &[u64],
                   literal_lengths: &[u64],
                   match_lengths: &[u64],
                   output_len| {
        for result in decode_lz_u64(
            literals,
            offsets,
            literal_lengths,
            match_lengths,
            output_len,
        ) {
            assert!(
                result.is_err(),
                "{offsets:?} {literal_lengths:?} {match_lengths:?} decoded"
            );
        }
    };
    rejects(b"", &[1], &[HIGH], &[0], 16);
    rejects(&[0; 4], &[HIGH], &[4], &[1], 16);
    rejects(&[0; 4], &[1], &[4], &[HIGH], 16);
    rejects(&[0; 8], &[1, 1], &[4, MAX], &[1, 0], 256);
    rejects(&[0; 4], &[1], &[4], &[MAX], 256);
    rejects(b"", &[1], &[u64::MAX], &[0], 16);
    rejects(&[0; 4], &[u64::MAX], &[4], &[1], 16);
    rejects(&[0; 4], &[1], &[4], &[u64::MAX], 16);
    rejects(&[0; 4], &[1], &[4], &[u64::MAX - 3], u64::MAX);
}

/// Field-LZ extras are 4 bytes, but with 8-byte elements a length or offset
/// near `u32::MAX` overflows `usize` on 32-bit targets.
#[test]
fn rejects_field_lz_extras_that_overflow_with_wide_elements() {
    let token = |offset_code: u16, literal_code: u16, match_code: u16| {
        (offset_code | (literal_code << 2) | (match_code << 6)).to_le_bytes()
    };
    let max = u32::MAX.to_le_bytes();
    let one = 1u32.to_le_bytes();
    let rejects = |tokens: [u8; 2], offsets: &[u8], extra_literals: &[u8], extra_matches: &[u8]| {
        let stream = |bytes, element_width| StreamInput {
            bytes,
            element_width,
            string_lengths: None,
        };
        let result = decode_field_lz_node(
            &[
                stream(&[0; 16], 8),
                stream(&tokens, 2),
                stream(offsets, 4),
                stream(extra_literals, 4),
                stream(extra_matches, 4),
            ],
            &[64],
            Limits::default(),
            &mut DecodeScratch::new(),
        );
        assert!(result.is_err(), "{tokens:?} decoded");
    };
    rejects(token(3, 15, 0), &one, &max, &[]);
    rejects(token(3, 1, 15), &one, &[], &max);
    rejects(token(3, 1, 0), &max, &[], &[]);
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
