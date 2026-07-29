use ozlrip::{ErrorKind, Limits, Options};

const MANIFEST: &str = include_str!("fixtures/error-taxonomy.tsv");
const MAGIC_BASE: u32 = 0xd7b1_a5c0;
const BUNDLE_INFO_MAGIC: u32 = 0x4942_ccda;
const PACKED_DICT_MAGIC: u32 = 0x4944_ccda;
const UNIQUE_ID_BYTES: usize = 32;
const FAT_BUNDLE_FLAG: u8 = 1;
const ZSTD_ID: u32 = 22;
const LZ4_ID: u32 = 62;

fn magic(version: u32) -> [u8; 4] {
    (MAGIC_BASE + version).to_le_bytes()
}

fn stored_serial_frame(bytes: &[u8]) -> Vec<u8> {
    let mut input = Vec::new();
    input.extend_from_slice(&magic(21));
    input.push(0);
    input.push(1);
    input.push(u8::try_from(bytes.len() + 1).unwrap());
    input.push(1);
    input.push(1);
    input.push(u8::try_from(bytes.len()).unwrap());
    input.extend_from_slice(bytes);
    input.push(0);
    input
}

fn unknown_size_frame() -> Vec<u8> {
    let mut input = Vec::new();
    input.extend_from_slice(&magic(21));
    input.push(0);
    input.push(1);
    input.push(0);
    input
}

fn custom_transform_frame() -> Vec<u8> {
    let mut input = Vec::new();
    input.extend_from_slice(&magic(21));
    input.push(0);
    input.push(1);
    input.push(1);
    input.push(2);
    input.push(0);
    input.push(1);
    input.push(1);
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

fn push_var_u64(out: &mut Vec<u8>, mut value: u64) {
    while value >= 0x80 {
        out.push(u8::try_from(value & 0x7f).unwrap() | 0x80);
        value >>= 7;
    }
    out.push(u8::try_from(value).unwrap());
}

fn dictionary_bundle(codec_id: u32, custom: bool) -> Vec<u8> {
    let bundle_id = [7; UNIQUE_ID_BYTES];
    let dict_id = [9; UNIQUE_ID_BYTES];
    let content = [1u32.to_le_bytes(), 1i32.to_le_bytes()].concat();

    let mut bundle = Vec::new();
    bundle.extend_from_slice(&BUNDLE_INFO_MAGIC.to_le_bytes());
    bundle.extend_from_slice(&bundle_id);
    bundle.push(FAT_BUNDLE_FLAG);
    bundle.extend_from_slice(&1u32.to_le_bytes());
    bundle.extend_from_slice(&dict_id);
    bundle.extend_from_slice(&PACKED_DICT_MAGIC.to_le_bytes());
    bundle.extend_from_slice(&dict_id);
    bundle.extend_from_slice(&codec_id.to_le_bytes());
    bundle.push(u8::from(custom));
    bundle.extend_from_slice(&u32::try_from(content.len()).unwrap().to_le_bytes());
    bundle.extend_from_slice(&content);
    bundle
}

#[test]
fn public_error_taxonomy_matches_manifest() {
    for row in taxonomy_rows() {
        if !feature_enabled(row.required_feature) {
            continue;
        }
        let case = error_case(row.case);
        assert_eq!(
            case.operation, row.operation,
            "{} operation mismatch",
            row.case
        );

        let err = match row.operation {
            Operation::Inspect => match ozlrip::inspect_with_options(&case.input, case.options) {
                Ok(_) => panic!("{} unexpectedly succeeded", row.case),
                Err(err) => err,
            },
            Operation::Decode => {
                let mut dst = vec![0xaa, 0xbb];
                let Err(err) =
                    ozlrip::decode_into_with_options(&case.input, &mut dst, case.options)
                else {
                    panic!("{} unexpectedly succeeded", row.case);
                };
                assert_eq!(dst, [0xaa, 0xbb], "{} mutated destination", row.case);
                err
            }
            Operation::LoadDictionary => {
                let mut decoder = ozlrip::Decoder::new();
                match decoder.load_dictionary_bundle(&case.input) {
                    Ok(()) => panic!("{} unexpectedly succeeded", row.case),
                    Err(err) => err,
                }
            }
        };

        assert_eq!(err.kind(), row.expected, "{}", row.case);
    }
}

fn taxonomy_rows() -> Vec<TaxonomyRow<'static>> {
    let mut lines = MANIFEST.lines();
    assert_eq!(
        lines.next(),
        Some("case\tcategory\toperation\texpected_kind\trequired_feature")
    );
    lines
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            let fields = line.split('\t').collect::<Vec<_>>();
            assert_eq!(fields.len(), 5, "bad error-taxonomy row: {line}");
            let category = fields[1];
            assert!(
                matches!(
                    category,
                    "unsupported"
                        | "malformed"
                        | "truncated"
                        | "limit"
                        | "invalid_graph"
                        | "invalid_type"
                        | "overflow"
                        | "checksum"
                ),
                "bad error taxonomy category: {category}"
            );
            TaxonomyRow {
                case: fields[0],
                operation: parse_operation(fields[2]),
                expected: parse_error_kind(fields[3]),
                required_feature: fields[4],
            }
        })
        .collect()
}

struct TaxonomyRow<'a> {
    case: &'a str,
    operation: Operation,
    expected: ErrorKind,
    required_feature: &'a str,
}

struct ErrorCase {
    input: Vec<u8>,
    operation: Operation,
    options: Options,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Operation {
    Inspect,
    Decode,
    LoadDictionary,
}

fn parse_operation(value: &str) -> Operation {
    match value {
        "inspect" => Operation::Inspect,
        "decode" => Operation::Decode,
        "load-dictionary" => Operation::LoadDictionary,
        _ => panic!("bad error taxonomy operation: {value}"),
    }
}

fn parse_error_kind(value: &str) -> ErrorKind {
    match value {
        "Unsupported" => ErrorKind::Unsupported,
        "Malformed" => ErrorKind::Malformed,
        "Truncated" => ErrorKind::Truncated,
        "LimitExceeded" => ErrorKind::LimitExceeded,
        "ChecksumMismatch" => ErrorKind::ChecksumMismatch,
        "InvalidGraph" => ErrorKind::InvalidGraph,
        "InvalidType" => ErrorKind::InvalidType,
        "IntegerOverflow" => ErrorKind::IntegerOverflow,
        _ => panic!("bad error taxonomy kind: {value}"),
    }
}

fn feature_enabled(value: &str) -> bool {
    match value {
        "none" => true,
        "checksum" => cfg!(feature = "checksum"),
        _ => panic!("bad error taxonomy feature: {value}"),
    }
}

fn error_case(name: &str) -> ErrorCase {
    match name {
        "unknown-magic" => decode_case(b"not-openzl".to_vec(), Options::default()),
        "unsupported-format-version" => inspect_case(
            {
                let mut input = Vec::new();
                input.extend_from_slice(&magic(255));
                input
            },
            Options::default(),
        ),
        "unknown-output-size" => decode_case(unknown_size_frame(), Options::default()),
        "custom-transform" => decode_case(custom_transform_frame(), Options::default()),
        "zigzag-header" => decode_case(
            standard_transform_serial_frame(21, 3, b"bytes", 5, &[0]),
            Options::default(),
        ),
        "custom-dictionary-materializer" => dictionary_case(dictionary_bundle(ZSTD_ID, true)),
        "external-dictionary-materializer" => dictionary_case(dictionary_bundle(LZ4_ID, false)),
        "truncated-magic" => inspect_case(vec![0xd7, 0xb1], Options::default()),
        "generated-truncated-output-size-varint" => {
            inspect_case(truncated_output_size_varint_frame(), Options::default())
        }
        "generated-truncated-stored-payload" => {
            decode_case(truncated_stored_payload_frame(), Options::default())
        }
        "zero-output-count" => inspect_case(
            {
                let mut input = Vec::new();
                input.extend_from_slice(&magic(21));
                input.push(0);
                input.push(0);
                input
            },
            Options::default(),
        ),
        "truncated-dictionary-bundle" => {
            dictionary_case(BUNDLE_INFO_MAGIC.to_le_bytes()[..2].to_vec())
        }
        "missing-eof-marker" => decode_case(
            {
                let mut input = stored_serial_frame(&[7, 8, 9]);
                input.pop();
                input
            },
            Options::default(),
        ),
        "stored-output-size-mismatch" => decode_case(
            {
                let mut input = stored_serial_frame(&[7, 8, 9]);
                input[6] = 5;
                input
            },
            Options::default(),
        ),
        "generated-trailing-after-eof" => {
            inspect_case(trailing_after_eof_frame(), Options::default())
        }
        "convert-num-to-serial-missing-header" => decode_case(
            standard_transform_serial_frame(21, 10, b"bytes", 5, &[]),
            Options::default(),
        ),
        "bad-dictionary-bundle-magic" => dictionary_case([0xff, 0xff, 0xff, 0xff].to_vec()),
        "frame-byte-limit" => inspect_case(
            stored_serial_frame(&[7, 8, 9]),
            Options {
                limits: Limits {
                    max_frame_bytes: 3,
                    ..Limits::default()
                },
                ..Options::default()
            },
        ),
        "decoded-byte-limit" => decode_case(
            stored_serial_frame(&[7, 8, 9]),
            Options {
                limits: Limits {
                    max_decoded_bytes: 2,
                    ..Limits::default()
                },
                ..Options::default()
            },
        ),
        "stored-stream-byte-limit" => decode_case(
            stored_serial_frame(&[7, 8, 9]),
            Options {
                limits: Limits {
                    max_stored_stream_bytes: 2,
                    ..Limits::default()
                },
                ..Options::default()
            },
        ),
        "output-count-limit" => inspect_case(
            stored_serial_frame(&[]),
            Options {
                limits: Limits {
                    max_streams: 0,
                    ..Limits::default()
                },
                ..Options::default()
            },
        ),
        "transform-header-byte-limit" => inspect_case(
            standard_transform_serial_frame(21, 22, &[1, 2, 3], 3, &[99]),
            Options {
                limits: Limits {
                    max_transform_header_bytes: 0,
                    ..Limits::default()
                },
                ..Options::default()
            },
        ),
        "invalid-graph-node-input" => {
            inspect_case(invalid_graph_node_input_frame(), Options::default())
        }
        "generated-duplicate-regen-distance" => {
            inspect_case(duplicate_regen_distance_frame(), Options::default())
        }
        "invalid-output-type" => inspect_case(
            {
                let mut input = Vec::new();
                input.extend_from_slice(&magic(14));
                input.push(4);
                input
            },
            Options::default(),
        ),
        "stored-stream-size-overflow" => inspect_case(
            stored_stream_size_overflow_frame(),
            Options {
                limits: Limits {
                    max_stored_stream_bytes: usize::MAX,
                    max_buffer_bytes: usize::MAX,
                    max_decoded_bytes: usize::MAX,
                    ..Limits::default()
                },
                ..Options::default()
            },
        ),
        "bad-header-checksum" => inspect_case(bad_header_checksum_frame(), Options::default()),
        "bad-decoded-checksum" => decode_case(bad_decoded_checksum_frame(), Options::default()),
        _ => panic!("unknown error taxonomy case: {name}"),
    }
}

fn truncated_output_size_varint_frame() -> Vec<u8> {
    let mut input = Vec::new();
    input.extend_from_slice(&magic(21));
    input.push(0);
    input.push(1);
    input.push(0x80);
    input
}

fn truncated_stored_payload_frame() -> Vec<u8> {
    let mut input = stored_serial_frame(&[7, 8, 9]);
    input.remove(10);
    input
}

fn trailing_after_eof_frame() -> Vec<u8> {
    let mut input = stored_serial_frame(&[7, 8, 9]);
    input.push(0xff);
    input
}

fn invalid_graph_node_input_frame() -> Vec<u8> {
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
    input
}

fn duplicate_regen_distance_frame() -> Vec<u8> {
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
    input
}

fn push_bitpacked_u32(out: &mut Vec<u8>, values: &[u32], bits: usize) {
    let mut bytes = vec![0u8; values.len().saturating_mul(bits).div_ceil(8)];
    for (index, &value) in values.iter().enumerate() {
        for bit in 0..bits {
            if (value >> bit) & 1 == 0 {
                continue;
            }
            let bit_index = index * bits + bit;
            bytes[bit_index / 8] |= 1 << (bit_index % 8);
        }
    }
    out.extend_from_slice(&bytes);
}

fn stored_stream_size_overflow_frame() -> Vec<u8> {
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
    input
}

fn bad_header_checksum_frame() -> Vec<u8> {
    let mut input = Vec::new();
    input.extend_from_slice(&magic(21));
    input.push(1 << 1);
    input.push(1);
    input.push(4);
    input.push(0);
    input
}

fn bad_decoded_checksum_frame() -> Vec<u8> {
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
    input
}

fn inspect_case(input: Vec<u8>, options: Options) -> ErrorCase {
    ErrorCase {
        input,
        operation: Operation::Inspect,
        options,
    }
}

fn decode_case(input: Vec<u8>, options: Options) -> ErrorCase {
    ErrorCase {
        input,
        operation: Operation::Decode,
        options,
    }
}

fn dictionary_case(input: Vec<u8>) -> ErrorCase {
    ErrorCase {
        input,
        operation: Operation::LoadDictionary,
        options: Options::default(),
    }
}
