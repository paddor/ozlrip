use ozlrip::{ErrorKind, Limits, Options};

const MANIFEST: &str = include_str!("fixtures/error-taxonomy.tsv");
const MAGIC_BASE: u32 = 0xd7b1_a5c0;

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

#[test]
fn public_error_taxonomy_matches_manifest() {
    for row in taxonomy_rows() {
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
        };

        assert_eq!(err.kind(), row.expected, "{}", row.case);
    }
}

fn taxonomy_rows() -> Vec<TaxonomyRow<'static>> {
    let mut lines = MANIFEST.lines();
    assert_eq!(
        lines.next(),
        Some("case\tcategory\toperation\texpected_kind")
    );
    lines
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            let fields = line.split('\t').collect::<Vec<_>>();
            assert_eq!(fields.len(), 4, "bad error-taxonomy row: {line}");
            let category = fields[1];
            assert!(
                matches!(
                    category,
                    "unsupported" | "malformed" | "truncated" | "limit"
                ),
                "bad error taxonomy category: {category}"
            );
            TaxonomyRow {
                case: fields[0],
                operation: parse_operation(fields[2]),
                expected: parse_error_kind(fields[3]),
            }
        })
        .collect()
}

struct TaxonomyRow<'a> {
    case: &'a str,
    operation: Operation,
    expected: ErrorKind,
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
}

fn parse_operation(value: &str) -> Operation {
    match value {
        "inspect" => Operation::Inspect,
        "decode" => Operation::Decode,
        _ => panic!("bad error taxonomy operation: {value}"),
    }
}

fn parse_error_kind(value: &str) -> ErrorKind {
    match value {
        "Unsupported" => ErrorKind::Unsupported,
        "Malformed" => ErrorKind::Malformed,
        "Truncated" => ErrorKind::Truncated,
        "LimitExceeded" => ErrorKind::LimitExceeded,
        _ => panic!("bad error taxonomy kind: {value}"),
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
        "truncated-magic" => inspect_case(vec![0xd7, 0xb1], Options::default()),
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
        _ => panic!("unknown error taxonomy case: {name}"),
    }
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
