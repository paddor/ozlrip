use alloc::vec::Vec;

use super::{StreamInput, parse_int};
use ozlrip_core::{ErrorKind, Limits};

fn stream(bytes: &[u8], element_width: usize) -> StreamInput<'_> {
    StreamInput {
        bytes,
        element_width,
        string_lengths: None,
    }
}

fn numbers(values: &[i64]) -> Vec<u8> {
    values
        .iter()
        .flat_map(|value| value.to_le_bytes())
        .collect()
}

#[test]
fn parse_int_decodes_signed_numbers() {
    let input = numbers(&[0, 1, -1, 100, -200]);
    let output = parse_int::decode_node(stream(&input, 8), &[], Limits::default()).unwrap();

    assert_eq!(output.element_width, 1);
    assert_eq!(output.bytes, b"01-1100-200");
    assert_eq!(
        output.string_lengths.as_deref(),
        Some([1, 1, 2, 3, 4].as_slice())
    );
}

#[test]
fn parse_int_decodes_i64_boundaries() {
    let input = numbers(&[i64::MIN, i64::MAX]);
    let output = parse_int::decode_node(stream(&input, 8), &[], Limits::default()).unwrap();

    assert_eq!(output.bytes, b"-92233720368547758089223372036854775807");
    assert_eq!(output.string_lengths.as_deref(), Some([20, 19].as_slice()));
}

#[test]
fn parse_int_rejects_non_empty_header() {
    let input = numbers(&[1]);
    let err = parse_int::decode_node(stream(&input, 8), &[0], Limits::default()).unwrap_err();

    assert_eq!(err.kind(), ErrorKind::Malformed);
}

#[test]
fn parse_int_rejects_non_i64_width() {
    let err = parse_int::decode_node(stream(&[1, 2, 3, 4], 4), &[], Limits::default()).unwrap_err();

    assert_eq!(err.kind(), ErrorKind::InvalidType);
}

#[test]
fn parse_int_rejects_truncated_i64_stream() {
    let err = parse_int::decode_node(stream(&[1, 2, 3], 8), &[], Limits::default()).unwrap_err();

    assert_eq!(err.kind(), ErrorKind::Malformed);
}

#[test]
fn parse_int_obeys_output_limits() {
    let input = numbers(&[100]);
    let err = parse_int::decode_node(
        stream(&input, 8),
        &[],
        Limits {
            max_decoded_bytes: 2,
            ..Limits::default()
        },
    )
    .unwrap_err();

    assert_eq!(err.kind(), ErrorKind::LimitExceeded);
}
