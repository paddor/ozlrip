use super::{StreamInput, decode_sparse_num_node};
use ozlrip_core::{ErrorKind, Limits};

fn stream<'a>(bytes: &'a [u8], element_width: usize) -> StreamInput<'a> {
    StreamInput {
        bytes,
        element_width,
        string_lengths: None,
    }
}

#[test]
fn sparse_num_accepts_zero_literal() {
    let distances = [3, 1];
    let values = [0];
    let output = decode_sparse_num_node(
        &[stream(&distances, 1), stream(&values, 1)],
        &[],
        Limits::default(),
    )
    .unwrap();

    assert_eq!(output.element_width, 1);
    assert_eq!(output.bytes, [0, 0, 0, 0, 0]);
}

#[test]
fn sparse_num_decodes_explicit_dominant() {
    let distances = [2, 0, 1];
    let values = [1, 2];
    let output = decode_sparse_num_node(
        &[stream(&distances, 1), stream(&values, 1)],
        &[7],
        Limits::default(),
    )
    .unwrap();

    assert_eq!(output.element_width, 1);
    assert_eq!(output.bytes, [7, 7, 1, 2, 7]);
}

#[test]
fn sparse_num_decodes_wide_explicit_dominant() {
    let distances = [1, 2];
    let values = [5u16.to_le_bytes(), 6u16.to_le_bytes()].concat();
    let output = decode_sparse_num_node(
        &[stream(&distances, 1), stream(&values, 2)],
        &1024u16.to_le_bytes(),
        Limits::default(),
    )
    .unwrap();

    assert_eq!(output.element_width, 2);
    assert_eq!(
        output.bytes,
        [
            1024u16.to_le_bytes(),
            5u16.to_le_bytes(),
            1024u16.to_le_bytes(),
            1024u16.to_le_bytes(),
            6u16.to_le_bytes(),
        ]
        .concat()
    );
}

#[test]
fn sparse_num_rejects_invalid_distance_count() {
    let distances = [0, 0, 0];
    let values = [1];
    let err = decode_sparse_num_node(
        &[stream(&distances, 1), stream(&values, 1)],
        &[],
        Limits::default(),
    )
    .unwrap_err();

    assert_eq!(err.kind(), ErrorKind::Malformed);
}

#[test]
fn sparse_num_rejects_header_wider_than_value() {
    let distances = [0];
    let values = [1];
    let err = decode_sparse_num_node(
        &[stream(&distances, 1), stream(&values, 1)],
        &[1, 0],
        Limits::default(),
    )
    .unwrap_err();

    assert_eq!(err.kind(), ErrorKind::Malformed);
}
