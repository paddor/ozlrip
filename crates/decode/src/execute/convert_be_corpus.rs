use super::{
    StreamInput, decode_plan, decode_serial_to_num_be_chunk, decode_struct_to_num_be_chunk,
};
use crate::parse::parse_frame_plan;
use alloc::vec::Vec;
use ozlrip_core::{ErrorKind, Limits};

fn stream<'a>(bytes: &'a [u8], element_width: usize) -> StreamInput<'a> {
    StreamInput {
        bytes,
        element_width,
        string_lengths: None,
    }
}

fn magic(version: u32) -> [u8; 4] {
    (0xd7b1_a5c0u32 + version).to_le_bytes()
}

fn push_var_u64(out: &mut Vec<u8>, mut value: u64) {
    while value >= 0x80 {
        out.push(u8::try_from(value & 0x7f).unwrap() | 0x80);
        value >>= 7;
    }
    out.push(u8::try_from(value).unwrap());
}

fn standard_transform_serial_frame(
    transform_id: u8,
    stored: &[u8],
    decoded_len: usize,
    transform_header: &[u8],
) -> Vec<u8> {
    let mut input = Vec::new();
    input.extend_from_slice(&magic(21));
    input.push(0);
    input.push(1);
    push_var_u64(&mut input, u64::try_from(decoded_len + 1).unwrap());
    input.push(2);
    input.push(1);
    input.push(0);
    input.push(transform_id);
    if transform_header.is_empty() {
        input.push(0);
    } else {
        input.push(1);
        push_var_u64(
            &mut input,
            u64::try_from(transform_header.len() - 1).unwrap(),
        );
    }
    input.push(0);
    input.push(0);
    input.push(0);
    push_var_u64(&mut input, u64::try_from(stored.len()).unwrap());
    input.extend_from_slice(transform_header);
    input.extend_from_slice(stored);
    input.push(0);
    input
}

#[test]
fn convert_struct_to_num_be_swaps_wide_elements() {
    let input = [0x12, 0x34, 0xab, 0xcd, 0x01, 0x02, 0x03, 0x04];
    let output = decode_struct_to_num_be_chunk(stream(&input, 2), &[], Limits::default()).unwrap();

    assert_eq!(output.element_width, 2);
    assert_eq!(
        output.bytes,
        [0x34, 0x12, 0xcd, 0xab, 0x02, 0x01, 0x04, 0x03]
    );
}

#[test]
fn convert_struct_to_num_be_accepts_u64_elements() {
    let input = [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef];
    let output = decode_struct_to_num_be_chunk(stream(&input, 8), &[], Limits::default()).unwrap();

    assert_eq!(output.element_width, 8);
    assert_eq!(
        output.bytes,
        [0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 0x01]
    );
}

#[test]
fn convert_serial_to_num_be_uses_header_width() {
    let input = [0x00, 0x00, 0x00, 0x2a, 0x12, 0x34, 0x56, 0x78];
    let output = decode_serial_to_num_be_chunk(stream(&input, 1), &[2], Limits::default()).unwrap();

    assert_eq!(output.element_width, 4);
    assert_eq!(
        output.bytes,
        [0x2a, 0x00, 0x00, 0x00, 0x78, 0x56, 0x34, 0x12]
    );
}

#[test]
fn convert_serial_to_num_be_decodes_v21_frame() {
    let input = standard_transform_serial_frame(14, &[0x12, 0x34, 0x56, 0x78], 4, &[2]);
    let plan = parse_frame_plan(&input, Limits::default()).unwrap();
    let mut output = Vec::new();

    let written = decode_plan(&input, &plan, &mut output, Limits::default()).unwrap();

    assert_eq!(written, 4);
    assert_eq!(output, [0x78, 0x56, 0x34, 0x12]);
}

#[test]
fn convert_serial_to_num_be_rejects_bad_header() {
    let err =
        decode_serial_to_num_be_chunk(stream(&[1, 2], 1), &[], Limits::default()).unwrap_err();

    assert_eq!(err.kind(), ErrorKind::Malformed);
}

#[test]
fn convert_serial_to_num_be_rejects_partial_element() {
    let err =
        decode_serial_to_num_be_chunk(stream(&[1, 2, 3], 1), &[1], Limits::default()).unwrap_err();

    assert_eq!(err.kind(), ErrorKind::Malformed);
}

#[test]
fn convert_struct_to_num_be_rejects_unsupported_width() {
    let err =
        decode_struct_to_num_be_chunk(stream(&[1, 2, 3], 3), &[], Limits::default()).unwrap_err();

    assert_eq!(err.kind(), ErrorKind::InvalidType);
}

#[test]
fn convert_struct_to_num_be_obeys_output_limits() {
    let err = decode_struct_to_num_be_chunk(
        stream(&[1, 2, 3, 4], 2),
        &[],
        Limits {
            max_decoded_bytes: 3,
            ..Limits::default()
        },
    )
    .unwrap_err();

    assert_eq!(err.kind(), ErrorKind::LimitExceeded);
}
