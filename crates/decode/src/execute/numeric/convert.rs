//! Conversion nodes: the ones that relabel their input without changing
//! its bytes, the big-endian numeric conversions, and the header checks
//! the numeric conversions share.

use alloc::format;
use alloc::vec::Vec;

use crate::standard;
use ozlrip_core::{Error, ErrorKind, Limits, Result};

use crate::execute::elements::{checked_sum_u32, read_var_u64};
use crate::execute::header::require_empty_header;
use crate::execute::output::check_output_len;
use crate::execute::streams::{OwnedStream, StreamInput};

pub(in crate::execute) fn is_byte_preserving_conversion(standard_id: u32) -> bool {
    matches!(
        standard_id,
        standard::CONVERT_SERIAL_TO_STRUCT_ID
            | standard::CONVERT_STRUCT_TO_SERIAL_ID
            | standard::CONVERT_STRING_TO_SERIAL_ID
            | standard::CONVERT_STRUCT_TO_NUM_LE_ID
            | standard::CONVERT_NUM_TO_STRUCT_LE_ID
            | standard::CONVERT_SERIAL_TO_NUM_LE_ID
            | standard::CONVERT_NUM_TO_SERIAL_LE_ID
    )
}

pub(in crate::execute) fn byte_preserving_conversion_output_width(
    standard_id: u32,
    input_count: usize,
    input: StreamInput<'_>,
    header: &[u8],
    limits: Limits,
) -> Result<Option<usize>> {
    let output_width = match standard_id {
        standard::CONVERT_SERIAL_TO_STRUCT_ID => {
            require_empty_header(header, "conversion headers are unsupported")?;
            input.element_width
        }
        standard::CONVERT_STRUCT_TO_SERIAL_ID => {
            let element_width = read_single_conversion_width(header)?;
            if !input.bytes.len().is_multiple_of(element_width) {
                return Err(Error::new(ErrorKind::Malformed)
                    .with_detail("serial stream size is not a multiple of struct width"));
            }
            element_width
        }
        standard::CONVERT_STRUCT_TO_NUM_LE_ID => {
            require_empty_header(header, "convert_struct_to_num_le headers are unsupported")?;
            input.element_width
        }
        standard::CONVERT_NUM_TO_STRUCT_LE_ID => {
            require_empty_header(header, "convert_num_to_struct_le headers are unsupported")?;
            input.element_width
        }
        standard::CONVERT_STRING_TO_SERIAL_ID => {
            require_empty_header(header, "convert_string_to_serial headers are unsupported")?;
            if input.element_width != 1 {
                return Err(Error::new(ErrorKind::InvalidType)
                    .with_detail("convert_string_to_serial input must be byte strings"));
            }
            let lengths = input.string_lengths.ok_or_else(|| {
                Error::new(ErrorKind::InvalidType)
                    .with_detail("convert_string_to_serial input is missing string lengths")
            })?;
            if checked_sum_u32(lengths)? != input.bytes.len() {
                return Err(Error::new(ErrorKind::Malformed)
                    .with_detail("convert_string_to_serial lengths do not sum to content size"));
            }
            1
        }
        standard::CONVERT_SERIAL_TO_NUM_LE_ID => {
            require_empty_header(header, "convert_serial_to_num_le headers are unsupported")?;
            1
        }
        standard::CONVERT_NUM_TO_SERIAL_LE_ID => {
            let int_size = read_conversion_int_size(header, "convert_num_to_serial_le")?;
            if !input.bytes.len().is_multiple_of(int_size) {
                return Err(Error::new(ErrorKind::Malformed)
                    .with_detail("serial stream size is not a multiple of integer width"));
            }
            int_size
        }
        _ => return Ok(None),
    };
    if input_count != 1 {
        return Err(Error::new(ErrorKind::InvalidGraph)
            .with_detail("single-input transform received the wrong input count"));
    }
    check_output_len(input.bytes.len(), limits)?;
    Ok(Some(output_width))
}

fn read_single_conversion_width(header: &[u8]) -> Result<usize> {
    let mut offset = 0usize;
    let element_width = read_var_u64(header, &mut offset)?;
    if offset != header.len() {
        return Err(Error::new(ErrorKind::Malformed)
            .with_detail("convert_struct_to_serial header has trailing bytes"));
    }
    let element_width = usize::try_from(element_width).map_err(|_| {
        Error::new(ErrorKind::LimitExceeded).with_detail("conversion element width is too large")
    })?;
    if element_width == 0 {
        return Err(Error::new(ErrorKind::Malformed)
            .with_detail("conversion element width must be nonzero"));
    }
    Ok(element_width)
}

fn read_conversion_int_size(header: &[u8], transform: &'static str) -> Result<usize> {
    let [int_log] = header else {
        return Err(Error::new(ErrorKind::Malformed)
            .with_detail(format!("{transform} header is malformed")));
    };
    if *int_log > 3 {
        return Err(Error::new(ErrorKind::Malformed)
            .with_detail(format!("{transform} integer width is invalid")));
    }
    1usize
        .checked_shl(u32::from(*int_log))
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))
}

fn validate_conversion_numeric_width(element_width: usize) -> Result<()> {
    match element_width {
        1 | 2 | 4 | 8 => Ok(()),
        _ => Err(Error::new(ErrorKind::InvalidType)
            .with_detail("conversion numeric width is unsupported")),
    }
}

pub(in crate::execute) fn decode_struct_to_num_be_chunk(
    stored: StreamInput<'_>,
    header: &[u8],
    limits: Limits,
) -> Result<OwnedStream> {
    require_empty_header(header, "convert_struct_to_num_be headers are unsupported")?;
    decode_big_endian_numeric_conversion(stored, stored.element_width, limits)
}

pub(in crate::execute) fn decode_serial_to_num_be_chunk(
    stored: StreamInput<'_>,
    header: &[u8],
    limits: Limits,
) -> Result<OwnedStream> {
    let int_size = read_conversion_int_size(header, "convert_serial_to_num_be")?;
    if !stored.bytes.len().is_multiple_of(int_size) {
        return Err(Error::new(ErrorKind::Malformed)
            .with_detail("serial stream size is not a multiple of integer width"));
    }
    decode_big_endian_numeric_conversion(stored, int_size, limits)
}

fn decode_big_endian_numeric_conversion(
    stored: StreamInput<'_>,
    element_width: usize,
    limits: Limits,
) -> Result<OwnedStream> {
    validate_conversion_numeric_width(element_width)?;
    check_output_len(stored.bytes.len(), limits)?;
    if !stored.bytes.len().is_multiple_of(element_width) {
        return Err(
            Error::new(ErrorKind::Malformed).with_detail("numeric stream has partial element")
        );
    }
    let mut output = Vec::new();
    output.try_reserve_exact(stored.bytes.len()).map_err(|_| {
        Error::new(ErrorKind::AllocationFailed).with_detail("conversion allocation failed")
    })?;
    for element in stored.bytes.chunks_exact(element_width) {
        output.extend(element.iter().rev().copied());
    }
    Ok(OwnedStream {
        bytes: output,
        element_width,
        string_lengths: None,
        recyclable: false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn le_struct_conversion_header_errors_name_their_transform() {
        let input = StreamInput {
            bytes: &[0; 4],
            element_width: 4,
            string_lengths: None,
        };
        for (id, name) in [
            (
                standard::CONVERT_STRUCT_TO_NUM_LE_ID,
                "convert_struct_to_num_le",
            ),
            (
                standard::CONVERT_NUM_TO_STRUCT_LE_ID,
                "convert_num_to_struct_le",
            ),
        ] {
            let err =
                byte_preserving_conversion_output_width(id, 1, input, &[0], Limits::default())
                    .unwrap_err();
            assert_eq!(err.kind(), ErrorKind::Unsupported);
            assert_eq!(
                err.detail(),
                Some(format!("{name} headers are unsupported").as_str())
            );
        }
    }
}
