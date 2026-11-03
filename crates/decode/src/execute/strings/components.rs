//! The `separate_string_components` node and its field-size lengths.

use alloc::vec::Vec;

use ozlrip_core::{Error, ErrorKind, Limits, Result};

use super::fast_lengths;
use crate::execute::elements::{
    numeric_element_count, read_usize_numeric_element, validate_numeric_stream_width,
};
use crate::execute::header::require_empty_header;
use crate::execute::streams::{OwnedStream, StreamInput};

pub(in crate::execute) fn decode_separate_string_components_node(
    inputs: &[StreamInput<'_>],
    header: &[u8],
    limits: Limits,
) -> Result<OwnedStream> {
    require_empty_header(header, "separate_string_components headers are unsupported")?;
    let [content, field_sizes] = inputs else {
        return Err(Error::new(ErrorKind::InvalidGraph)
            .with_detail("separate_string_components input count does not match node shape"));
    };
    if content.element_width != 1 {
        return Err(Error::new(ErrorKind::InvalidType)
            .with_detail("separate_string_components content must be serial bytes"));
    }
    validate_numeric_stream_width(field_sizes.element_width, "string field sizes")?;
    let field_count = numeric_element_count(field_sizes.bytes, field_sizes.element_width)?;
    let (string_lengths, total) = decode_string_component_lengths(field_sizes, field_count)?;
    if total != content.bytes.len() {
        return Err(Error::new(ErrorKind::Malformed)
            .with_detail("string field sizes do not sum to content size"));
    }
    if content.bytes.len() > limits.max_decoded_bytes
        || content.bytes.len() > limits.max_buffer_bytes
    {
        return Err(
            Error::new(ErrorKind::LimitExceeded).with_detail("decoded output limit exceeded")
        );
    }
    let mut output = Vec::new();
    output.try_reserve_exact(content.bytes.len()).map_err(|_| {
        Error::new(ErrorKind::AllocationFailed).with_detail("string component allocation failed")
    })?;
    output.extend_from_slice(content.bytes);
    Ok(OwnedStream::strings(output, string_lengths))
}

fn decode_string_component_lengths(
    field_sizes: &StreamInput<'_>,
    field_count: usize,
) -> Result<(Vec<u32>, usize)> {
    let mut string_lengths = Vec::new();
    string_lengths.try_reserve_exact(field_count).map_err(|_| {
        Error::new(ErrorKind::AllocationFailed).with_detail("string length allocation failed")
    })?;
    let mut total = 0usize;
    match field_sizes.element_width {
        1 => {
            fast_lengths::decode_u8_lengths(field_sizes.bytes, &mut string_lengths, &mut total)?;
        }
        2 => {
            for size in field_sizes.bytes.as_chunks::<2>().0 {
                let size = u16::from_le_bytes(*size);
                total = total
                    .checked_add(usize::from(size))
                    .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
                string_lengths.push(u32::from(size));
            }
        }
        4 => {
            for size in field_sizes.bytes.as_chunks::<4>().0 {
                let size = u32::from_le_bytes(*size);
                let size_usize = usize::try_from(size).map_err(|_| {
                    Error::new(ErrorKind::LimitExceeded)
                        .with_detail("string field size is too large")
                })?;
                total = total
                    .checked_add(size_usize)
                    .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
                string_lengths.push(size);
            }
        }
        8 => {
            for index in 0..field_count {
                let size = read_usize_numeric_element(
                    field_sizes.bytes,
                    field_sizes.element_width,
                    index,
                )?;
                total = total
                    .checked_add(size)
                    .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
                string_lengths.push(u32::try_from(size).map_err(|_| {
                    Error::new(ErrorKind::LimitExceeded)
                        .with_detail("string field size is too large")
                })?);
            }
        }
        _ => unreachable!("validate_numeric_stream_width accepted only supported widths"),
    }
    Ok((string_lengths, total))
}
