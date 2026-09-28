//! Numeric nodes that undo an arithmetic transform: `delta`, `zigzag`,
//! `divide_by` and `range_pack`.

use ozlrip_core::{Error, ErrorKind, Limits, Result};

use super::{fast_delta, fast_zigzag};
use crate::execute::elements::{
    max_numeric_value, numeric_element_count, push_numeric_element, read_element, read_var_u64,
    validate_numeric_stream_width,
};
use crate::execute::header::require_empty_header;
use crate::execute::output::{alloc_output, check_output_len};
use crate::execute::runtime::DecodeScratch;
use crate::execute::streams::{OwnedStream, StreamInput};

pub(in crate::execute) fn decode_zigzag_numeric_chunk(
    stored: StreamInput<'_>,
    header: &[u8],
    limits: Limits,
) -> Result<OwnedStream> {
    require_empty_header(header, "zigzag transform headers are unsupported")?;
    validate_numeric_stream_width(stored.element_width, "zigzag")?;
    if !stored.bytes.len().is_multiple_of(stored.element_width) {
        return Err(
            Error::new(ErrorKind::Malformed).with_detail("zigzag input has partial element")
        );
    }
    let mut output = alloc_output(stored.bytes.len(), limits, "zigzag allocation failed")?;
    fast_zigzag::decode_numeric(stored.bytes, stored.element_width, &mut output);
    Ok(OwnedStream {
        bytes: output,
        element_width: stored.element_width,
        string_lengths: None,
        recyclable: false,
    })
}

/// First format version that keeps the first value of a delta stream in the
/// transform header. Older versions keep it first in the stream.
const DELTA_HEADER_VERSION_MIN: u32 = 13;

pub(in crate::execute) fn decode_delta_node(
    stored: StreamInput<'_>,
    header: &[u8],
    format_version: u32,
    limits: Limits,
    scratch: &mut DecodeScratch,
) -> Result<OwnedStream> {
    validate_numeric_stream_width(stored.element_width, "delta input")?;
    numeric_element_count(stored.bytes, stored.element_width)?;
    let (first, deltas) = if format_version < DELTA_HEADER_VERSION_MIN {
        require_empty_header(header, "delta headers before format v13 are unsupported")?;
        stored
            .bytes
            .split_at_checked(stored.element_width)
            .unwrap_or_default()
    } else {
        match header.len() {
            0 if stored.bytes.is_empty() => (header, stored.bytes),
            0 => {
                return Err(
                    Error::new(ErrorKind::Malformed).with_detail("delta stream has no first value")
                );
            }
            len if len == stored.element_width => (header, stored.bytes),
            _ => {
                return Err(Error::new(ErrorKind::Malformed)
                    .with_detail("delta header must contain one element"));
            }
        }
    };
    let output_len = first.len().checked_add(deltas.len()).ok_or_else(|| {
        Error::new(ErrorKind::IntegerOverflow).with_detail("delta size overflowed")
    })?;
    check_output_len(output_len, limits)?;
    let mut output = scratch.take_byte_buffer(output_len, "delta allocation failed")?;
    if first.is_empty() {
        return Ok(OwnedStream {
            bytes: output,
            element_width: stored.element_width,
            string_lengths: None,
            recyclable: true,
        });
    }
    fast_delta::decode_delta_elements(deltas, first, stored.element_width, output_len, &mut output);
    Ok(OwnedStream::pooled(output, stored.element_width))
}

pub(in crate::execute) fn decode_divide_by_node(
    stored: StreamInput<'_>,
    header: &[u8],
    limits: Limits,
) -> Result<OwnedStream> {
    validate_numeric_stream_width(stored.element_width, "divide_by input")?;
    numeric_element_count(stored.bytes, stored.element_width)?;
    let divisor = parse_divide_by_divisor(header, stored.element_width)?;
    let mut output = alloc_output(stored.bytes.len(), limits, "divide_by allocation failed")?;
    let max_value = max_numeric_value(stored.element_width)?;
    for element in stored.bytes.chunks_exact(stored.element_width) {
        let quotient = read_element(element);
        let decoded = quotient.checked_mul(divisor).ok_or_else(|| {
            Error::new(ErrorKind::Malformed).with_detail("divide_by value overflowed")
        })?;
        if decoded > max_value {
            return Err(Error::new(ErrorKind::Malformed).with_detail("divide_by value overflowed"));
        }
        push_numeric_element(&mut output, stored.element_width, decoded);
    }
    Ok(OwnedStream::typed(output, stored.element_width))
}

fn parse_divide_by_divisor(header: &[u8], element_width: usize) -> Result<u64> {
    if header.is_empty() {
        return Err(Error::new(ErrorKind::Malformed).with_detail("divide_by header is malformed"));
    }
    let mut offset = 0usize;
    let divisor = read_var_u64(header, &mut offset)?;
    if offset != header.len() {
        return Err(
            Error::new(ErrorKind::Malformed).with_detail("divide_by header has trailing bytes")
        );
    }
    if divisor == 0 || divisor > max_numeric_value(element_width)? {
        return Err(Error::new(ErrorKind::Malformed).with_detail("divide_by divisor is invalid"));
    }
    Ok(divisor)
}

pub(in crate::execute) fn decode_range_pack_node(
    stored: StreamInput<'_>,
    header: &[u8],
    limits: Limits,
) -> Result<OwnedStream> {
    validate_numeric_stream_width(stored.element_width, "range_pack input")?;
    let elements = numeric_element_count(stored.bytes, stored.element_width)?;
    let (&output_width, min_bytes) = header.split_first().ok_or_else(|| {
        Error::new(ErrorKind::Malformed).with_detail("range_pack header is malformed")
    })?;
    let output_width = usize::from(output_width);
    if !matches!(output_width, 1 | 2 | 4 | 8) || output_width < stored.element_width {
        return Err(
            Error::new(ErrorKind::Malformed).with_detail("range_pack output width is invalid")
        );
    }
    let min_value = match min_bytes.len() {
        0 => 0,
        len if len == output_width => read_element(min_bytes),
        _ => {
            return Err(
                Error::new(ErrorKind::Malformed).with_detail("range_pack header is malformed")
            );
        }
    };
    let output_len = elements
        .checked_mul(output_width)
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
    let mut output = alloc_output(output_len, limits, "range_pack allocation failed")?;
    let overflowed = || Error::new(ErrorKind::Malformed).with_detail("range_pack value overflowed");
    if output_width == 1 {
        let min_value = min_bytes.first().copied().unwrap_or(0);
        for &value in stored.bytes {
            output.push(value.checked_add(min_value).ok_or_else(overflowed)?);
        }
    } else {
        let max_value = max_numeric_value(output_width)?;
        for element in stored.bytes.chunks_exact(stored.element_width) {
            let value = read_element(element)
                .checked_add(min_value)
                .filter(|&value| value <= max_value)
                .ok_or_else(overflowed)?;
            push_numeric_element(&mut output, output_width, value);
        }
    }
    Ok(OwnedStream::typed(output, output_width))
}
