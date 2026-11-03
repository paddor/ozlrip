//! Numeric nodes that repeat their input: `constant` and `dedup_num`.

use alloc::format;
use alloc::vec::Vec;

use ozlrip_core::{Error, ErrorKind, Limits, Result};

use crate::execute::elements::{
    numeric_element_count, read_var_u64, validate_numeric_stream_width,
};
use crate::execute::header::require_empty_header;
use crate::execute::output::check_output_len;
use crate::execute::runtime::DecodeScratch;
use crate::execute::streams::{OwnedStream, StreamInput};

pub(in crate::execute) fn decode_constant_serial_chunk(
    stored: &[u8],
    header: &[u8],
    limits: Limits,
    scratch: &mut DecodeScratch,
) -> Result<OwnedStream> {
    let input = StreamInput {
        bytes: stored,
        element_width: 1,
        string_lengths: None,
    };
    decode_constant_typed_chunk(input, header, limits, scratch, "constant_serial")
}

pub(in crate::execute) fn decode_constant_fixed_chunk(
    stored: StreamInput<'_>,
    header: &[u8],
    limits: Limits,
    scratch: &mut DecodeScratch,
) -> Result<OwnedStream> {
    if stored.string_lengths.is_some() {
        return Err(Error::new(ErrorKind::InvalidType)
            .with_detail("constant_fixed input must not be a string stream"));
    }
    decode_constant_typed_chunk(stored, header, limits, scratch, "constant_fixed")
}

fn decode_constant_typed_chunk(
    stored: StreamInput<'_>,
    header: &[u8],
    limits: Limits,
    scratch: &mut DecodeScratch,
    name: &'static str,
) -> Result<OwnedStream> {
    if stored.element_width == 0 {
        return Err(Error::new(ErrorKind::InvalidType)
            .with_detail(format!("{name} element width must be nonzero")));
    }
    if stored.bytes.len() != stored.element_width {
        return Err(Error::new(ErrorKind::Malformed)
            .with_detail(format!("{name} input must contain one element")));
    }
    let mut offset = 0usize;
    let output_elements = read_var_u64(header, &mut offset)?;
    if offset != header.len() {
        return Err(
            Error::new(ErrorKind::Malformed).with_detail(format!("unexpected {name} header bytes"))
        );
    }
    if output_elements == 0 {
        return Err(Error::new(ErrorKind::Malformed)
            .with_detail(format!("{name} output count must be nonzero")));
    }
    let output_elements = usize::try_from(output_elements).map_err(|_| {
        Error::new(ErrorKind::LimitExceeded).with_detail("output count is too large")
    })?;
    let output_len = output_elements
        .checked_mul(stored.element_width)
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
    check_output_len(output_len, limits)?;
    let mut output = scratch.take_byte_buffer(output_len, "constant allocation failed")?;
    repeat_constant_element(stored.bytes, output_len, &mut output);
    Ok(OwnedStream::pooled(output, stored.element_width))
}

fn repeat_constant_element(element: &[u8], output_len: usize, output: &mut Vec<u8>) {
    if element.len() == 1 {
        output.resize(output_len, element[0]);
        return;
    }

    output.extend_from_slice(element);
    while output.len() < output_len {
        let len = output.len();
        let copy_len = len.min(output_len - len);
        output.extend_from_within(..copy_len);
    }
}

pub(in crate::execute) fn decode_dedup_num_node(
    stored: StreamInput<'_>,
    header: &[u8],
    output_count: usize,
    limits: Limits,
) -> Result<Vec<OwnedStream>> {
    require_empty_header(header, "dedup_num headers are unsupported")?;
    if output_count == 0 {
        return Err(
            Error::new(ErrorKind::InvalidGraph).with_detail("dedup_num output count is zero")
        );
    }
    if stored.string_lengths.is_some() {
        return Err(
            Error::new(ErrorKind::InvalidType).with_detail("dedup_num input must be numeric")
        );
    }
    validate_numeric_stream_width(stored.element_width, "dedup_num input")?;
    numeric_element_count(stored.bytes, stored.element_width)?;
    check_output_len(stored.bytes.len(), limits)?;
    let total_buffer_bytes = stored
        .bytes
        .len()
        .checked_mul(output_count)
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
    if total_buffer_bytes > limits.max_buffer_bytes {
        return Err(
            Error::new(ErrorKind::LimitExceeded).with_detail("decoded output limit exceeded")
        );
    }

    let mut outputs = Vec::new();
    outputs.try_reserve_exact(output_count).map_err(|_| {
        Error::new(ErrorKind::AllocationFailed).with_detail("dedup_num output allocation failed")
    })?;
    for _ in 0..output_count {
        let mut bytes = Vec::new();
        bytes.try_reserve_exact(stored.bytes.len()).map_err(|_| {
            Error::new(ErrorKind::AllocationFailed).with_detail("dedup_num allocation failed")
        })?;
        bytes.extend_from_slice(stored.bytes);
        outputs.push(OwnedStream::typed(bytes, stored.element_width));
    }
    Ok(outputs)
}
