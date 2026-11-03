//! The `sentinel` node: a value stream whose sentinel entries are replaced
//! from an exception stream.

use ozlrip_core::{Error, ErrorKind, Limits, Result};

use crate::execute::elements::{
    max_numeric_value, numeric_element_count, read_numeric_element, read_var_u64,
    validate_numeric_stream_width, write_numeric_element,
};
use crate::execute::output::alloc_output;
use crate::execute::streams::{OwnedStream, StreamInput};

pub(in crate::execute) fn decode_sentinel_node(
    inputs: &[StreamInput<'_>],
    header: &[u8],
    limits: Limits,
) -> Result<OwnedStream> {
    let [values, exceptions] = inputs else {
        return Err(Error::new(ErrorKind::InvalidGraph)
            .with_detail("sentinel input count does not match node shape"));
    };
    validate_numeric_stream_width(values.element_width, "sentinel values")?;
    validate_numeric_stream_width(exceptions.element_width, "sentinel exceptions")?;
    if values.element_width > exceptions.element_width {
        return Err(Error::new(ErrorKind::Malformed)
            .with_detail("sentinel values width exceeds output width"));
    }
    let sentinel = parse_sentinel(header, max_numeric_value(values.element_width)?)?;
    let value_count = numeric_element_count(values.bytes, values.element_width)?;
    let exception_count = numeric_element_count(exceptions.bytes, exceptions.element_width)?;
    let output_len = value_count
        .checked_mul(exceptions.element_width)
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
    let mut output = alloc_output(output_len, limits, "sentinel allocation failed")?;
    output.resize(output_len, 0);
    let mut exception_index = 0usize;
    for value_index in 0..value_count {
        let value = read_numeric_element(values.bytes, values.element_width, value_index)?;
        let output_offset = value_index
            .checked_mul(exceptions.element_width)
            .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
        if value == sentinel {
            if exception_index >= exception_count {
                return Err(Error::new(ErrorKind::Malformed)
                    .with_detail("sentinel exception stream is exhausted"));
            }
            let exception =
                read_numeric_element(exceptions.bytes, exceptions.element_width, exception_index)?;
            write_numeric_element(
                &mut output[output_offset..],
                exceptions.element_width,
                exception,
            );
            exception_index = exception_index
                .checked_add(1)
                .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
        } else {
            write_numeric_element(
                &mut output[output_offset..],
                exceptions.element_width,
                value,
            );
        }
    }
    if exception_index != exception_count {
        return Err(Error::new(ErrorKind::Malformed)
            .with_detail("sentinel exception stream was not fully consumed"));
    }
    Ok(OwnedStream::typed(output, exceptions.element_width))
}

/// The sentinel value a header names, or `max_value` for an empty header.
fn parse_sentinel(header: &[u8], max_value: u64) -> Result<u64> {
    if header.is_empty() {
        return Ok(max_value);
    }
    let mut offset = 0usize;
    let value = read_var_u64(header, &mut offset)?;
    if offset != header.len() {
        return Err(
            Error::new(ErrorKind::Malformed).with_detail("sentinel header has trailing bytes")
        );
    }
    if value > max_value {
        return Err(
            Error::new(ErrorKind::Malformed).with_detail("sentinel value exceeds values width")
        );
    }
    Ok(value)
}
