//! The `concat_serial`, `concat_num` and `concat_struct` nodes, and the
//! size-stream helpers `concat_string` shares.

use alloc::vec::Vec;

use ozlrip_core::{Error, ErrorKind, Limits, Result};

use crate::execute::elements::{numeric_element_count, read_usize_numeric_element};
use crate::execute::header::require_empty_header;
use crate::execute::output::check_output_len;
use crate::execute::streams::{OwnedStream, StreamInput};

pub(in crate::execute) fn decode_concat_node(
    inputs: &[StreamInput<'_>],
    header: &[u8],
    expected_outputs: usize,
    limits: Limits,
) -> Result<Vec<OwnedStream>> {
    require_empty_header(header, "concat transform headers are unsupported")?;
    let [sizes, concatenated] = inputs else {
        return Err(Error::new(ErrorKind::InvalidGraph)
            .with_detail("concat input count does not match node shape"));
    };
    let output_count = concat_output_count(sizes, expected_outputs)?;
    if concatenated.element_width == 0 {
        return Err(Error::new(ErrorKind::InvalidType).with_detail("concat element width is zero"));
    }
    if !concatenated
        .bytes
        .len()
        .is_multiple_of(concatenated.element_width)
    {
        return Err(
            Error::new(ErrorKind::Malformed).with_detail("concat input has partial element")
        );
    }

    let total_elements = numeric_element_count(concatenated.bytes, concatenated.element_width)?;
    let mut consumed_elements = 0usize;
    let mut consumed_bytes = 0usize;
    let mut outputs = Vec::new();
    outputs.try_reserve_exact(output_count).map_err(|_| {
        Error::new(ErrorKind::AllocationFailed).with_detail("concat output allocation failed")
    })?;

    for output_index in 0..output_count {
        let output_elements = read_concat_size(sizes, output_index)?;
        let output_bytes = output_elements
            .checked_mul(concatenated.element_width)
            .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
        check_output_len(output_bytes, limits)?;
        let next_elements = consumed_elements
            .checked_add(output_elements)
            .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
        let next_bytes = consumed_bytes
            .checked_add(output_bytes)
            .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
        if next_elements > total_elements || next_bytes > concatenated.bytes.len() {
            return Err(Error::new(ErrorKind::Malformed).with_detail("concat size exceeds input"));
        }
        let mut output = Vec::new();
        output.try_reserve_exact(output_bytes).map_err(|_| {
            Error::new(ErrorKind::AllocationFailed).with_detail("concat allocation failed")
        })?;
        output.extend_from_slice(&concatenated.bytes[consumed_bytes..next_bytes]);
        outputs.push(OwnedStream {
            bytes: output,
            element_width: concatenated.element_width,
            string_lengths: None,
            recyclable: false,
        });
        consumed_elements = next_elements;
        consumed_bytes = next_bytes;
    }

    if consumed_elements != total_elements || consumed_bytes != concatenated.bytes.len() {
        return Err(
            Error::new(ErrorKind::Malformed).with_detail("concat sizes do not consume input")
        );
    }
    Ok(outputs)
}

fn concat_size_count(sizes: &StreamInput<'_>) -> Result<usize> {
    match sizes.element_width {
        1 | 4 => numeric_element_count(sizes.bytes, 4),
        _ => {
            Err(Error::new(ErrorKind::InvalidType).with_detail("concat sizes width is unsupported"))
        }
    }
}

/// Checks the size table against the graph before any per-output allocation,
/// so a large table cannot reserve outputs the graph does not have.
pub(in crate::execute) fn concat_output_count(
    sizes: &StreamInput<'_>,
    expected_outputs: usize,
) -> Result<usize> {
    let output_count = concat_size_count(sizes)?;
    if output_count == 0 {
        return Err(Error::new(ErrorKind::Malformed).with_detail("concat size table is empty"));
    }
    if output_count != expected_outputs {
        return Err(Error::new(ErrorKind::InvalidGraph)
            .with_detail("node output count does not match graph"));
    }
    Ok(output_count)
}

pub(in crate::execute) fn read_concat_size(sizes: &StreamInput<'_>, index: usize) -> Result<usize> {
    match sizes.element_width {
        1 | 4 => read_usize_numeric_element(sizes.bytes, 4, index),
        _ => {
            Err(Error::new(ErrorKind::InvalidType).with_detail("concat sizes width is unsupported"))
        }
    }
}
