//! The `dispatch_n_by_tag` node: segments from several streams,
//! interleaved in the order a tag stream gives.

use alloc::vec::Vec;

use ozlrip_core::{Error, ErrorKind, Limits, Result};

use super::fast_dispatch;
use crate::execute::elements::{
    numeric_element_count, read_usize_numeric_element, validate_numeric_stream_width,
};
use crate::execute::header::require_empty_header;
use crate::execute::output::check_output_len;
use crate::execute::streams::StreamInput;

pub(in crate::execute) fn decode_dispatch_n_by_tag_node(
    inputs: &[StreamInput<'_>],
    variable_inputs: u32,
    header: &[u8],
    format_version: u32,
    limits: Limits,
) -> Result<Vec<u8>> {
    require_empty_header(header, "dispatchN_byTag headers are unsupported")?;
    let (tags, segment_sizes, segment_inputs, segment_count) =
        n_by_tag_shape(inputs, variable_inputs, format_version)?;
    let total_output =
        check_n_by_tag_segments(tags, segment_sizes, segment_inputs, segment_count, limits)?;
    let mut output = Vec::new();
    fast_dispatch::decode_dispatch_n_by_tag_to_output(
        tags,
        segment_sizes,
        segment_inputs,
        segment_count,
        total_output,
        &mut output,
    )?;
    if output.len() != total_output {
        return Err(
            Error::new(ErrorKind::Malformed).with_detail("dispatchN_byTag output size mismatch")
        );
    }
    Ok(output)
}

/// Splits a dispatchN_byTag node's inputs into tags, segment sizes and
/// source streams, and returns the segment count.
fn n_by_tag_shape<'a, 'b>(
    inputs: &'a [StreamInput<'b>],
    variable_inputs: u32,
    format_version: u32,
) -> Result<(
    &'a StreamInput<'b>,
    &'a StreamInput<'b>,
    &'a [StreamInput<'b>],
    usize,
)> {
    let variable_inputs = usize::try_from(variable_inputs)
        .map_err(|_| Error::new(ErrorKind::LimitExceeded).with_detail("input count too large"))?;
    if inputs.len()
        != variable_inputs
            .checked_add(2)
            .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?
    {
        return Err(Error::new(ErrorKind::InvalidGraph)
            .with_detail("dispatchN_byTag input count does not match node shape"));
    }
    let [tags, segment_sizes, segment_inputs @ ..] = inputs else {
        return Err(Error::new(ErrorKind::InvalidGraph)
            .with_detail("dispatchN_byTag input count does not match node shape"));
    };
    if segment_inputs.len() != variable_inputs {
        return Err(Error::new(ErrorKind::InvalidGraph)
            .with_detail("dispatchN_byTag variable input count does not match node shape"));
    }
    let expected_tag_width = if format_version < 20 { 1 } else { 2 };
    if tags.element_width > expected_tag_width {
        return Err(Error::new(ErrorKind::Unsupported)
            .with_detail("dispatchN_byTag tag width is unsupported"));
    }
    validate_numeric_stream_width(tags.element_width, "dispatchN_byTag tags")?;
    validate_numeric_stream_width(segment_sizes.element_width, "dispatchN_byTag segment sizes")?;
    let segment_count = numeric_element_count(segment_sizes.bytes, segment_sizes.element_width)?;
    if numeric_element_count(tags.bytes, tags.element_width)? != segment_count {
        return Err(Error::new(ErrorKind::Malformed)
            .with_detail("dispatchN_byTag tag count does not match segment count"));
    }
    if segment_count != 0 && segment_inputs.is_empty() {
        return Err(Error::new(ErrorKind::Malformed)
            .with_detail("dispatchN_byTag segments require source streams"));
    }
    if format_version < 20 && segment_inputs.len() >= 256 {
        return Err(Error::new(ErrorKind::Unsupported)
            .with_detail("dispatchN_byTag source count is unsupported"));
    }
    if format_version >= 20 && segment_inputs.len() >= (1usize << 16) {
        return Err(Error::new(ErrorKind::Unsupported)
            .with_detail("dispatchN_byTag source count is unsupported"));
    }
    Ok((tags, segment_sizes, segment_inputs, segment_count))
}

/// Checks that the segments of each tag add up to its source stream, and
/// returns the total output size.
fn check_n_by_tag_segments(
    tags: &StreamInput<'_>,
    segment_sizes: &StreamInput<'_>,
    segment_inputs: &[StreamInput<'_>],
    segment_count: usize,
    limits: Limits,
) -> Result<usize> {
    let mut source_totals = Vec::new();
    source_totals
        .try_reserve_exact(segment_inputs.len())
        .map_err(|_| {
            Error::new(ErrorKind::AllocationFailed).with_detail("dispatchN_byTag allocation failed")
        })?;
    let mut total_output = 0usize;
    for input in segment_inputs {
        if input.element_width == 0 {
            return Err(Error::new(ErrorKind::InvalidType)
                .with_detail("dispatchN_byTag source width is zero"));
        }
        source_totals.push(0usize);
        total_output = total_output
            .checked_add(input.bytes.len())
            .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
    }
    check_output_len(total_output, limits)?;

    for segment in 0..segment_count {
        let tag = read_usize_numeric_element(tags.bytes, tags.element_width, segment)?;
        let size =
            read_usize_numeric_element(segment_sizes.bytes, segment_sizes.element_width, segment)?;
        let source_total = source_totals.get_mut(tag).ok_or_else(|| {
            Error::new(ErrorKind::Malformed).with_detail("dispatchN_byTag tag is out of range")
        })?;
        *source_total = source_total
            .checked_add(size)
            .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
    }
    for (total, input) in source_totals.iter().zip(segment_inputs) {
        if *total != input.bytes.len() {
            return Err(Error::new(ErrorKind::Malformed)
                .with_detail("dispatchN_byTag segment sizes do not consume source stream"));
        }
    }
    Ok(total_output)
}
