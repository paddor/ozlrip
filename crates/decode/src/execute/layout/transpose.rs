//! The `transpose` and `transpose_split` nodes.

use crate::standard;
use ozlrip_core::{Error, ErrorKind, Limits, Result};

use super::fast_transpose;
use crate::execute::header::require_empty_header;
use crate::execute::output::check_output_len;
use crate::execute::runtime::DecodeScratch;
use crate::execute::streams::{OwnedStream, StreamInput};

pub(in crate::execute) fn is_transpose_split(id: u32) -> bool {
    id == standard::TRANSPOSE_SPLIT_ID || transpose_split_width(Some(id)).is_some()
}

fn transpose_split_width(id: Option<u32>) -> Option<usize> {
    match id {
        Some(standard::TRANSPOSE_SPLIT2_ID) => Some(2),
        Some(standard::TRANSPOSE_SPLIT4_ID) => Some(4),
        Some(standard::TRANSPOSE_SPLIT8_ID) => Some(8),
        _ => None,
    }
}

pub(in crate::execute) fn decode_transpose_node(
    source: StreamInput<'_>,
    header: &[u8],
    limits: Limits,
    scratch: &mut DecodeScratch,
) -> Result<OwnedStream> {
    require_empty_header(header, "transpose transform headers are unsupported")?;
    let source_width = source.element_width;
    if source_width == 0 || !source.bytes.len().is_multiple_of(source_width) {
        return Err(Error::new(ErrorKind::Malformed)
            .with_detail("transpose input size is not a multiple of width"));
    }
    let output_len = source.bytes.len();
    check_output_len(output_len, limits)?;

    let source_elements = source.bytes.len() / source_width;
    let output_width = if source_elements == 0 {
        source_width
    } else {
        source_elements
    };
    let mut output = scratch.take_stale_byte_buffer(output_len, "transpose allocation failed")?;
    output.resize(output_len, 0);
    for output_element in 0..source_width {
        for output_byte in 0..source_elements {
            output[output_element * output_width + output_byte] =
                source.bytes[output_byte * source_width + output_element];
        }
    }
    Ok(OwnedStream::pooled(output, output_width))
}

pub(in crate::execute) fn decode_transpose_split_node(
    inputs: &[StreamInput<'_>],
    variable_inputs: u32,
    header: &[u8],
    limits: Limits,
    scratch: &mut DecodeScratch,
) -> Result<OwnedStream> {
    require_empty_header(header, "transpose_split transform headers are unsupported")?;
    if variable_inputs != 0
        && usize::try_from(variable_inputs).is_ok_and(|count| count != inputs.len())
    {
        return Err(Error::new(ErrorKind::InvalidGraph)
            .with_detail("transpose_split variable input count does not match inputs"));
    }
    let Some(first) = inputs.first() else {
        return Err(Error::new(ErrorKind::InvalidGraph)
            .with_detail("transpose_split input count does not match width"));
    };
    let width = inputs.len();
    let lane_len = first.bytes.len();
    let output_len = lane_len.checked_mul(width).ok_or_else(|| {
        Error::new(ErrorKind::IntegerOverflow).with_detail("transpose size overflowed")
    })?;
    check_output_len(output_len, limits)?;
    for lane in inputs {
        if lane.bytes.len() != lane_len {
            return Err(Error::new(ErrorKind::Malformed)
                .with_detail("transpose_split lanes have different sizes"));
        }
    }
    let mut output = scratch.take_stale_byte_buffer(output_len, "transpose allocation failed")?;
    fast_transpose::write_transpose_split_output(inputs, output_len, &mut output);
    Ok(OwnedStream::pooled(output, width))
}
