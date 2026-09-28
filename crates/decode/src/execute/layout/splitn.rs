//! The `splitn` nodes: several streams joined back into one.

use alloc::vec::Vec;

use ozlrip_core::{Error, ErrorKind, Limits, Result};

use crate::execute::elements::read_var_u64;
use crate::execute::header::require_empty_header;
use crate::execute::output::alloc_output;
use crate::execute::streams::{OwnedStream, StreamInput};

pub(in crate::execute) fn decode_splitn_node(
    inputs: &[StreamInput<'_>],
    variable_inputs: u32,
    header: &[u8],
    limits: Limits,
) -> Result<Vec<u8>> {
    Ok(decode_splitn_typed_node(inputs, variable_inputs, header, limits)?.bytes)
}

pub(in crate::execute) fn decode_splitn_typed_node(
    inputs: &[StreamInput<'_>],
    variable_inputs: u32,
    header: &[u8],
    limits: Limits,
) -> Result<OwnedStream> {
    let input_count = usize::try_from(variable_inputs)
        .map_err(|_| Error::new(ErrorKind::LimitExceeded).with_detail("too many splitn inputs"))?;
    if inputs.len() != input_count {
        return Err(Error::new(ErrorKind::InvalidGraph)
            .with_detail("splitn input count does not match node shape"));
    }
    if input_count == 0 {
        let element_width = splitn_empty_element_width(header)?;
        return Ok(OwnedStream {
            bytes: Vec::new(),
            element_width,
            string_lengths: None,
            recyclable: false,
        });
    }
    require_empty_header(header, "splitn headers are unsupported")?;
    let element_width = inputs[0].element_width;
    if element_width == 0 {
        return Err(Error::new(ErrorKind::InvalidType).with_detail("splitn element width is zero"));
    }

    let mut total_len = 0usize;
    for input in inputs {
        if input.element_width != element_width {
            return Err(
                Error::new(ErrorKind::InvalidType).with_detail("splitn input widths must match")
            );
        }
        if !input.bytes.len().is_multiple_of(element_width) {
            return Err(
                Error::new(ErrorKind::Malformed).with_detail("splitn input has partial element")
            );
        }
        total_len = total_len.checked_add(input.bytes.len()).ok_or_else(|| {
            Error::new(ErrorKind::IntegerOverflow).with_detail("splitn size overflowed")
        })?;
    }
    let mut output = alloc_output(total_len, limits, "splitn allocation failed")?;
    for input in inputs {
        output.extend_from_slice(input.bytes);
    }
    Ok(OwnedStream {
        bytes: output,
        element_width,
        string_lengths: None,
        recyclable: false,
    })
}

fn splitn_empty_element_width(header: &[u8]) -> Result<usize> {
    if header.is_empty() {
        return Ok(1);
    }
    let mut offset = 0usize;
    let element_width = read_var_u64(header, &mut offset)?;
    if offset != header.len() {
        return Err(Error::new(ErrorKind::Malformed).with_detail("unexpected splitn header bytes"));
    }
    if element_width == 0 {
        return Err(
            Error::new(ErrorKind::Malformed).with_detail("splitn element width must be nonzero")
        );
    }
    usize::try_from(element_width)
        .map_err(|_| Error::new(ErrorKind::LimitExceeded).with_detail("splitn width is too large"))
}
