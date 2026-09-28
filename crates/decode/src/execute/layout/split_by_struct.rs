//! The `split_by_struct` node: per-field streams interleaved back into
//! structs.

use alloc::vec::Vec;

use ozlrip_core::{Error, ErrorKind, Limits, Result};

use super::fast_split_struct;
use super::split_struct::split_by_struct_output_len;
use crate::execute::header::require_empty_header;
use crate::execute::output::{alloc_output, check_output_len};
use crate::execute::streams::{OwnedStream, StreamInput};

pub(in crate::execute) fn decode_split_by_struct_node(
    inputs: &[StreamInput<'_>],
    variable_inputs: u32,
    header: &[u8],
    limits: Limits,
) -> Result<OwnedStream> {
    require_empty_header(header, "split_by_struct headers are unsupported")?;
    let input_count = usize::try_from(variable_inputs).map_err(|_| {
        Error::new(ErrorKind::LimitExceeded).with_detail("too many split_by_struct inputs")
    })?;
    if inputs.len() != input_count {
        return Err(Error::new(ErrorKind::InvalidGraph)
            .with_detail("split_by_struct input count does not match node shape"));
    }
    let output_len = split_by_struct_output_len(inputs)?;
    let mut output = alloc_output(output_len, limits, "split_by_struct allocation failed")?;
    append_split_by_struct_output(inputs, limits, &mut output)?;
    Ok(OwnedStream {
        bytes: output,
        element_width: 1,
        string_lengths: None,
        recyclable: false,
    })
}

pub(in crate::execute) fn append_split_by_struct_output(
    inputs: &[StreamInput<'_>],
    limits: Limits,
    output: &mut Vec<u8>,
) -> Result<()> {
    let output_len = split_by_struct_output_len(inputs)?;
    check_output_len(output_len, limits)?;
    let required_capacity = output
        .len()
        .checked_add(output_len)
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
    if output.capacity() < required_capacity {
        output
            .try_reserve_exact(required_capacity - output.len())
            .map_err(|_| {
                Error::new(ErrorKind::AllocationFailed)
                    .with_detail("split_by_struct allocation failed")
            })?;
    }
    fast_split_struct::append_split_by_struct_output(inputs, output);
    Ok(())
}
