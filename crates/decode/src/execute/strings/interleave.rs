//! The `interleave_string` node.

use alloc::vec::Vec;

use ozlrip_core::{Error, ErrorKind, Limits, Result};

use crate::execute::elements::checked_sum_u32;
use crate::execute::output::{alloc_output, check_output_len};
use crate::execute::streams::{OwnedStream, StreamInput};

pub(in crate::execute) fn decode_interleave_string_node(
    input: StreamInput<'_>,
    header: &[u8],
    limits: Limits,
) -> Result<Vec<OwnedStream>> {
    let output_count = interleave_output_count(header, limits)?;
    if input.element_width != 1 {
        return Err(Error::new(ErrorKind::InvalidType)
            .with_detail("interleave_string input must be byte strings"));
    }
    let string_lengths = input.string_lengths.ok_or_else(|| {
        Error::new(ErrorKind::InvalidType).with_detail("interleave_string input is missing lengths")
    })?;
    if string_lengths.len() % output_count != 0 {
        return Err(Error::new(ErrorKind::Malformed)
            .with_detail("interleave_string input count is not divisible by output count"));
    }
    if checked_sum_u32(string_lengths)? != input.bytes.len() {
        return Err(Error::new(ErrorKind::Malformed)
            .with_detail("interleave_string lengths do not sum to content size"));
    }
    check_output_len(input.bytes.len(), limits)?;

    let strings_per_output = string_lengths.len() / output_count;
    let byte_counts = interleave_byte_counts(string_lengths, output_count)?;
    let mut outputs = Vec::new();
    outputs.try_reserve_exact(output_count).map_err(|_| {
        Error::new(ErrorKind::AllocationFailed).with_detail("interleave output allocation failed")
    })?;
    for &byte_count in &byte_counts {
        let bytes = alloc_output(byte_count, limits, "interleave allocation failed")?;
        let mut lengths = Vec::new();
        lengths.try_reserve_exact(strings_per_output).map_err(|_| {
            Error::new(ErrorKind::AllocationFailed)
                .with_detail("interleave length allocation failed")
        })?;
        outputs.push(OwnedStream::strings(bytes, lengths));
    }

    let mut src_offset = 0usize;
    for (index, &len) in string_lengths.iter().enumerate() {
        let len_usize = usize::try_from(len).map_err(|_| {
            Error::new(ErrorKind::LimitExceeded).with_detail("string length is too large")
        })?;
        let src_end = src_offset
            .checked_add(len_usize)
            .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
        let bytes = input.bytes.get(src_offset..src_end).ok_or_else(|| {
            Error::new(ErrorKind::Malformed).with_detail("interleave_string input is truncated")
        })?;
        let output_index = index % output_count;
        outputs[output_index].bytes.extend_from_slice(bytes);
        outputs[output_index]
            .string_lengths
            .as_mut()
            .ok_or_else(|| Error::new(ErrorKind::InvalidGraph))?
            .push(len);
        src_offset = src_end;
    }
    debug_assert_eq!(src_offset, input.bytes.len());
    Ok(outputs)
}

/// The output count an interleave_string header holds.
fn interleave_output_count(header: &[u8], limits: Limits) -> Result<usize> {
    let [b0, b1, b2, b3] = header else {
        return Err(
            Error::new(ErrorKind::Malformed).with_detail("interleave_string header is malformed")
        );
    };
    let output_count = u32::from_le_bytes([*b0, *b1, *b2, *b3]);
    let output_count = usize::try_from(output_count).map_err(|_| {
        Error::new(ErrorKind::LimitExceeded).with_detail("interleave_string output count too large")
    })?;
    if output_count == 0 {
        return Err(Error::new(ErrorKind::Malformed)
            .with_detail("interleave_string output count must be nonzero"));
    }
    if output_count > limits.max_streams {
        return Err(Error::new(ErrorKind::LimitExceeded)
            .with_detail("interleave_string output count too large"));
    }
    Ok(output_count)
}

/// Content bytes of each interleave_string output.
fn interleave_byte_counts(string_lengths: &[u32], output_count: usize) -> Result<Vec<usize>> {
    let mut byte_counts = Vec::new();
    byte_counts.try_reserve_exact(output_count).map_err(|_| {
        Error::new(ErrorKind::AllocationFailed).with_detail("interleave size allocation failed")
    })?;
    byte_counts.resize(output_count, 0usize);
    for (index, &len) in string_lengths.iter().enumerate() {
        let len = usize::try_from(len).map_err(|_| {
            Error::new(ErrorKind::LimitExceeded).with_detail("string length is too large")
        })?;
        let output_index = index % output_count;
        byte_counts[output_index] = byte_counts[output_index]
            .checked_add(len)
            .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
    }
    Ok(byte_counts)
}
