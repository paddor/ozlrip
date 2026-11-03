//! The `dispatch_string` node: strings from several sources, interleaved
//! in the order an index stream gives.

use alloc::vec::Vec;

use ozlrip_core::{Error, ErrorKind, Limits, Result};

use super::csv::append_u16_dispatched_to_serial;
use super::source::{DispatchStringSource, SerialOutput, append_dispatched_string_to_serial};
use crate::execute::elements::{checked_sum_u32, numeric_element_count, require_numeric_width};
use crate::execute::header::require_empty_header;
use crate::execute::output::{alloc_output, check_output_len};
use crate::execute::streams::{OwnedStream, StreamInput};

pub(in crate::execute) fn decode_dispatch_string_node(
    inputs: &[StreamInput<'_>],
    variable_inputs: u32,
    header: &[u8],
    format_version: u32,
    limits: Limits,
) -> Result<OwnedStream> {
    require_empty_header(header, "dispatch_string headers are unsupported")?;
    let (indices, string_inputs, index_count) =
        dispatch_shape(inputs, variable_inputs, format_version)?;
    let (mut sources, total_bytes) = collect_sources(string_inputs, index_count, true)?;
    let mut output = alloc_output(total_bytes, limits, "dispatch output allocation failed")?;
    let mut output_lengths = Vec::new();
    output_lengths.try_reserve_exact(index_count).map_err(|_| {
        Error::new(ErrorKind::AllocationFailed).with_detail("dispatch length allocation failed")
    })?;
    match indices.element_width {
        1 => {
            for &source in indices.bytes {
                append_dispatched_string(
                    usize::from(source),
                    &mut sources,
                    &mut output,
                    &mut output_lengths,
                )?;
            }
        }
        2 => {
            for source in indices.bytes.as_chunks::<2>().0 {
                append_dispatched_string(
                    usize::from(u16::from_le_bytes(*source)),
                    &mut sources,
                    &mut output,
                    &mut output_lengths,
                )?;
            }
        }
        _ => unreachable!("require_numeric_width accepted only the expected dispatch width"),
    }
    ensure_sources_consumed(&sources)?;
    Ok(OwnedStream::strings(output, output_lengths))
}

/// Splits a dispatch_string node's inputs into its index stream and string
/// sources, and returns the index count.
fn dispatch_shape<'a, 'b>(
    inputs: &'a [StreamInput<'b>],
    variable_inputs: u32,
    format_version: u32,
) -> Result<(&'a StreamInput<'b>, &'a [StreamInput<'b>], usize)> {
    let variable_inputs = usize::try_from(variable_inputs)
        .map_err(|_| Error::new(ErrorKind::LimitExceeded).with_detail("input count too large"))?;
    if inputs.len()
        != variable_inputs
            .checked_add(1)
            .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?
    {
        return Err(Error::new(ErrorKind::InvalidGraph)
            .with_detail("dispatch_string input count does not match node shape"));
    }
    let (indices, string_inputs) = inputs.split_first().ok_or_else(|| {
        Error::new(ErrorKind::InvalidGraph).with_detail("dispatch_string index stream is missing")
    })?;
    let expected_index_width = if format_version < 21 { 1 } else { 2 };
    require_numeric_width(indices, expected_index_width, "dispatch_string indices")?;
    let index_count = numeric_element_count(indices.bytes, indices.element_width)?;
    if index_count != 0 && string_inputs.is_empty() {
        return Err(Error::new(ErrorKind::Malformed)
            .with_detail("dispatch_string indices require string inputs"));
    }
    Ok((indices, string_inputs, index_count))
}

/// One source per string input, and their total content size. With
/// `verify_sums`, each input's lengths must add up to its content;
/// direct-append inputs come from nodes that already checked that.
fn collect_sources<'a>(
    string_inputs: &[StreamInput<'a>],
    index_count: usize,
    verify_sums: bool,
) -> Result<(Vec<DispatchStringSource<'a>>, usize)> {
    let mut sources = Vec::new();
    sources
        .try_reserve_exact(string_inputs.len())
        .map_err(|_| {
            Error::new(ErrorKind::AllocationFailed).with_detail("dispatch allocation failed")
        })?;
    let mut total_string_count = 0usize;
    let mut total_bytes = 0usize;
    for input in string_inputs {
        if input.element_width != 1 {
            return Err(Error::new(ErrorKind::InvalidType)
                .with_detail("dispatch_string inputs must be byte strings"));
        }
        let lengths = input.string_lengths.ok_or_else(|| {
            Error::new(ErrorKind::InvalidType)
                .with_detail("dispatch_string input is missing string lengths")
        })?;
        if verify_sums && checked_sum_u32(lengths)? != input.bytes.len() {
            return Err(Error::new(ErrorKind::Malformed)
                .with_detail("dispatch_string input lengths do not sum to content size"));
        }
        total_string_count = total_string_count
            .checked_add(lengths.len())
            .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
        total_bytes = total_bytes
            .checked_add(input.bytes.len())
            .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
        sources.push(DispatchStringSource {
            bytes: input.bytes,
            lengths,
            position: 0,
            byte_position: 0,
        });
    }
    if index_count != total_string_count {
        return Err(Error::new(ErrorKind::Malformed)
            .with_detail("dispatch_string index count does not match string count"));
    }
    Ok((sources, total_bytes))
}

fn ensure_sources_consumed(sources: &[DispatchStringSource<'_>]) -> Result<()> {
    for source in sources {
        if source.position != source.lengths.len() || source.byte_position != source.bytes.len() {
            return Err(Error::new(ErrorKind::Malformed)
                .with_detail("dispatch_string did not consume every source string"));
        }
    }
    Ok(())
}

#[expect(
    clippy::inline_always,
    reason = "profiled CSV dispatch hot path benefits from inlining this leaf"
)]
#[inline(always)]
fn append_dispatched_string(
    source: usize,
    sources: &mut [DispatchStringSource<'_>],
    output: &mut Vec<u8>,
    output_lengths: &mut Vec<u32>,
) -> Result<()> {
    let source = sources.get_mut(source).ok_or_else(|| {
        Error::new(ErrorKind::Malformed).with_detail("dispatch_string source index is invalid")
    })?;
    let length = *source.lengths.get(source.position).ok_or_else(|| {
        Error::new(ErrorKind::Malformed).with_detail("dispatch_string source is exhausted")
    })?;
    let length_usize = usize::try_from(length)
        .map_err(|_| Error::new(ErrorKind::LimitExceeded).with_detail("string length too large"))?;
    let offset = source.byte_position;
    let end = offset
        .checked_add(length_usize)
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
    let bytes = source.bytes.get(offset..end).ok_or_else(|| {
        Error::new(ErrorKind::Malformed).with_detail("dispatch_string range is invalid")
    })?;
    output.extend_from_slice(bytes);
    output_lengths.push(length);
    source.position = source
        .position
        .checked_add(1)
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
    source.byte_position = end;
    Ok(())
}

pub(in crate::execute) fn decode_dispatch_string_node_to_serial_output(
    inputs: &[StreamInput<'_>],
    variable_inputs: u32,
    header: &[u8],
    format_version: u32,
    limits: Limits,
    output: &mut Vec<u8>,
) -> Result<()> {
    require_empty_header(header, "dispatch_string headers are unsupported")?;
    let (indices, string_inputs, index_count) =
        dispatch_shape(inputs, variable_inputs, format_version)?;
    let (mut sources, total_bytes) = collect_sources(string_inputs, index_count, false)?;
    check_output_len(total_bytes, limits)?;
    output.try_reserve_exact(total_bytes).map_err(|_| {
        Error::new(ErrorKind::AllocationFailed).with_detail("dispatch output allocation failed")
    })?;
    let mut serial = SerialOutput::new(output);
    append_indices_to_serial(
        indices.bytes,
        indices.element_width,
        &mut sources,
        &mut serial,
    )?;
    ensure_sources_consumed(&sources)
}

fn append_indices_to_serial(
    indices: &[u8],
    index_width: usize,
    sources: &mut [DispatchStringSource<'_>],
    output: &mut SerialOutput<'_>,
) -> Result<()> {
    match index_width {
        1 => {
            for &source in indices {
                append_dispatched_string_to_serial(usize::from(source), sources, output)?;
            }
            Ok(())
        }
        2 => append_u16_dispatched_to_serial(indices, sources, output),
        _ => unreachable!("require_numeric_width accepted only the expected dispatch width"),
    }
}
