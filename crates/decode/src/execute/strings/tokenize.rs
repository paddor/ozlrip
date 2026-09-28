//! The `tokenize` node for strings: an alphabet of strings and indexes
//! into it.

use alloc::vec::Vec;

use ozlrip_core::{Error, ErrorKind, Limits, Result};

use super::concat::byte_string_lengths;
use crate::execute::elements::{
    numeric_element_count, read_usize_numeric_element, validate_numeric_stream_width,
};
use crate::execute::header::require_empty_header;
use crate::execute::output::alloc_output;
use crate::execute::streams::{OwnedStream, StreamInput};

pub(in crate::execute) fn decode_tokenize_string_node(
    inputs: &[StreamInput<'_>],
    header: &[u8],
    limits: Limits,
) -> Result<OwnedStream> {
    require_empty_header(header, "tokenize_string headers are unsupported")?;
    let [alphabet, indices] = inputs else {
        return Err(Error::new(ErrorKind::InvalidGraph)
            .with_detail("tokenize_string input count does not match node shape"));
    };
    let alphabet_lengths = byte_string_lengths(
        alphabet,
        [
            "tokenize_string alphabet must be byte strings",
            "tokenize_string alphabet is missing string lengths",
            "tokenize_string alphabet lengths do not sum to content size",
        ],
    )?;
    validate_numeric_stream_width(indices.element_width, "tokenize_string indices")?;

    let alphabet_size = alphabet_lengths.len();
    let output_elements = numeric_element_count(indices.bytes, indices.element_width)?;
    if alphabet_size == 0 {
        if output_elements == 0 {
            return Ok(OwnedStream::strings(Vec::new(), Vec::new()));
        }
        return Err(
            Error::new(ErrorKind::Malformed).with_detail("tokenize_string alphabet is empty")
        );
    }
    if output_elements < alphabet_size {
        return Err(Error::new(ErrorKind::Malformed)
            .with_detail("tokenize_string output count is smaller than alphabet"));
    }

    let starts = alphabet_starts(alphabet_lengths)?;
    let output_len = tokenized_len(indices, alphabet_lengths, output_elements)?;
    let mut bytes = alloc_output(output_len, limits, "tokenize_string allocation failed")?;
    let mut lengths = Vec::new();
    lengths.try_reserve_exact(output_elements).map_err(|_| {
        Error::new(ErrorKind::AllocationFailed)
            .with_detail("tokenize_string length allocation failed")
    })?;

    for index in 0..output_elements {
        let token = read_usize_numeric_element(indices.bytes, indices.element_width, index)?;
        let start = starts[token];
        let len = alphabet_lengths[token];
        let len_usize = usize::try_from(len).map_err(|_| {
            Error::new(ErrorKind::LimitExceeded).with_detail("string length is too large")
        })?;
        let end = start
            .checked_add(len_usize)
            .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
        let token_bytes = alphabet.bytes.get(start..end).ok_or_else(|| {
            Error::new(ErrorKind::Malformed).with_detail("tokenize_string alphabet is truncated")
        })?;
        bytes.extend_from_slice(token_bytes);
        lengths.push(len);
    }

    Ok(OwnedStream::strings(bytes, lengths))
}

/// Offset of each alphabet string in the tokenize_string alphabet content.
fn alphabet_starts(alphabet_lengths: &[u32]) -> Result<Vec<usize>> {
    let mut starts = Vec::new();
    starts
        .try_reserve_exact(alphabet_lengths.len())
        .map_err(|_| {
            Error::new(ErrorKind::AllocationFailed)
                .with_detail("tokenize_string alphabet allocation failed")
        })?;
    let mut offset = 0usize;
    for &len in alphabet_lengths {
        starts.push(offset);
        let len = usize::try_from(len).map_err(|_| {
            Error::new(ErrorKind::LimitExceeded).with_detail("string length is too large")
        })?;
        offset = offset
            .checked_add(len)
            .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
    }
    Ok(starts)
}

/// Total content size of the strings `indices` select.
fn tokenized_len(
    indices: &StreamInput<'_>,
    alphabet_lengths: &[u32],
    output_elements: usize,
) -> Result<usize> {
    let mut output_len = 0usize;
    for index in 0..output_elements {
        let token = read_usize_numeric_element(indices.bytes, indices.element_width, index)?;
        let &token_len = alphabet_lengths.get(token).ok_or_else(|| {
            Error::new(ErrorKind::Malformed).with_detail("tokenize_string index is out of range")
        })?;
        let token_len = usize::try_from(token_len).map_err(|_| {
            Error::new(ErrorKind::LimitExceeded).with_detail("string length is too large")
        })?;
        output_len = output_len
            .checked_add(token_len)
            .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
    }
    Ok(output_len)
}
