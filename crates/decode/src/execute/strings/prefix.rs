//! The `prefix` node: strings rebuilt from suffixes and the length each
//! shares with the string before it.

use alloc::vec::Vec;

use ozlrip_core::{Error, ErrorKind, Limits, Result};

use super::concat::byte_string_lengths;
use crate::execute::elements::{numeric_element_count, read_usize_numeric_element};
use crate::execute::header::require_empty_header;
use crate::execute::output::alloc_output;
use crate::execute::streams::{OwnedStream, StreamInput};

pub(in crate::execute) fn decode_prefix_node(
    inputs: &[StreamInput<'_>],
    header: &[u8],
    limits: Limits,
) -> Result<OwnedStream> {
    require_empty_header(header, "prefix headers are unsupported")?;
    let [suffixes, match_sizes] = inputs else {
        return Err(Error::new(ErrorKind::InvalidGraph)
            .with_detail("prefix input count does not match node shape"));
    };
    let suffix_lengths = byte_string_lengths(
        suffixes,
        [
            "prefix suffixes must be byte strings",
            "prefix suffixes are missing lengths",
            "prefix suffix lengths do not sum to content size",
        ],
    )?;
    if match_sizes.element_width != 4 {
        return Err(Error::new(ErrorKind::InvalidType)
            .with_detail("prefix match sizes width is unsupported"));
    }
    let match_count = numeric_element_count(match_sizes.bytes, match_sizes.element_width)?;
    if match_count != suffix_lengths.len() {
        return Err(Error::new(ErrorKind::Malformed)
            .with_detail("prefix match count does not match suffix count"));
    }

    let (output_lengths, output_len) = prefix_output_lengths(suffix_lengths, match_sizes.bytes)?;
    let mut output = alloc_output(output_len, limits, "prefix allocation failed")?;
    let mut suffix_offset = 0usize;
    let mut previous_start = 0usize;
    let mut previous_len = 0usize;
    for (index, &suffix_len) in suffix_lengths.iter().enumerate() {
        let match_len = read_usize_numeric_element(match_sizes.bytes, 4, index)?;
        let suffix_len = usize::try_from(suffix_len).map_err(|_| {
            Error::new(ErrorKind::LimitExceeded).with_detail("prefix suffix length is too large")
        })?;
        output.extend_from_within(previous_start..previous_start + match_len);
        let suffix_end = suffix_offset
            .checked_add(suffix_len)
            .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
        output.extend_from_slice(&suffixes.bytes[suffix_offset..suffix_end]);
        previous_len = usize::try_from(output_lengths[index]).map_err(|_| {
            Error::new(ErrorKind::LimitExceeded).with_detail("prefix output length is too large")
        })?;
        previous_start = output
            .len()
            .checked_sub(previous_len)
            .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
        debug_assert_eq!(previous_start + previous_len, output.len());
        suffix_offset = suffix_end;
    }
    debug_assert_eq!(previous_start + previous_len, output.len());
    debug_assert_eq!(output.len(), output_len);
    Ok(OwnedStream::strings(output, output_lengths))
}

/// Each prefix output string's length, and their total.
fn prefix_output_lengths(suffix_lengths: &[u32], match_sizes: &[u8]) -> Result<(Vec<u32>, usize)> {
    let mut output_lengths = Vec::new();
    output_lengths
        .try_reserve_exact(suffix_lengths.len())
        .map_err(|_| {
            Error::new(ErrorKind::AllocationFailed).with_detail("prefix length allocation failed")
        })?;
    let mut output_len = 0usize;
    let mut previous_len = 0usize;
    for (index, &suffix_len) in suffix_lengths.iter().enumerate() {
        let match_len = read_usize_numeric_element(match_sizes, 4, index)?;
        if match_len > previous_len {
            return Err(Error::new(ErrorKind::Malformed)
                .with_detail("prefix match exceeds previous string"));
        }
        let suffix_len = usize::try_from(suffix_len).map_err(|_| {
            Error::new(ErrorKind::LimitExceeded).with_detail("prefix suffix length is too large")
        })?;
        let current_len = match_len
            .checked_add(suffix_len)
            .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
        output_len = output_len
            .checked_add(current_len)
            .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
        output_lengths.push(u32::try_from(current_len).map_err(|_| {
            Error::new(ErrorKind::LimitExceeded).with_detail("prefix output length is too large")
        })?);
        previous_len = current_len;
    }
    Ok((output_lengths, output_len))
}
