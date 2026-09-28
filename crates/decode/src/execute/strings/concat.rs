//! The `concat_string` node, and the byte-string input check the string
//! nodes share.

use alloc::vec::Vec;

use ozlrip_core::{Error, ErrorKind, Limits, Result};

use crate::execute::elements::checked_sum_u32;
use crate::execute::header::require_empty_header;
use crate::execute::layout::{concat_output_count, read_concat_size};
use crate::execute::output::check_output_len;
use crate::execute::streams::{OwnedStream, StreamInput};

pub(in crate::execute) fn decode_concat_string_node(
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
    let string_lengths = byte_string_lengths(
        concatenated,
        [
            "concat_string input must be byte strings",
            "concat_string input is missing lengths",
            "concat_string lengths do not sum to content size",
        ],
    )?;

    let mut consumed_elements = 0usize;
    let mut consumed_bytes = 0usize;
    let mut outputs = Vec::new();
    outputs.try_reserve_exact(output_count).map_err(|_| {
        Error::new(ErrorKind::AllocationFailed).with_detail("concat output allocation failed")
    })?;

    for output_index in 0..output_count {
        let output_elements = read_concat_size(sizes, output_index)?;
        let next_elements = consumed_elements
            .checked_add(output_elements)
            .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
        if next_elements > string_lengths.len() {
            return Err(Error::new(ErrorKind::Malformed).with_detail("concat size exceeds input"));
        }
        let output_lengths = &string_lengths[consumed_elements..next_elements];
        let output_bytes = checked_sum_u32(output_lengths)?;
        check_output_len(output_bytes, limits)?;
        let next_bytes = consumed_bytes
            .checked_add(output_bytes)
            .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
        if next_bytes > concatenated.bytes.len() {
            return Err(Error::new(ErrorKind::Malformed).with_detail("concat size exceeds input"));
        }

        let mut output = Vec::new();
        output.try_reserve_exact(output_bytes).map_err(|_| {
            Error::new(ErrorKind::AllocationFailed).with_detail("concat allocation failed")
        })?;
        output.extend_from_slice(&concatenated.bytes[consumed_bytes..next_bytes]);
        let mut lengths = Vec::new();
        lengths
            .try_reserve_exact(output_lengths.len())
            .map_err(|_| {
                Error::new(ErrorKind::AllocationFailed)
                    .with_detail("concat length allocation failed")
            })?;
        lengths.extend_from_slice(output_lengths);
        outputs.push(OwnedStream::strings(output, lengths));
        consumed_elements = next_elements;
        consumed_bytes = next_bytes;
    }

    if consumed_elements != string_lengths.len() || consumed_bytes != concatenated.bytes.len() {
        return Err(
            Error::new(ErrorKind::Malformed).with_detail("concat sizes do not consume input")
        );
    }
    Ok(outputs)
}

/// The string lengths of a byte-string input, after checking its element
/// width and that the lengths add up to its content. `details` describe
/// the three checks in that order: width, missing lengths, length sum.
pub(super) fn byte_string_lengths<'a>(
    input: &StreamInput<'a>,
    details: [&'static str; 3],
) -> Result<&'a [u32]> {
    let [width, missing, sum] = details;
    if input.element_width != 1 {
        return Err(Error::new(ErrorKind::InvalidType).with_detail(width));
    }
    let lengths = input
        .string_lengths
        .ok_or_else(|| Error::new(ErrorKind::InvalidType).with_detail(missing))?;
    if checked_sum_u32(lengths)? != input.bytes.len() {
        return Err(Error::new(ErrorKind::Malformed).with_detail(sum));
    }
    Ok(lengths)
}
