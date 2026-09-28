use alloc::vec::Vec;

use ozlrip_core::{Error, ErrorKind, Limits, Result};

use super::elements::{
    checked_sum_u32, numeric_element_count, read_usize_numeric_element,
    validate_numeric_stream_width,
};
use super::fast_lengths;
use super::header::require_empty_header;
use super::layout_nodes::{concat_output_count, read_concat_size};
use super::output::{alloc_output, check_output_len};
use super::streams::{OwnedStream, StreamInput};

pub(super) fn decode_concat_string_node(
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

pub(super) fn decode_interleave_string_node(
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

pub(super) fn decode_separate_string_components_node(
    inputs: &[StreamInput<'_>],
    header: &[u8],
    limits: Limits,
) -> Result<OwnedStream> {
    require_empty_header(header, "separate_string_components headers are unsupported")?;
    let [content, field_sizes] = inputs else {
        return Err(Error::new(ErrorKind::InvalidGraph)
            .with_detail("separate_string_components input count does not match node shape"));
    };
    if content.element_width != 1 {
        return Err(Error::new(ErrorKind::InvalidType)
            .with_detail("separate_string_components content must be serial bytes"));
    }
    validate_numeric_stream_width(field_sizes.element_width, "string field sizes")?;
    let field_count = numeric_element_count(field_sizes.bytes, field_sizes.element_width)?;
    let (string_lengths, total) = decode_string_component_lengths(field_sizes, field_count)?;
    if total != content.bytes.len() {
        return Err(Error::new(ErrorKind::Malformed)
            .with_detail("string field sizes do not sum to content size"));
    }
    if content.bytes.len() > limits.max_decoded_bytes
        || content.bytes.len() > limits.max_buffer_bytes
    {
        return Err(
            Error::new(ErrorKind::LimitExceeded).with_detail("decoded output limit exceeded")
        );
    }
    let mut output = Vec::new();
    output.try_reserve_exact(content.bytes.len()).map_err(|_| {
        Error::new(ErrorKind::AllocationFailed).with_detail("string component allocation failed")
    })?;
    output.extend_from_slice(content.bytes);
    Ok(OwnedStream::strings(output, string_lengths))
}

pub(super) fn decode_string_component_lengths(
    field_sizes: &StreamInput<'_>,
    field_count: usize,
) -> Result<(Vec<u32>, usize)> {
    let mut string_lengths = Vec::new();
    string_lengths.try_reserve_exact(field_count).map_err(|_| {
        Error::new(ErrorKind::AllocationFailed).with_detail("string length allocation failed")
    })?;
    let mut total = 0usize;
    match field_sizes.element_width {
        1 => {
            fast_lengths::decode_u8_lengths(field_sizes.bytes, &mut string_lengths, &mut total)?;
        }
        2 => {
            for size in field_sizes.bytes.as_chunks::<2>().0 {
                let size = u16::from_le_bytes(*size);
                total = total
                    .checked_add(usize::from(size))
                    .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
                string_lengths.push(u32::from(size));
            }
        }
        4 => {
            for size in field_sizes.bytes.as_chunks::<4>().0 {
                let size = u32::from_le_bytes(*size);
                let size_usize = usize::try_from(size).map_err(|_| {
                    Error::new(ErrorKind::LimitExceeded)
                        .with_detail("string field size is too large")
                })?;
                total = total
                    .checked_add(size_usize)
                    .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
                string_lengths.push(size);
            }
        }
        8 => {
            for index in 0..field_count {
                let size = read_usize_numeric_element(
                    field_sizes.bytes,
                    field_sizes.element_width,
                    index,
                )?;
                total = total
                    .checked_add(size)
                    .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
                string_lengths.push(u32::try_from(size).map_err(|_| {
                    Error::new(ErrorKind::LimitExceeded)
                        .with_detail("string field size is too large")
                })?);
            }
        }
        _ => unreachable!("validate_numeric_stream_width accepted only supported widths"),
    }
    Ok((string_lengths, total))
}

pub(super) fn decode_prefix_node(
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

pub(super) fn decode_tokenize_string_node(
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

/// The string lengths of a byte-string input, after checking its element
/// width and that the lengths add up to its content. `details` describe
/// the three checks in that order: width, missing lengths, length sum.
fn byte_string_lengths<'a>(
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
