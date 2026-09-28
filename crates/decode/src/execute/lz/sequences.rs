//! The `lz` node: a literal stream plus offset, literal length and match
//! length streams, one element per sequence.

use alloc::vec::Vec;

use ozlrip_core::{Error, ErrorKind, Limits, Result};

#[cfg(not(feature = "paranoid"))]
use super::fast_lz;
use crate::execute::elements::{
    numeric_element_count, read_usize_numeric_element, read_var_u64, validate_numeric_stream_width,
};
use crate::execute::output::check_output_len;
use crate::execute::streams::StreamInput;

pub(in crate::execute) fn decode_lz_node(
    inputs: &[StreamInput<'_>],
    header: &[u8],
    limits: Limits,
) -> Result<Vec<u8>> {
    let (output_len, sequence_count) = validate_lz_node(inputs, header, limits)?;
    let mut output = Vec::new();
    decode_lz_node_to_output_validated(inputs, sequence_count, output_len, &mut output, 0)?;
    Ok(output)
}

#[expect(
    clippy::inline_always,
    reason = "profiled LZ decode paths pay measurable validation call overhead"
)]
#[inline(always)]
fn validate_lz_node(
    inputs: &[StreamInput<'_>],
    header: &[u8],
    limits: Limits,
) -> Result<(usize, usize)> {
    let [literals, offsets, literal_lengths, match_lengths] = inputs else {
        return Err(Error::new(ErrorKind::InvalidGraph)
            .with_detail("lz input count does not match node shape"));
    };
    if literals.element_width != 1 {
        return Err(
            Error::new(ErrorKind::InvalidType).with_detail("lz literals must be serial bytes")
        );
    }
    validate_numeric_stream_width(offsets.element_width, "lz offsets")?;
    validate_numeric_stream_width(literal_lengths.element_width, "lz literal lengths")?;
    validate_numeric_stream_width(match_lengths.element_width, "lz match lengths")?;
    let sequence_count = numeric_element_count(offsets.bytes, offsets.element_width)?;
    if numeric_element_count(literal_lengths.bytes, literal_lengths.element_width)?
        != sequence_count
        || numeric_element_count(match_lengths.bytes, match_lengths.element_width)?
            != sequence_count
    {
        return Err(
            Error::new(ErrorKind::Malformed).with_detail("lz sequence stream counts do not match")
        );
    }

    let mut offset = 0usize;
    let output_len = read_var_u64(header, &mut offset)?;
    if offset != header.len() {
        return Err(Error::new(ErrorKind::Malformed).with_detail("lz header has trailing bytes"));
    }
    let output_len = usize::try_from(output_len).map_err(|_| {
        Error::new(ErrorKind::LimitExceeded).with_detail("lz output size is too large")
    })?;
    check_output_len(output_len, limits)?;
    Ok((output_len, sequence_count))
}

pub(in crate::execute) fn decode_lz_node_to_output(
    inputs: &[StreamInput<'_>],
    header: &[u8],
    limits: Limits,
    output: &mut Vec<u8>,
    output_base: usize,
) -> Result<()> {
    let (output_len, sequence_count) = validate_lz_node(inputs, header, limits)?;
    decode_lz_node_to_output_validated(inputs, sequence_count, output_len, output, output_base)
}

#[expect(
    clippy::inline_always,
    reason = "profiled LZ decode paths pay measurable dispatch call overhead"
)]
#[inline(always)]
fn decode_lz_node_to_output_validated(
    inputs: &[StreamInput<'_>],
    sequence_count: usize,
    output_len: usize,
    output: &mut Vec<u8>,
    output_base: usize,
) -> Result<()> {
    let [literals, offsets, literal_lengths, match_lengths] = inputs else {
        return Err(Error::new(ErrorKind::InvalidGraph)
            .with_detail("lz input count does not match node shape"));
    };
    let output_limit = output_base
        .checked_add(output_len)
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
    if output.capacity() < output_limit {
        output
            .try_reserve_exact(output_limit - output.len())
            .map_err(|_| {
                Error::new(ErrorKind::AllocationFailed).with_detail("lz allocation failed")
            })?;
    }

    if offsets.element_width == 1
        && literal_lengths.element_width == 2
        && match_lengths.element_width == 2
    {
        return decode_lz_u8_u16_u16_to_output(
            literals.bytes,
            offsets.bytes,
            literal_lengths.bytes,
            match_lengths.bytes,
            sequence_count,
            output_len,
            output,
            output_base,
        );
    }
    if offsets.element_width == 4
        && literal_lengths.element_width == 2
        && match_lengths.element_width == 2
    {
        return decode_lz_u32_u16_u16_to_output(
            literals.bytes,
            offsets.bytes,
            literal_lengths.bytes,
            match_lengths.bytes,
            sequence_count,
            output_len,
            output,
            output_base,
        );
    }

    decode_lz_node_to_output_generic(
        literals,
        offsets,
        literal_lengths,
        match_lengths,
        sequence_count,
        output_limit,
        output,
        output_base,
    )
}

/// The u8 offset, u16 length layout: the unchecked fast path, or its
/// checked twin under `paranoid`.
#[expect(
    clippy::inline_always,
    reason = "a thin cfg switch; the callee keeps its own inlining"
)]
#[expect(
    clippy::too_many_arguments,
    reason = "the LZ streams stay split, as the node hands them over"
)]
#[inline(always)]
fn decode_lz_u8_u16_u16_to_output(
    literals: &[u8],
    offsets: &[u8],
    literal_lengths: &[u8],
    match_lengths: &[u8],
    sequence_count: usize,
    output_len: usize,
    output: &mut Vec<u8>,
    output_base: usize,
) -> Result<()> {
    #[cfg(not(feature = "paranoid"))]
    return fast_lz::decode_u8_u16_u16_to_output(
        literals,
        offsets,
        literal_lengths,
        match_lengths,
        sequence_count,
        output_len,
        output,
        output_base,
    );
    #[cfg(feature = "paranoid")]
    return decode_lz_u8_u16_u16_to_output_safe(
        literals,
        offsets,
        literal_lengths,
        match_lengths,
        sequence_count,
        output_len,
        output,
        output_base,
    );
}

#[inline(never)]
#[expect(
    clippy::too_many_arguments,
    reason = "LZ fallback keeps validated stream arguments split to avoid packing overhead"
)]
fn decode_lz_node_to_output_generic(
    literals: &StreamInput<'_>,
    offsets: &StreamInput<'_>,
    literal_lengths: &StreamInput<'_>,
    match_lengths: &StreamInput<'_>,
    sequence_count: usize,
    output_limit: usize,
    output: &mut Vec<u8>,
    output_base: usize,
) -> Result<()> {
    let sequences = (0..sequence_count).map(|sequence| {
        let literal_len = read_usize_numeric_element(
            literal_lengths.bytes,
            literal_lengths.element_width,
            sequence,
        )?;
        let match_offset =
            read_usize_numeric_element(offsets.bytes, offsets.element_width, sequence)?;
        let match_len =
            read_usize_numeric_element(match_lengths.bytes, match_lengths.element_width, sequence)?;
        Ok(LzSequence {
            literal_len,
            match_offset,
            match_len,
        })
    });
    decode_lz_sequences(sequences, literals.bytes, output_limit, output, output_base)
}

#[cfg(feature = "paranoid")]
#[expect(
    clippy::inline_always,
    reason = "paranoid LZ fallback keeps the safe copy loop visible to callers"
)]
#[expect(
    clippy::too_many_arguments,
    reason = "arguments are split stream slices from the validated LZ node shape"
)]
#[inline(always)]
fn decode_lz_u8_u16_u16_to_output_safe(
    literals: &[u8],
    offsets: &[u8],
    literal_lengths: &[u8],
    match_lengths: &[u8],
    sequence_count: usize,
    output_len: usize,
    output: &mut Vec<u8>,
    output_base: usize,
) -> Result<()> {
    debug_assert_eq!(offsets.len(), sequence_count);
    debug_assert_eq!(literal_lengths.len(), sequence_count * 2);
    debug_assert_eq!(match_lengths.len(), sequence_count * 2);

    let output_limit = output_base
        .checked_add(output_len)
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
    let sequences = offsets
        .iter()
        .zip(literal_lengths.as_chunks::<2>().0)
        .zip(match_lengths.as_chunks::<2>().0)
        .map(|((&offset, literal_len), match_len)| {
            Ok(LzSequence {
                literal_len: usize::from(u16::from_le_bytes(*literal_len)),
                match_offset: usize::from(offset),
                match_len: usize::from(u16::from_le_bytes(*match_len)),
            })
        });
    decode_lz_sequences(sequences, literals, output_limit, output, output_base)
}

#[expect(
    clippy::inline_always,
    clippy::too_many_arguments,
    reason = "profiled LZ specialization keeps stream arguments split and inlined"
)]
#[inline(always)]
fn decode_lz_u32_u16_u16_to_output(
    literals: &[u8],
    offsets: &[u8],
    literal_lengths: &[u8],
    match_lengths: &[u8],
    sequence_count: usize,
    output_len: usize,
    output: &mut Vec<u8>,
    output_base: usize,
) -> Result<()> {
    debug_assert_eq!(offsets.len(), sequence_count * 4);
    debug_assert_eq!(literal_lengths.len(), sequence_count * 2);
    debug_assert_eq!(match_lengths.len(), sequence_count * 2);

    let output_limit = output_base
        .checked_add(output_len)
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
    let sequences = offsets
        .as_chunks::<4>()
        .0
        .iter()
        .zip(literal_lengths.as_chunks::<2>().0)
        .zip(match_lengths.as_chunks::<2>().0)
        .map(|((offset, literal_len), match_len)| {
            let match_offset = usize::try_from(u32::from_le_bytes(*offset)).map_err(|_| {
                Error::new(ErrorKind::LimitExceeded).with_detail("numeric value is too large")
            })?;
            Ok(LzSequence {
                literal_len: usize::from(u16::from_le_bytes(*literal_len)),
                match_offset,
                match_len: usize::from(u16::from_le_bytes(*match_len)),
            })
        });
    decode_lz_sequences(sequences, literals, output_limit, output, output_base)
}

struct LzSequence {
    literal_len: usize,
    match_offset: usize,
    match_len: usize,
}

/// The LZ sequence loop. `output` holds `output_base` bytes from before
/// this node; each sequence appends its literals and then its match, and
/// the literals left after the last sequence end the output at exactly
/// `output_limit`.
#[expect(
    clippy::inline_always,
    reason = "each LZ stream layout gets its own copy of the loop"
)]
#[inline(always)]
fn decode_lz_sequences(
    sequences: impl Iterator<Item = Result<LzSequence>>,
    literals: &[u8],
    output_limit: usize,
    output: &mut Vec<u8>,
    output_base: usize,
) -> Result<()> {
    // Matches are copied into spare capacity up to `output_limit`.
    #[cfg(not(feature = "paranoid"))]
    if output.len() != output_base || output.capacity() < output_limit {
        return Err(
            Error::new(ErrorKind::InvalidGraph).with_detail("lz output spare capacity is invalid")
        );
    }
    let mut out_pos = output_base;
    let mut lit_pos = 0usize;
    for sequence in sequences {
        let LzSequence {
            literal_len,
            match_offset,
            match_len,
        } = sequence?;

        let literal_end = lit_pos
            .checked_add(literal_len)
            .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
        let out_literal_end = out_pos
            .checked_add(literal_len)
            .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
        let literal_src = literals.get(lit_pos..literal_end).ok_or_else(|| {
            Error::new(ErrorKind::Malformed).with_detail("lz literal stream is too short")
        })?;
        if out_literal_end > output_limit {
            return Err(Error::new(ErrorKind::Malformed)
                .with_detail("lz literal length exceeds output size"));
        }
        output.extend_from_slice(literal_src);
        lit_pos = literal_end;
        out_pos = out_literal_end;

        if match_offset == 0 {
            return Err(Error::new(ErrorKind::Malformed).with_detail("lz offset is zero"));
        }
        if match_offset > out_pos - output_base {
            return Err(
                Error::new(ErrorKind::Malformed).with_detail("lz offset exceeds decoded prefix")
            );
        }
        let out_match_end = out_pos
            .checked_add(match_len)
            .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
        if out_match_end > output_limit {
            return Err(
                Error::new(ErrorKind::Malformed).with_detail("lz match length exceeds output size")
            );
        }
        #[cfg(not(feature = "paranoid"))]
        if match_len <= match_offset {
            // SAFETY: `output` holds `out_pos` bytes and has capacity
            // `output_limit`, checked before the loop. The source starts
            // `match_offset <= out_pos - output_base` bytes back and ends at or
            // before `out_pos`, and `out_match_end <= output_limit`.
            unsafe {
                fast_lz::append_nonoverlapping_match(output, out_pos - match_offset, match_len);
            }
        } else {
            append_lz_match(output, out_pos, match_offset, match_len);
        }
        #[cfg(feature = "paranoid")]
        append_lz_match(output, out_pos, match_offset, match_len);
        out_pos = out_match_end;
    }

    append_last_lz_literals(output, literals, lit_pos, out_pos, output_limit)
}

/// Appends the literals after the last sequence, which must end the output
/// at exactly `output_limit`.
#[expect(
    clippy::inline_always,
    reason = "runs once after the hot sequence loop it was split from"
)]
#[inline(always)]
fn append_last_lz_literals(
    output: &mut Vec<u8>,
    literals: &[u8],
    lit_pos: usize,
    out_pos: usize,
    output_limit: usize,
) -> Result<()> {
    let remaining_literals = literals.get(lit_pos..).ok_or_else(|| {
        Error::new(ErrorKind::Malformed).with_detail("lz literal stream is too short")
    })?;
    let out_end = out_pos
        .checked_add(remaining_literals.len())
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
    if out_end != output_limit {
        return Err(
            Error::new(ErrorKind::Malformed).with_detail("lz output size does not match header")
        );
    }
    output.extend_from_slice(remaining_literals);
    Ok(())
}

pub(super) fn append_lz_match(
    output: &mut Vec<u8>,
    out_pos: usize,
    match_offset: usize,
    match_len: usize,
) {
    if match_len == 0 {
        return;
    }
    debug_assert_eq!(output.len(), out_pos);
    let src_start = out_pos - match_offset;
    if match_len <= match_offset {
        output.extend_from_within(src_start..src_start + match_len);
        return;
    }

    output.extend_from_within(src_start..out_pos);
    let mut copied = match_offset;
    while copied < match_len {
        let len = copied.min(match_len - copied);
        output.extend_from_within(out_pos..out_pos + len);
        copied += len;
    }
}
