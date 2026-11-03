//! The `field_lz` node: LZ over fixed-width fields, with tokens, offsets
//! and extra lengths in their own streams.

use alloc::vec::Vec;

use ozlrip_core::{Error, ErrorKind, Limits, Result};

use crate::arith::{checked_add, checked_mul};
use crate::execute::elements::{read_var_u64, require_numeric_width};
use crate::execute::output::check_output_len;
use crate::execute::runtime::DecodeScratch;
use crate::execute::streams::{OwnedStream, StreamInput};

pub(in crate::execute) fn decode_field_lz_node(
    inputs: &[StreamInput<'_>],
    header: &[u8],
    limits: Limits,
    scratch: &mut DecodeScratch,
) -> Result<OwnedStream> {
    let output_capacity = field_lz_output_capacity(inputs, header, limits)?;
    let mut output = scratch.take_byte_buffer(output_capacity, "field_lz allocation failed")?;
    let element_width = decode_field_lz_node_to_output(inputs, header, limits, &mut output, 0)?;
    Ok(OwnedStream::pooled(output, element_width))
}

fn field_lz_output_capacity(
    inputs: &[StreamInput<'_>],
    header: &[u8],
    limits: Limits,
) -> Result<usize> {
    let [
        literals,
        tokens,
        offsets,
        extra_literal_lengths,
        extra_match_lengths,
    ] = inputs
    else {
        return Err(Error::new(ErrorKind::InvalidGraph)
            .with_detail("field_lz input count does not match node shape"));
    };
    let element_width = literals.element_width;
    if !matches!(element_width, 1 | 2 | 4 | 8) {
        return Err(
            Error::new(ErrorKind::InvalidType).with_detail("field_lz literal width is unsupported")
        );
    }
    require_numeric_width(tokens, 2, "field_lz tokens")?;
    require_numeric_width(offsets, 4, "field_lz offsets")?;
    require_numeric_width(extra_literal_lengths, 4, "field_lz extra literal lengths")?;
    require_numeric_width(extra_match_lengths, 4, "field_lz extra match lengths")?;

    let mut header_offset = 0usize;
    let output_elements = read_var_u64(header, &mut header_offset)?;
    if header_offset != header.len() {
        return Err(
            Error::new(ErrorKind::Malformed).with_detail("field_lz header has trailing bytes")
        );
    }
    let output_elements = usize::try_from(output_elements).map_err(|_| {
        Error::new(ErrorKind::LimitExceeded).with_detail("field_lz output size is too large")
    })?;
    let output_capacity = output_elements
        .checked_mul(element_width)
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
    check_output_len(output_capacity, limits)?;
    Ok(output_capacity)
}

pub(in crate::execute) fn decode_field_lz_node_to_output(
    inputs: &[StreamInput<'_>],
    header: &[u8],
    limits: Limits,
    output: &mut Vec<u8>,
    output_base: usize,
) -> Result<usize> {
    let output_capacity = field_lz_output_capacity(inputs, header, limits)?;
    let [
        literals,
        tokens,
        offsets,
        extra_literal_lengths,
        extra_match_lengths,
    ] = inputs
    else {
        return Err(Error::new(ErrorKind::InvalidGraph)
            .with_detail("field_lz input count does not match node shape"));
    };
    let element_width = literals.element_width;
    let output_limit = output_base
        .checked_add(output_capacity)
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
    if output.capacity() < output_limit {
        output
            .try_reserve_exact(output_limit - output.len())
            .map_err(|_| {
                Error::new(ErrorKind::AllocationFailed).with_detail("field_lz allocation failed")
            })?;
    }

    let mut sequences = FieldLzSequences::new(
        offsets.bytes,
        extra_literal_lengths.bytes,
        extra_match_lengths.bytes,
        element_width,
    );
    decode_field_lz_tokens(
        literals.bytes,
        tokens.bytes,
        &mut sequences,
        output_limit,
        output,
        output_base,
    )?;
    Ok(element_width)
}

/// Decodes field-LZ tokens with checked appends.
fn decode_field_lz_tokens(
    literals: &[u8],
    tokens: &[u8],
    sequences: &mut FieldLzSequences<'_>,
    output_limit: usize,
    output: &mut Vec<u8>,
    output_base: usize,
) -> Result<()> {
    let mut literal_pos = 0usize;
    for token_bytes in tokens.as_chunks::<2>().0 {
        let (match_offset, literal_len, match_len) =
            sequences.next(u16::from_le_bytes(*token_bytes))?;
        append_field_lz_literals(output, literals, &mut literal_pos, literal_len)?;
        append_field_lz_match(output, output_base, match_offset, match_len, output_limit)?;
    }

    let remaining_literals = literals.get(literal_pos..).ok_or_else(|| {
        Error::new(ErrorKind::Malformed).with_detail("field_lz literal stream is too short")
    })?;
    let final_len = output
        .len()
        .checked_add(remaining_literals.len())
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
    if final_len > output_limit {
        return Err(Error::new(ErrorKind::Malformed)
            .with_detail("field_lz output size exceeds header capacity"));
    }
    output.extend_from_slice(remaining_literals);
    sequences.finish()
}

/// Turns field-LZ tokens into byte offsets and lengths, reading the offset
/// and extra length streams and keeping the three repeat offsets.
struct FieldLzSequences<'a> {
    reps: [usize; 3],
    offsets: core::slice::Iter<'a, [u8; 4]>,
    extra_literal_lengths: core::slice::Iter<'a, [u8; 4]>,
    extra_match_lengths: core::slice::Iter<'a, [u8; 4]>,
    element_width: usize,
    min_match: usize,
}

impl<'a> FieldLzSequences<'a> {
    fn new(
        offsets: &'a [u8],
        extra_literal_lengths: &'a [u8],
        extra_match_lengths: &'a [u8],
        element_width: usize,
    ) -> Self {
        let min_match = match element_width {
            1 => 4usize,
            2 => 2usize,
            _ => 1usize,
        };
        Self {
            reps: [element_width, element_width * 2, element_width * 4],
            offsets: offsets.as_chunks::<4>().0.iter(),
            extra_literal_lengths: extra_literal_lengths.as_chunks::<4>().0.iter(),
            extra_match_lengths: extra_match_lengths.as_chunks::<4>().0.iter(),
            element_width,
            min_match,
        }
    }

    /// The match offset, literal length and match length of one token, in
    /// bytes.
    fn next(&mut self, token: u16) -> Result<(usize, usize, usize)> {
        let match_offset = self.match_offset(usize::from(token & 0x3))?;
        let literal_code = usize::from((token >> 2) & 0x0f);
        let literal_elements = if literal_code == 15 {
            checked_add(literal_code, next_u32(&mut self.extra_literal_lengths)?)?
        } else {
            literal_code
        };
        let literal_len = checked_mul(literal_elements, self.element_width)?;
        let match_code = usize::from((token >> 6) & 0x0f);
        let mut match_elements = checked_add(match_code, self.min_match)?;
        if match_code == 15 {
            match_elements = checked_add(match_elements, next_u32(&mut self.extra_match_lengths)?)?;
        }
        let match_len = checked_mul(match_elements, self.element_width)?;
        Ok((match_offset, literal_len, match_len))
    }

    fn match_offset(&mut self, offset_code: usize) -> Result<usize> {
        let reps = &mut self.reps;
        Ok(match offset_code {
            3 => {
                let raw_offset = next_u32(&mut self.offsets)?;
                let byte_offset = checked_mul(raw_offset, self.element_width)?;
                reps[2] = reps[1];
                reps[1] = reps[0];
                reps[0] = byte_offset;
                byte_offset
            }
            0 => reps[0],
            1 => {
                let byte_offset = reps[1];
                reps.swap(1, 0);
                byte_offset
            }
            2 => {
                let byte_offset = reps[2];
                reps[2] = reps[1];
                reps[1] = reps[0];
                reps[0] = byte_offset;
                byte_offset
            }
            _ => unreachable!("offset code is masked to two bits"),
        })
    }

    fn finish(&self) -> Result<()> {
        if self.offsets.len() != 0
            || self.extra_literal_lengths.len() != 0
            || self.extra_match_lengths.len() != 0
        {
            return Err(Error::new(ErrorKind::Malformed)
                .with_detail("field_lz numeric stream was not fully consumed"));
        }
        Ok(())
    }
}

fn next_u32(values: &mut core::slice::Iter<'_, [u8; 4]>) -> Result<usize> {
    let bytes = values.next().ok_or_else(|| {
        Error::new(ErrorKind::Malformed).with_detail("numeric stream is exhausted")
    })?;
    Ok(u32::from_le_bytes(*bytes) as usize)
}

#[expect(
    clippy::inline_always,
    reason = "profiled field-LZ token loop pays measurable append call overhead"
)]
#[inline(always)]
fn append_field_lz_literals(
    output: &mut Vec<u8>,
    literals: &[u8],
    literal_pos: &mut usize,
    literal_len: usize,
) -> Result<()> {
    let literal_end = literal_pos
        .checked_add(literal_len)
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
    let src = literals.get(*literal_pos..literal_end).ok_or_else(|| {
        Error::new(ErrorKind::Malformed).with_detail("field_lz literal stream is too short")
    })?;
    output.extend_from_slice(src);
    *literal_pos = literal_end;
    Ok(())
}

#[expect(
    clippy::inline_always,
    reason = "profiled field-LZ token loop pays measurable match append call overhead"
)]
#[inline(always)]
fn append_field_lz_match(
    output: &mut Vec<u8>,
    output_base: usize,
    match_offset: usize,
    match_len: usize,
    output_limit: usize,
) -> Result<()> {
    if match_offset == 0 {
        return Err(Error::new(ErrorKind::Malformed).with_detail("field_lz offset is zero"));
    }
    let chunk_len = output
        .len()
        .checked_sub(output_base)
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
    if match_offset > chunk_len {
        return Err(
            Error::new(ErrorKind::Malformed).with_detail("field_lz offset exceeds decoded prefix")
        );
    }
    let end = output
        .len()
        .checked_add(match_len)
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
    if end > output_limit {
        return Err(Error::new(ErrorKind::Malformed)
            .with_detail("field_lz match length exceeds output size"));
    }
    let start = output.len();
    let src_start = start - match_offset;
    if match_len <= match_offset {
        output.extend_from_within(src_start..src_start + match_len);
        return Ok(());
    }

    output.extend_from_within(src_start..start);
    let mut copied = match_offset;
    while copied < match_len {
        let len = copied.min(match_len - copied);
        output.extend_from_within(start..start + len);
        copied += len;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use ozlrip_core::Result;

    use super::{FieldLzSequences, decode_field_lz_tokens};

    #[expect(clippy::too_many_arguments, reason = "mirrors the field_lz streams")]
    fn decode_to_output(
        literals: &[u8],
        tokens: &[u8],
        offsets: &[u8],
        extra_literal_lengths: &[u8],
        extra_match_lengths: &[u8],
        element_width: usize,
        output_capacity: usize,
        output: &mut Vec<u8>,
        output_base: usize,
    ) -> Result<()> {
        let mut sequences = FieldLzSequences::new(
            offsets,
            extra_literal_lengths,
            extra_match_lengths,
            element_width,
        );
        decode_field_lz_tokens(
            literals,
            tokens,
            &mut sequences,
            output_base + output_capacity,
            output,
            output_base,
        )
    }

    #[test]
    fn decodes_overlapping_explicit_offset_match() {
        let mut output = Vec::with_capacity(16);
        let token = 3 | (4 << 2) | (4 << 6);

        decode_to_output(
            b"abcdWXYZ",
            &u16::to_le_bytes(token),
            &u32::to_le_bytes(4),
            &[],
            &[],
            1,
            16,
            &mut output,
            0,
        )
        .unwrap();

        assert_eq!(output, b"abcdabcdabcdWXYZ");
    }

    #[test]
    fn decodes_long_overlapping_repeat() {
        let mut output = Vec::with_capacity(1024);
        let token = 3 | (15 << 2) | (15 << 6);

        decode_to_output(
            b"0123456789abcdef!",
            &u16::to_le_bytes(token),
            &u32::to_le_bytes(16),
            &u32::to_le_bytes(1),
            &u32::to_le_bytes(476),
            1,
            512,
            &mut output,
            0,
        )
        .unwrap();

        assert_eq!(&output[..16], b"0123456789abcdef");
        assert_eq!(output[16..511], b"0123456789abcdef".repeat(31)[..495]);
        assert_eq!(output[511], b'!');
    }

    #[test]
    fn decodes_with_nonzero_output_base() {
        let mut output = Vec::from(&b"pre"[..]);
        output.reserve_exact(8);
        let token = 3 | (3 << 2);

        decode_to_output(
            b"abcz",
            &u16::to_le_bytes(token),
            &u32::to_le_bytes(3),
            &[],
            &[],
            1,
            8,
            &mut output,
            3,
        )
        .unwrap();

        assert_eq!(output, b"preabcabcaz");
    }

    #[test]
    fn rejects_extra_numeric_values() {
        let mut output = Vec::with_capacity(8);
        let token = 3 | (4 << 2);

        let err = decode_to_output(
            b"abcd",
            &u16::to_le_bytes(token),
            &[4, 0, 0, 0, 7, 0, 0, 0],
            &[],
            &[],
            1,
            8,
            &mut output,
            0,
        )
        .unwrap_err();

        assert_eq!(err.kind(), ozlrip_core::ErrorKind::Malformed);
    }
}
