use alloc::{format, vec::Vec};

use ozlrip_core::{Error, ErrorKind, Limits, Result};

use super::{
    DecodeScratch, OwnedStream, StreamInput, numeric_element_count, read_usize_numeric_element,
    read_var_u64, require_numeric_width, validate_numeric_stream_width,
};
#[cfg(not(feature = "paranoid"))]
use super::{fast_field_lz, fast_lz};

pub(super) fn decode_lz_node(
    inputs: &[StreamInput<'_>],
    header: &[u8],
    limits: Limits,
) -> Result<Vec<u8>> {
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
    if output_len > limits.max_decoded_bytes || output_len > limits.max_buffer_bytes {
        return Err(
            Error::new(ErrorKind::LimitExceeded).with_detail("decoded output limit exceeded")
        );
    }
    let mut output = Vec::new();
    output
        .try_reserve_exact(output_len)
        .map_err(|_| Error::new(ErrorKind::LimitExceeded).with_detail("lz allocation failed"))?;

    let mut out_pos = 0usize;
    let mut lit_pos = 0usize;
    for sequence in 0..sequence_count {
        let literal_len = read_usize_numeric_element(
            literal_lengths.bytes,
            literal_lengths.element_width,
            sequence,
        )?;
        let match_offset =
            read_usize_numeric_element(offsets.bytes, offsets.element_width, sequence)?;
        let match_len =
            read_usize_numeric_element(match_lengths.bytes, match_lengths.element_width, sequence)?;

        let literal_end = lit_pos
            .checked_add(literal_len)
            .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
        let out_literal_end = out_pos
            .checked_add(literal_len)
            .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
        let literal_src = literals.bytes.get(lit_pos..literal_end).ok_or_else(|| {
            Error::new(ErrorKind::Malformed).with_detail("lz literal stream is too short")
        })?;
        if out_literal_end > output_len {
            return Err(Error::new(ErrorKind::Malformed)
                .with_detail("lz literal length exceeds output size"));
        }
        output.extend_from_slice(literal_src);
        lit_pos = literal_end;
        out_pos = out_literal_end;

        if match_offset == 0 {
            return Err(Error::new(ErrorKind::Malformed).with_detail("lz offset is zero"));
        }
        if match_offset > out_pos {
            return Err(
                Error::new(ErrorKind::Malformed).with_detail("lz offset exceeds decoded prefix")
            );
        }
        let out_match_end = out_pos
            .checked_add(match_len)
            .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
        if out_match_end > output_len {
            return Err(
                Error::new(ErrorKind::Malformed).with_detail("lz match length exceeds output size")
            );
        }
        append_lz_match(&mut output, out_pos, match_offset, match_len);
        out_pos = out_match_end;
    }

    let remaining_literals = literals.bytes.get(lit_pos..).ok_or_else(|| {
        Error::new(ErrorKind::Malformed).with_detail("lz literal stream is too short")
    })?;
    let out_end = out_pos
        .checked_add(remaining_literals.len())
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
    if out_end != output_len {
        return Err(
            Error::new(ErrorKind::Malformed).with_detail("lz output size does not match header")
        );
    }
    output.extend_from_slice(remaining_literals);
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
    if output_len > limits.max_decoded_bytes || output_len > limits.max_buffer_bytes {
        return Err(
            Error::new(ErrorKind::LimitExceeded).with_detail("decoded output limit exceeded")
        );
    }
    Ok((output_len, sequence_count))
}

pub(super) fn decode_lz_node_to_output(
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
                Error::new(ErrorKind::LimitExceeded).with_detail("lz allocation failed")
            })?;
    }

    if offsets.element_width == 1
        && literal_lengths.element_width == 2
        && match_lengths.element_width == 2
    {
        #[cfg(not(feature = "paranoid"))]
        return fast_lz::decode_u8_u16_u16_to_output(
            literals.bytes,
            offsets.bytes,
            literal_lengths.bytes,
            match_lengths.bytes,
            sequence_count,
            output_len,
            output,
            output_base,
        );
        #[cfg(feature = "paranoid")]
        return decode_lz_u8_u16_u16_to_output_safe(
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
    let mut out_pos = output_base;
    let mut lit_pos = 0usize;
    for sequence in 0..sequence_count {
        let literal_len = read_usize_numeric_element(
            literal_lengths.bytes,
            literal_lengths.element_width,
            sequence,
        )?;
        let match_offset =
            read_usize_numeric_element(offsets.bytes, offsets.element_width, sequence)?;
        let match_len =
            read_usize_numeric_element(match_lengths.bytes, match_lengths.element_width, sequence)?;

        let literal_end = lit_pos
            .checked_add(literal_len)
            .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
        let out_literal_end = out_pos
            .checked_add(literal_len)
            .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
        let literal_src = literals.bytes.get(lit_pos..literal_end).ok_or_else(|| {
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
        append_lz_match(output, out_pos, match_offset, match_len);
        out_pos = out_match_end;
    }

    let remaining_literals = literals.bytes.get(lit_pos..).ok_or_else(|| {
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

#[cfg(feature = "paranoid")]
#[expect(
    clippy::inline_always,
    reason = "paranoid LZ fallback keeps the safe copy loop visible to callers"
)]
#[expect(
    clippy::too_many_arguments,
    reason = "arguments are split stream slices from the validated LZ node shape"
)]
#[expect(
    clippy::needless_range_loop,
    reason = "sequence index addresses parallel byte streams with different widths"
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
    let mut out_pos = output_base;
    let mut lit_pos = 0usize;
    for sequence in 0..sequence_count {
        let length_offset = sequence * 2;
        let literal_len = usize::from(u16::from_le_bytes([
            literal_lengths[length_offset],
            literal_lengths[length_offset + 1],
        ]));
        let match_offset = usize::from(offsets[sequence]);
        let match_len = usize::from(u16::from_le_bytes([
            match_lengths[length_offset],
            match_lengths[length_offset + 1],
        ]));

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
        append_lz_match(output, out_pos, match_offset, match_len);
        out_pos = out_match_end;
    }

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
    let mut out_pos = output_base;
    let mut lit_pos = 0usize;
    for ((offset, literal_len), match_len) in offsets
        .chunks_exact(4)
        .zip(literal_lengths.chunks_exact(2))
        .zip(match_lengths.chunks_exact(2))
    {
        let literal_len = usize::from(u16::from_le_bytes([literal_len[0], literal_len[1]]));
        let match_offset = usize::try_from(u32::from_le_bytes([
            offset[0], offset[1], offset[2], offset[3],
        ]))
        .map_err(|_| {
            Error::new(ErrorKind::LimitExceeded).with_detail("numeric value is too large")
        })?;
        let match_len = usize::from(u16::from_le_bytes([match_len[0], match_len[1]]));

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
        append_lz_match(output, out_pos, match_offset, match_len);
        out_pos = out_match_end;
    }

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

fn append_lz_match(output: &mut Vec<u8>, out_pos: usize, match_offset: usize, match_len: usize) {
    if match_len == 0 {
        return;
    }
    debug_assert_eq!(output.len(), out_pos);
    let src_start = out_pos - match_offset;
    if match_len <= match_offset {
        #[cfg(not(feature = "paranoid"))]
        {
            fast_lz::append_nonoverlapping_match(output, src_start, match_len);
        }
        #[cfg(feature = "paranoid")]
        {
            output.extend_from_within(src_start..src_start + match_len);
        }
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

pub(super) fn decode_fastlz_deprecated_node(
    source: StreamInput<'_>,
    header: &[u8],
    limits: Limits,
) -> Result<Vec<u8>> {
    if !header.is_empty() {
        return Err(Error::new(ErrorKind::Unsupported)
            .with_detail("fastlz_deprecated headers are unsupported"));
    }
    let (decoded_size, payload) =
        parse_deprecated_lz_stored_stream(source, limits, "fastlz_deprecated")?;
    let literals = decode_fastlz_deprecated_literal_only_payload(payload)?;
    if literals.len() != decoded_size {
        return Err(Error::new(ErrorKind::Malformed)
            .with_detail("fastlz_deprecated output size does not match prefix"));
    }
    copy_deprecated_lz_literals(literals, "fastlz_deprecated")
}

pub(super) fn decode_rolz_deprecated_node(
    source: StreamInput<'_>,
    header: &[u8],
    limits: Limits,
) -> Result<Vec<u8>> {
    if !header.is_empty() {
        return Err(Error::new(ErrorKind::Unsupported)
            .with_detail("rolz_deprecated headers are unsupported"));
    }
    let (decoded_size, payload) =
        parse_deprecated_lz_stored_stream(source, limits, "rolz_deprecated")?;
    let literals = decode_rolz_deprecated_literal_only_payload(payload)?;
    if literals.len() != decoded_size {
        return Err(Error::new(ErrorKind::Malformed)
            .with_detail("rolz_deprecated output size does not match prefix"));
    }
    copy_deprecated_lz_literals(literals, "rolz_deprecated")
}

fn decode_fastlz_deprecated_literal_only_payload(payload: &[u8]) -> Result<&[u8]> {
    let mut offset = 0usize;
    let literals =
        parse_legacy_raw_entropy_slice(payload, &mut offset, 1, "fastlz_deprecated literals")?;
    let tokens =
        parse_legacy_raw_entropy_slice(payload, &mut offset, 2, "fastlz_deprecated tokens")?;
    if !tokens.is_empty() {
        return Err(Error::new(ErrorKind::Unsupported)
            .with_detail("fastlz_deprecated sequences are unsupported"));
    }
    read_zero_deprecated_lz_size(payload, &mut offset, "fastlz_deprecated offsets")?;
    read_zero_deprecated_lz_size(payload, &mut offset, "fastlz_deprecated extras")?;
    if offset != payload.len() {
        return Err(Error::new(ErrorKind::Malformed)
            .with_detail("fastlz_deprecated payload has trailing bytes"));
    }
    Ok(literals)
}

fn decode_rolz_deprecated_literal_only_payload(payload: &[u8]) -> Result<&[u8]> {
    let header = payload.get(..15).ok_or_else(|| {
        Error::new(ErrorKind::Truncated).with_detail("rolz_deprecated header is truncated")
    })?;
    if header[..7] != [2, 12, 4, 3, 1, 7, 3] {
        return Err(Error::new(ErrorKind::Unsupported)
            .with_detail("rolz_deprecated parameters are unsupported"));
    }
    let num_literals = u32::from_le_bytes([header[7], header[8], header[9], header[10]]) as usize;
    let num_sequences =
        u32::from_le_bytes([header[11], header[12], header[13], header[14]]) as usize;
    if num_sequences != 0 {
        return Err(Error::new(ErrorKind::Unsupported)
            .with_detail("rolz_deprecated sequences are unsupported"));
    }

    let mut offset = 15usize;
    let literals = if num_literals == 0 {
        &[][..]
    } else {
        let order = *payload.get(offset).ok_or_else(|| {
            Error::new(ErrorKind::Truncated)
                .with_detail("rolz_deprecated literal order flag is truncated")
        })?;
        offset = offset
            .checked_add(1)
            .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
        if order != 0 {
            return Err(Error::new(ErrorKind::Unsupported)
                .with_detail("rolz_deprecated order-1 literals are unsupported"));
        }
        parse_legacy_raw_entropy_slice(payload, &mut offset, 1, "rolz_deprecated literals")?
    };
    if literals.len() != num_literals {
        return Err(Error::new(ErrorKind::Malformed)
            .with_detail("rolz_deprecated literal count is invalid"));
    }

    let match_types =
        parse_legacy_raw_entropy_slice(payload, &mut offset, 1, "rolz_deprecated match types")?;
    if !match_types.is_empty() {
        return Err(Error::new(ErrorKind::Unsupported)
            .with_detail("rolz_deprecated match types are unsupported"));
    }
    if offset != payload.len() {
        return Err(Error::new(ErrorKind::Malformed)
            .with_detail("rolz_deprecated payload has trailing bytes"));
    }
    Ok(literals)
}

fn parse_deprecated_lz_stored_stream<'a>(
    source: StreamInput<'a>,
    limits: Limits,
    transform_name: &str,
) -> Result<(usize, &'a [u8])> {
    if source.element_width != 1 {
        return Err(Error::new(ErrorKind::InvalidType)
            .with_detail(format!("{transform_name} input must be serial")));
    }
    let size_prefix = source.bytes.get(..4).ok_or_else(|| {
        Error::new(ErrorKind::Truncated).with_detail("deprecated lz stream is missing size prefix")
    })?;
    let decoded_size = usize::try_from(u32::from_le_bytes([
        size_prefix[0],
        size_prefix[1],
        size_prefix[2],
        size_prefix[3],
    ]))
    .map_err(|_| {
        Error::new(ErrorKind::LimitExceeded).with_detail("deprecated lz output size is too large")
    })?;
    if decoded_size > limits.max_decoded_bytes || decoded_size > limits.max_buffer_bytes {
        return Err(
            Error::new(ErrorKind::LimitExceeded).with_detail("decoded output limit exceeded")
        );
    }
    Ok((decoded_size, &source.bytes[4..]))
}

fn parse_legacy_raw_entropy_slice<'a>(
    source: &'a [u8],
    offset: &mut usize,
    element_width: usize,
    transform_name: &str,
) -> Result<&'a [u8]> {
    let header = *source.get(*offset).ok_or_else(|| {
        Error::new(ErrorKind::Truncated)
            .with_detail(format!("{transform_name} entropy header is truncated"))
    })?;
    *offset = (*offset)
        .checked_add(1)
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
    match header & 0x07 {
        3 => {}
        6 | 7 => {
            return Err(Error::new(ErrorKind::Malformed)
                .with_detail(format!("{transform_name} entropy mode is reserved")));
        }
        _ => {
            return Err(Error::new(ErrorKind::Unsupported)
                .with_detail(format!("{transform_name} entropy mode is unsupported")));
        }
    }

    let decoded_elements = read_legacy_entropy_size(header, source, offset, transform_name)?;
    let output_len = decoded_elements
        .checked_mul(element_width)
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
    let end = (*offset)
        .checked_add(output_len)
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
    let payload = source
        .get(*offset..end)
        .ok_or_else(|| Error::new(ErrorKind::Truncated))?;
    *offset = end;
    Ok(payload)
}

fn read_legacy_entropy_size(
    header: u8,
    source: &[u8],
    offset: &mut usize,
    transform_name: &str,
) -> Result<usize> {
    let low = u64::from((header >> 3) & 0x0f);
    let high = if header & 0x80 == 0 {
        0
    } else {
        let high = read_var_u64(source, offset)?;
        if high > (u64::MAX >> 4) {
            return Err(Error::new(ErrorKind::IntegerOverflow));
        }
        high << 4
    };
    let decoded = low
        .checked_add(high)
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
    usize::try_from(decoded).map_err(|_| {
        Error::new(ErrorKind::LimitExceeded)
            .with_detail(format!("{transform_name} output size is too large"))
    })
}

fn read_zero_deprecated_lz_size(
    source: &[u8],
    offset: &mut usize,
    transform_name: &str,
) -> Result<()> {
    let size = read_var_u64(source, offset)?;
    if size != 0 {
        return Err(Error::new(ErrorKind::Malformed)
            .with_detail(format!("{transform_name} stream must be empty")));
    }
    Ok(())
}

fn copy_deprecated_lz_literals(literals: &[u8], transform_name: &str) -> Result<Vec<u8>> {
    let mut output = Vec::new();
    output.try_reserve_exact(literals.len()).map_err(|_| {
        Error::new(ErrorKind::LimitExceeded)
            .with_detail(format!("{transform_name} allocation failed"))
    })?;
    output.extend_from_slice(literals);
    Ok(output)
}

pub(super) fn decode_field_lz_node(
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
    if output_capacity > limits.max_decoded_bytes || output_capacity > limits.max_buffer_bytes {
        return Err(
            Error::new(ErrorKind::LimitExceeded).with_detail("decoded output limit exceeded")
        );
    }
    Ok(output_capacity)
}

pub(super) fn decode_field_lz_node_to_output(
    inputs: &[StreamInput<'_>],
    header: &[u8],
    limits: Limits,
    output: &mut Vec<u8>,
    output_base: usize,
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
    if output_capacity > limits.max_decoded_bytes || output_capacity > limits.max_buffer_bytes {
        return Err(
            Error::new(ErrorKind::LimitExceeded).with_detail("decoded output limit exceeded")
        );
    }
    let output_limit = output_base
        .checked_add(output_capacity)
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
    if output.capacity() < output_limit {
        output
            .try_reserve_exact(output_limit - output.len())
            .map_err(|_| {
                Error::new(ErrorKind::LimitExceeded).with_detail("field_lz allocation failed")
            })?;
    }

    #[cfg(not(feature = "paranoid"))]
    {
        fast_field_lz::decode_to_output(
            literals.bytes,
            tokens.bytes,
            offsets.bytes,
            extra_literal_lengths.bytes,
            extra_match_lengths.bytes,
            element_width,
            output_capacity,
            output,
            output_base,
        )?;
        Ok(element_width)
    }

    #[cfg(feature = "paranoid")]
    {
        let min_match = match element_width {
            1 => 4usize,
            2 => 2usize,
            _ => 1usize,
        };
        let mut reps = [element_width, element_width * 2, element_width * 4];
        let mut literal_pos = 0usize;
        let mut offset_values = offsets.bytes.chunks_exact(4);
        let mut extra_literal_values = extra_literal_lengths.bytes.chunks_exact(4);
        let mut extra_match_values = extra_match_lengths.bytes.chunks_exact(4);

        for token_bytes in tokens.bytes.chunks_exact(2) {
            let token = u16::from_le_bytes([token_bytes[0], token_bytes[1]]);
            let offset_code = usize::from(token & 0x3);
            let literal_code = usize::from((token >> 2) & 0x0f);
            let match_code = usize::from((token >> 6) & 0x0f);

            let match_offset = match offset_code {
                3 => {
                    let offset_bytes = offset_values.next().ok_or_else(|| {
                        Error::new(ErrorKind::Malformed).with_detail("numeric stream is exhausted")
                    })?;
                    let raw_offset = u32::from_le_bytes([
                        offset_bytes[0],
                        offset_bytes[1],
                        offset_bytes[2],
                        offset_bytes[3],
                    ]) as usize;
                    let byte_offset = raw_offset
                        .checked_mul(element_width)
                        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
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
            };

            let mut literal_elements = literal_code;
            if literal_code == 15 {
                let extra_bytes = extra_literal_values.next().ok_or_else(|| {
                    Error::new(ErrorKind::Malformed).with_detail("numeric stream is exhausted")
                })?;
                let extra = u32::from_le_bytes([
                    extra_bytes[0],
                    extra_bytes[1],
                    extra_bytes[2],
                    extra_bytes[3],
                ]) as usize;
                literal_elements = literal_elements
                    .checked_add(extra)
                    .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
            }
            let literal_len = literal_elements
                .checked_mul(element_width)
                .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;

            let mut match_elements = match_code
                .checked_add(min_match)
                .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
            if match_code == 15 {
                let extra_bytes = extra_match_values.next().ok_or_else(|| {
                    Error::new(ErrorKind::Malformed).with_detail("numeric stream is exhausted")
                })?;
                let extra = u32::from_le_bytes([
                    extra_bytes[0],
                    extra_bytes[1],
                    extra_bytes[2],
                    extra_bytes[3],
                ]) as usize;
                match_elements = match_elements
                    .checked_add(extra)
                    .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
            }
            let match_len = match_elements
                .checked_mul(element_width)
                .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;

            append_field_lz_literals(output, literals.bytes, &mut literal_pos, literal_len)?;
            append_field_lz_match(output, output_base, match_offset, match_len, output_limit)?;
        }

        let remaining_literals = literals.bytes.get(literal_pos..).ok_or_else(|| {
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

        if offset_values.len() != 0
            || extra_literal_values.len() != 0
            || extra_match_values.len() != 0
        {
            return Err(Error::new(ErrorKind::Malformed)
                .with_detail("field_lz numeric stream was not fully consumed"));
        }

        Ok(element_width)
    }
}

#[cfg(feature = "paranoid")]
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

#[cfg(feature = "paranoid")]
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
