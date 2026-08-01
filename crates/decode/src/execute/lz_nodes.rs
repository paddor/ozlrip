use alloc::{format, vec::Vec};

use ozlrip_core::{Error, ErrorKind, Limits, Result};
use zrip_core::bitstream::reader_reverse::ReverseBitReader;

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

#[derive(Clone, Copy)]
enum LegacyLiteralPayload<'a> {
    Raw(&'a [u8]),
    Constant {
        value: &'a [u8],
        decoded_elements: usize,
        element_width: usize,
    },
}

impl LegacyLiteralPayload<'_> {
    fn byte_len(&self) -> Result<usize> {
        match self {
            Self::Raw(bytes) => Ok(bytes.len()),
            Self::Constant {
                decoded_elements,
                element_width,
                ..
            } => legacy_entropy_output_len(*decoded_elements, *element_width),
        }
    }
}

struct LegacyLiteralCursor<'a> {
    payload: LegacyLiteralPayload<'a>,
    offset: usize,
}

impl<'a> LegacyLiteralCursor<'a> {
    const fn new(payload: LegacyLiteralPayload<'a>) -> Self {
        Self { payload, offset: 0 }
    }

    fn remaining_len(&self) -> Result<usize> {
        self.payload
            .byte_len()?
            .checked_sub(self.offset)
            .ok_or_else(|| {
                Error::new(ErrorKind::Malformed)
                    .with_detail("fastlz_deprecated literal stream is too short")
            })
    }

    fn extend_next(&mut self, len: usize, output: &mut Vec<u8>) -> Result<()> {
        let end = self
            .offset
            .checked_add(len)
            .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
        if end > self.payload.byte_len()? {
            return Err(Error::new(ErrorKind::Malformed)
                .with_detail("fastlz_deprecated literal stream is too short"));
        }
        match self.payload {
            LegacyLiteralPayload::Raw(bytes) => {
                let chunk = bytes.get(self.offset..end).ok_or_else(|| {
                    Error::new(ErrorKind::Malformed)
                        .with_detail("fastlz_deprecated literal stream is too short")
                })?;
                output.extend_from_slice(chunk);
            }
            LegacyLiteralPayload::Constant {
                value,
                element_width,
                ..
            } => {
                if !self.offset.is_multiple_of(element_width) || !len.is_multiple_of(element_width)
                {
                    return Err(Error::new(ErrorKind::Malformed)
                        .with_detail("deprecated lz constant literal range is misaligned"));
                }
                let elements = len / element_width;
                for _ in 0..elements {
                    output.extend_from_slice(value);
                }
            }
        }
        self.offset = end;
        Ok(())
    }

    fn extend_remaining(&mut self, output: &mut Vec<u8>) -> Result<()> {
        let len = self.remaining_len()?;
        self.extend_next(len, output)
    }
}

struct FastLzDeprecatedPayload<'a> {
    literals: LegacyLiteralPayload<'a>,
    tokens: &'a [u8],
    offsets: &'a [u8],
    extras: &'a [u8],
}

const FASTLZ_DEPRECATED_MIN_OFFSET: usize = 16;

#[derive(Clone, Copy)]
struct RolzDeprecatedParams {
    context_depth: usize,
    context_log: usize,
    row_log: usize,
    min_length: usize,
    predict_match_length: bool,
    lz_min_length: usize,
    rep_min_length: usize,
}

struct RolzDeprecatedPayload<'a> {
    params: RolzDeprecatedParams,
    literals: RolzDeprecatedLiterals<'a>,
    match_types: Vec<u8>,
    literal_lengths: Vec<usize>,
    match_lengths: Vec<usize>,
    match_codes: Vec<usize>,
}

enum RolzDeprecatedLiterals<'a> {
    Linear(LegacyLiteralPayload<'a>),
    O1(RolzDeprecatedO1Literals<'a>),
}

struct RolzDeprecatedO1Literals<'a> {
    max_context: u8,
    context_to_cluster: [u8; 256],
    clusters: Vec<LegacyLiteralPayload<'a>>,
    total_len: usize,
}

enum RolzDeprecatedLiteralCursor<'a> {
    Linear(LegacyLiteralCursor<'a>),
    O1 {
        payload: RolzDeprecatedO1Literals<'a>,
        cluster_offsets: [usize; 256],
        consumed: usize,
    },
}

#[derive(Clone, Copy, Default)]
struct RolzDeprecatedTableEntry {
    index: usize,
    predicted_match_length: u8,
}

struct RolzDeprecatedTable {
    heads: Vec<usize>,
    entries: Vec<RolzDeprecatedTableEntry>,
    row_log: usize,
    row_mask: usize,
}

const ROLZ_DEPRECATED_PARAMS: RolzDeprecatedParams = RolzDeprecatedParams {
    context_depth: 2,
    context_log: 12,
    row_log: 4,
    min_length: 3,
    predict_match_length: true,
    lz_min_length: 7,
    rep_min_length: 3,
};
const ROLZ_DEPRECATED_HEADER_LEN: usize = 15;
const ROLZ_DEPRECATED_MARKOV_STATES: usize = 6;
const ROLZ_DEPRECATED_INITIAL_REPS: [usize; 3] = [1, 4, 8];
const ROLZ_DEPRECATED_REP_SUB: usize = 4;
const ROLZ_DEPRECATED_MATCH_TYPE_LZ: u8 = 0;
const ROLZ_DEPRECATED_MATCH_TYPE_ROLZ: u8 = 1;
const ROLZ_DEPRECATED_MATCH_TYPE_REP0: u8 = 2;
const ROLZ_DEPRECATED_MATCH_TYPE_REP: u8 = 3;
const ROLZ_DEPRECATED_VALUE_BASE: [usize; 59] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
    26, 27, 28, 29, 30, 31, 0x20, 0x40, 0x80, 0x100, 0x200, 0x400, 0x800, 0x1000, 0x2000, 0x4000,
    0x8000, 0x10000, 0x20000, 0x40000, 0x80000, 0x100000, 0x200000, 0x400000, 0x800000, 0x1000000,
    0x2000000, 0x4000000, 0x8000000, 0x10000000, 0x20000000, 0x40000000, 0x80000000,
];
const ROLZ_DEPRECATED_VALUE_BITS: [u8; 59] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29,
    30, 31,
];

impl RolzDeprecatedTable {
    fn new(params: RolzDeprecatedParams, limits: Limits) -> Result<Self> {
        let contexts = 1usize
            .checked_shl(u32::try_from(params.context_log).map_err(|_| {
                Error::new(ErrorKind::LimitExceeded)
                    .with_detail("rolz_deprecated context log is too large")
            })?)
            .ok_or_else(|| {
                Error::new(ErrorKind::LimitExceeded)
                    .with_detail("rolz_deprecated context table is too large")
            })?;
        let row_size = 1usize
            .checked_shl(u32::try_from(params.row_log).map_err(|_| {
                Error::new(ErrorKind::LimitExceeded)
                    .with_detail("rolz_deprecated row log is too large")
            })?)
            .ok_or_else(|| {
                Error::new(ErrorKind::LimitExceeded)
                    .with_detail("rolz_deprecated row table is too large")
            })?;
        let entries_len = contexts
            .checked_mul(row_size)
            .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
        let entry_limit = limits
            .max_buffer_bytes
            .checked_div(core::mem::size_of::<RolzDeprecatedTableEntry>().max(1))
            .unwrap_or(0);
        if entries_len > entry_limit {
            return Err(Error::new(ErrorKind::LimitExceeded)
                .with_detail("rolz_deprecated table exceeds buffer limit"));
        }

        let mut heads = Vec::new();
        heads.try_reserve_exact(contexts).map_err(|_| {
            Error::new(ErrorKind::LimitExceeded)
                .with_detail("rolz_deprecated head table allocation failed")
        })?;
        heads.resize(contexts, 0);
        let mut entries = Vec::new();
        entries.try_reserve_exact(entries_len).map_err(|_| {
            Error::new(ErrorKind::LimitExceeded)
                .with_detail("rolz_deprecated table allocation failed")
        })?;
        entries.resize(entries_len, RolzDeprecatedTableEntry::default());
        Ok(Self {
            heads,
            entries,
            row_log: params.row_log,
            row_mask: row_size - 1,
        })
    }

    fn get(
        &self,
        context: usize,
        index: usize,
        encoded_match_length: usize,
        params: RolzDeprecatedParams,
    ) -> Result<(usize, usize)> {
        if index > self.row_mask {
            return Err(Error::new(ErrorKind::Malformed)
                .with_detail("rolz_deprecated match code is invalid"));
        }
        let row_start = context
            .checked_shl(u32::try_from(self.row_log).map_err(|_| {
                Error::new(ErrorKind::LimitExceeded)
                    .with_detail("rolz_deprecated row log is too large")
            })?)
            .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
        let head = *self
            .heads
            .get(context)
            .ok_or_else(|| Error::new(ErrorKind::Malformed))?;
        let pos = row_start
            .checked_add((head + index) & self.row_mask)
            .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
        let entry = *self.entries.get(pos).ok_or_else(|| {
            Error::new(ErrorKind::Malformed).with_detail("rolz_deprecated table index is invalid")
        })?;
        if entry.index == 0 {
            return Err(Error::new(ErrorKind::Malformed)
                .with_detail("rolz_deprecated match index is invalid"));
        }
        let match_length = rolz_deprecated_decode_match_length(
            params.min_length,
            usize::from(entry.predicted_match_length),
            encoded_match_length,
        )?;
        Ok((entry.index - 1, match_length))
    }

    fn put(&mut self, context: usize, index: usize, match_length: usize) -> Result<()> {
        let head = self
            .heads
            .get_mut(context)
            .ok_or_else(|| Error::new(ErrorKind::Malformed))?;
        let pos_in_row = head.wrapping_sub(1) & self.row_mask;
        *head = pos_in_row;
        let row_start = context
            .checked_shl(u32::try_from(self.row_log).map_err(|_| {
                Error::new(ErrorKind::LimitExceeded)
                    .with_detail("rolz_deprecated row log is too large")
            })?)
            .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
        let pos = row_start
            .checked_add(pos_in_row)
            .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
        let entry = self.entries.get_mut(pos).ok_or_else(|| {
            Error::new(ErrorKind::Malformed).with_detail("rolz_deprecated table index is invalid")
        })?;
        entry.index = index;
        entry.predicted_match_length = u8::try_from(match_length.min(usize::from(u8::MAX)))
            .map_err(|_| Error::new(ErrorKind::IntegerOverflow))?;
        Ok(())
    }
}

impl RolzDeprecatedLiterals<'_> {
    fn byte_len(&self) -> Result<usize> {
        match self {
            Self::Linear(payload) => payload.byte_len(),
            Self::O1(payload) => Ok(payload.total_len),
        }
    }
}

impl<'a> RolzDeprecatedLiteralCursor<'a> {
    fn new(payload: RolzDeprecatedLiterals<'a>) -> Self {
        match payload {
            RolzDeprecatedLiterals::Linear(payload) => {
                Self::Linear(LegacyLiteralCursor::new(payload))
            }
            RolzDeprecatedLiterals::O1(payload) => Self::O1 {
                payload,
                cluster_offsets: [0; 256],
                consumed: 0,
            },
        }
    }

    fn remaining_len(&self) -> Result<usize> {
        match self {
            Self::Linear(cursor) => cursor.remaining_len(),
            Self::O1 {
                payload, consumed, ..
            } => payload.total_len.checked_sub(*consumed).ok_or_else(|| {
                Error::new(ErrorKind::Malformed)
                    .with_detail("rolz_deprecated literal stream is too short")
            }),
        }
    }

    fn extend_next(&mut self, len: usize, output: &mut Vec<u8>) -> Result<()> {
        match self {
            Self::Linear(cursor) => cursor.extend_next(len, output),
            Self::O1 {
                payload,
                cluster_offsets,
                consumed,
            } => {
                let end = consumed
                    .checked_add(len)
                    .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
                if end > payload.total_len {
                    return Err(Error::new(ErrorKind::Malformed)
                        .with_detail("rolz_deprecated literal stream is too short"));
                }

                let mut context = output.last().copied().unwrap_or(0);
                for _ in 0..len {
                    if context > payload.max_context {
                        return Err(Error::new(ErrorKind::Malformed)
                            .with_detail("rolz_deprecated literal context is invalid"));
                    }
                    let cluster = usize::from(payload.context_to_cluster[usize::from(context)]);
                    let cluster_payload = payload.clusters.get(cluster).ok_or_else(|| {
                        Error::new(ErrorKind::Malformed)
                            .with_detail("rolz_deprecated literal cluster is invalid")
                    })?;
                    let cluster_offset = cluster_offsets.get_mut(cluster).ok_or_else(|| {
                        Error::new(ErrorKind::Malformed)
                            .with_detail("rolz_deprecated literal cluster is invalid")
                    })?;
                    context = read_legacy_literal_byte(
                        cluster_payload,
                        *cluster_offset,
                        "rolz_deprecated literals",
                    )?;
                    *cluster_offset = (*cluster_offset)
                        .checked_add(1)
                        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
                    *consumed = (*consumed)
                        .checked_add(1)
                        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
                    output.push(context);
                }
                Ok(())
            }
        }
    }

    fn extend_remaining(&mut self, output: &mut Vec<u8>) -> Result<()> {
        let len = self.remaining_len()?;
        self.extend_next(len, output)
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
    let payload = parse_fastlz_deprecated_payload(payload)?;
    decode_fastlz_deprecated_payload(payload, decoded_size)
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
    let payload = parse_rolz_deprecated_payload(payload, limits)?;
    decode_rolz_deprecated_payload(payload, decoded_size, limits)
}

fn parse_fastlz_deprecated_payload(payload: &[u8]) -> Result<FastLzDeprecatedPayload<'_>> {
    let mut offset = 0usize;
    let literals = parse_legacy_literal_entropy_payload(
        payload,
        &mut offset,
        1,
        "fastlz_deprecated literals",
    )?;
    let tokens =
        parse_legacy_raw_entropy_slice(payload, &mut offset, 2, "fastlz_deprecated tokens")?;
    let offsets =
        read_deprecated_lz_sized_slice(payload, &mut offset, "fastlz_deprecated offsets")?;
    let extras = read_deprecated_lz_sized_slice(payload, &mut offset, "fastlz_deprecated extras")?;
    if offset != payload.len() {
        return Err(Error::new(ErrorKind::Malformed)
            .with_detail("fastlz_deprecated payload has trailing bytes"));
    }
    Ok(FastLzDeprecatedPayload {
        literals,
        tokens,
        offsets,
        extras,
    })
}

fn decode_fastlz_deprecated_payload(
    payload: FastLzDeprecatedPayload<'_>,
    decoded_size: usize,
) -> Result<Vec<u8>> {
    let mut output = Vec::new();
    output.try_reserve_exact(decoded_size).map_err(|_| {
        Error::new(ErrorKind::LimitExceeded).with_detail("fastlz_deprecated allocation failed")
    })?;
    let mut literals = LegacyLiteralCursor::new(payload.literals);
    let mut offsets_pos = 0usize;
    let mut extras_pos = 0usize;
    let mut rep = FASTLZ_DEPRECATED_MIN_OFFSET;

    for (index, token) in payload.tokens.chunks_exact(2).enumerate() {
        let token = u16::from_le_bytes([token[0], token[1]]);
        if index == 0 && token == 60 {
            append_fastlz_deprecated_literals(
                &mut literals,
                &mut output,
                usize::from((token >> 2) & 0x0f),
                decoded_size,
            )?;
            continue;
        }

        let offset = read_fastlz_deprecated_offset(
            token & 0x03,
            payload.offsets,
            &mut offsets_pos,
            &mut rep,
        )?;
        let (literal_len, match_len) = if token & !0x03 == 0 {
            (
                read_fastlz_deprecated_extra(payload.extras, &mut extras_pos)?,
                read_fastlz_deprecated_extra(payload.extras, &mut extras_pos)?,
            )
        } else {
            (
                usize::from((token >> 2) & 0x0f),
                usize::from((token >> 6) & 0x1f),
            )
        };
        append_fastlz_deprecated_literals(&mut literals, &mut output, literal_len, decoded_size)?;
        if offset < FASTLZ_DEPRECATED_MIN_OFFSET {
            return Err(Error::new(ErrorKind::Malformed)
                .with_detail("fastlz_deprecated offset is too small"));
        }
        if offset > output.len() {
            return Err(Error::new(ErrorKind::Malformed)
                .with_detail("fastlz_deprecated offset exceeds decoded prefix"));
        }
        let match_end = output
            .len()
            .checked_add(match_len)
            .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
        if match_end > decoded_size {
            return Err(Error::new(ErrorKind::Malformed)
                .with_detail("fastlz_deprecated match length exceeds output size"));
        }
        let out_pos = output.len();
        append_lz_match(&mut output, out_pos, offset, match_len);
    }

    if offsets_pos != payload.offsets.len() || extras_pos != payload.extras.len() {
        return Err(Error::new(ErrorKind::Malformed)
            .with_detail("fastlz_deprecated auxiliary stream was not fully consumed"));
    }
    let remaining_literals = literals.remaining_len()?;
    let output_end = output
        .len()
        .checked_add(remaining_literals)
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
    if output_end != decoded_size {
        return Err(Error::new(ErrorKind::Malformed)
            .with_detail("fastlz_deprecated output size does not match prefix"));
    }
    literals.extend_remaining(&mut output)?;
    Ok(output)
}

fn append_fastlz_deprecated_literals(
    literals: &mut LegacyLiteralCursor<'_>,
    output: &mut Vec<u8>,
    len: usize,
    decoded_size: usize,
) -> Result<()> {
    let output_end = output
        .len()
        .checked_add(len)
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
    if output_end > decoded_size {
        return Err(Error::new(ErrorKind::Malformed)
            .with_detail("fastlz_deprecated literal length exceeds output size"));
    }
    literals.extend_next(len, output)
}

fn read_fastlz_deprecated_offset(
    code: u16,
    offsets: &[u8],
    offsets_pos: &mut usize,
    rep: &mut usize,
) -> Result<usize> {
    let offset = match code {
        0 => *rep,
        1 => {
            let offset = usize::from(*offsets.get(*offsets_pos).ok_or_else(|| {
                Error::new(ErrorKind::Malformed)
                    .with_detail("fastlz_deprecated offsets stream is exhausted")
            })?);
            *offsets_pos = (*offsets_pos)
                .checked_add(1)
                .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
            *rep = offset;
            offset
        }
        2 => {
            let end = (*offsets_pos)
                .checked_add(2)
                .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
            let offset = offsets.get(*offsets_pos..end).ok_or_else(|| {
                Error::new(ErrorKind::Malformed)
                    .with_detail("fastlz_deprecated offsets stream is exhausted")
            })?;
            let offset = usize::from(u16::from_le_bytes([offset[0], offset[1]]));
            *offsets_pos = end;
            *rep = offset;
            offset
        }
        3 => {
            let end = (*offsets_pos)
                .checked_add(3)
                .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
            let offset = offsets.get(*offsets_pos..end).ok_or_else(|| {
                Error::new(ErrorKind::Malformed)
                    .with_detail("fastlz_deprecated offsets stream is exhausted")
            })?;
            let offset = usize::from(offset[0])
                | (usize::from(offset[1]) << 8)
                | (usize::from(offset[2]) << 16);
            *offsets_pos = end;
            *rep = offset;
            offset
        }
        _ => unreachable!("fastlz offset code is masked to two bits"),
    };
    Ok(offset)
}

fn read_fastlz_deprecated_extra(extras: &[u8], extras_pos: &mut usize) -> Result<usize> {
    let mut length = usize::from(*extras.get(*extras_pos).ok_or_else(|| {
        Error::new(ErrorKind::Malformed).with_detail("fastlz_deprecated extras stream is exhausted")
    })?);
    *extras_pos = (*extras_pos)
        .checked_add(1)
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
    if length != 255 {
        return Ok(length);
    }
    loop {
        let end = (*extras_pos)
            .checked_add(2)
            .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
        let extra = extras.get(*extras_pos..end).ok_or_else(|| {
            Error::new(ErrorKind::Malformed)
                .with_detail("fastlz_deprecated extras stream is exhausted")
        })?;
        let extra = usize::from(u16::from_le_bytes([extra[0], extra[1]]));
        *extras_pos = end;
        length = length
            .checked_add(extra)
            .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
        if extra < usize::from(u16::MAX) {
            break;
        }
    }
    Ok(length)
}

fn parse_rolz_deprecated_payload(
    payload: &[u8],
    limits: Limits,
) -> Result<RolzDeprecatedPayload<'_>> {
    let header = payload.get(..ROLZ_DEPRECATED_HEADER_LEN).ok_or_else(|| {
        Error::new(ErrorKind::Truncated).with_detail("rolz_deprecated header is truncated")
    })?;
    let params = parse_rolz_deprecated_params(header)?;
    let num_literals = usize::try_from(read_deprecated_lz_le_u32(
        header,
        7,
        "rolz_deprecated literals",
    )?)
    .map_err(|_| {
        Error::new(ErrorKind::LimitExceeded)
            .with_detail("rolz_deprecated literal count is too large")
    })?;
    let num_sequences = usize::try_from(read_deprecated_lz_le_u32(
        header,
        11,
        "rolz_deprecated sequences",
    )?)
    .map_err(|_| {
        Error::new(ErrorKind::LimitExceeded)
            .with_detail("rolz_deprecated sequence count is too large")
    })?;
    if num_sequences > limits.max_buffer_bytes / 16 {
        return Err(Error::new(ErrorKind::LimitExceeded)
            .with_detail("rolz_deprecated sequence count exceeds buffer limit"));
    }

    let mut offset = ROLZ_DEPRECATED_HEADER_LEN;
    let literals = parse_rolz_deprecated_literals(payload, &mut offset, num_literals, limits)?;
    if literals.byte_len()? != num_literals {
        return Err(Error::new(ErrorKind::Malformed)
            .with_detail("rolz_deprecated literal count is invalid"));
    }

    let match_types = decode_deprecated_lz_entropy_payload_to_vec(
        payload,
        &mut offset,
        num_sequences,
        limits,
        "rolz_deprecated match types",
    )?;
    for &match_type in &match_types {
        if match_type > ROLZ_DEPRECATED_MATCH_TYPE_REP {
            return Err(Error::new(ErrorKind::Malformed)
                .with_detail("rolz_deprecated match type is invalid"));
        }
    }
    let literal_lengths = decode_rolz_deprecated_seq_values(
        payload,
        &mut offset,
        &match_types,
        limits,
        "rolz_deprecated literal lengths",
    )?;
    let match_lengths = decode_rolz_deprecated_seq_values(
        payload,
        &mut offset,
        &match_types,
        limits,
        "rolz_deprecated match lengths",
    )?;
    let match_codes = decode_rolz_deprecated_seq_values(
        payload,
        &mut offset,
        &match_types,
        limits,
        "rolz_deprecated match codes",
    )?;
    if offset != payload.len() {
        return Err(Error::new(ErrorKind::Malformed)
            .with_detail("rolz_deprecated payload has trailing bytes"));
    }
    Ok(RolzDeprecatedPayload {
        params,
        literals,
        match_types,
        literal_lengths,
        match_lengths,
        match_codes,
    })
}

fn parse_rolz_deprecated_literals<'a>(
    payload: &'a [u8],
    offset: &mut usize,
    num_literals: usize,
    limits: Limits,
) -> Result<RolzDeprecatedLiterals<'a>> {
    if num_literals == 0 {
        return Ok(RolzDeprecatedLiterals::Linear(LegacyLiteralPayload::Raw(
            &[],
        )));
    }

    let order = *payload.get(*offset).ok_or_else(|| {
        Error::new(ErrorKind::Truncated)
            .with_detail("rolz_deprecated literal order flag is truncated")
    })?;
    *offset = (*offset)
        .checked_add(1)
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
    match order {
        0 => parse_legacy_literal_entropy_payload(payload, offset, 1, "rolz_deprecated literals")
            .map(RolzDeprecatedLiterals::Linear),
        1 => parse_rolz_deprecated_o1_literals(payload, offset, num_literals, limits),
        _ => Err(Error::new(ErrorKind::Malformed)
            .with_detail("rolz_deprecated literal order flag is invalid")),
    }
}

fn parse_rolz_deprecated_o1_literals<'a>(
    payload: &'a [u8],
    offset: &mut usize,
    num_literals: usize,
    limits: Limits,
) -> Result<RolzDeprecatedLiterals<'a>> {
    let max_context = *payload.get(*offset).ok_or_else(|| {
        Error::new(ErrorKind::Truncated)
            .with_detail("rolz_deprecated literal clustering is truncated")
    })?;
    *offset = (*offset)
        .checked_add(1)
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;

    let map_len = usize::from(max_context)
        .checked_add(1)
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
    let map_end = (*offset)
        .checked_add(map_len)
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
    let map = payload.get(*offset..map_end).ok_or_else(|| {
        Error::new(ErrorKind::Truncated)
            .with_detail("rolz_deprecated literal clustering is truncated")
    })?;
    *offset = map_end;

    let mut context_to_cluster = [0u8; 256];
    context_to_cluster[..map_len].copy_from_slice(map);
    let num_clusters = map
        .iter()
        .copied()
        .max()
        .map(|cluster| usize::from(cluster) + 1)
        .unwrap_or(0);
    let cluster_limit = limits
        .max_buffer_bytes
        .checked_div(core::mem::size_of::<LegacyLiteralPayload<'_>>().max(1))
        .unwrap_or(0);
    if num_clusters > cluster_limit {
        return Err(Error::new(ErrorKind::LimitExceeded)
            .with_detail("rolz_deprecated literal clusters exceed buffer limit"));
    }

    let mut clusters = Vec::new();
    clusters.try_reserve_exact(num_clusters).map_err(|_| {
        Error::new(ErrorKind::LimitExceeded)
            .with_detail("rolz_deprecated literal cluster allocation failed")
    })?;
    let mut total = 0usize;
    for _ in 0..num_clusters {
        let count = usize::try_from(read_deprecated_lz_le_u32(
            payload,
            *offset,
            "rolz_deprecated literal cluster",
        )?)
        .map_err(|_| {
            Error::new(ErrorKind::LimitExceeded)
                .with_detail("rolz_deprecated literal cluster is too large")
        })?;
        *offset = (*offset)
            .checked_add(4)
            .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
        total = total
            .checked_add(count)
            .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
        if total > num_literals {
            return Err(Error::new(ErrorKind::Malformed)
                .with_detail("rolz_deprecated literal cluster count is invalid"));
        }

        let cluster =
            parse_legacy_literal_entropy_payload(payload, offset, 1, "rolz_deprecated literals")?;
        if cluster.byte_len()? != count {
            return Err(Error::new(ErrorKind::Malformed)
                .with_detail("rolz_deprecated literal cluster count is invalid"));
        }
        clusters.push(cluster);
    }
    if total != num_literals {
        return Err(Error::new(ErrorKind::Malformed)
            .with_detail("rolz_deprecated literal cluster count is invalid"));
    }

    Ok(RolzDeprecatedLiterals::O1(RolzDeprecatedO1Literals {
        max_context,
        context_to_cluster,
        clusters,
        total_len: num_literals,
    }))
}

fn parse_rolz_deprecated_params(header: &[u8]) -> Result<RolzDeprecatedParams> {
    let params = RolzDeprecatedParams {
        context_depth: usize::from(header[0]),
        context_log: usize::from(header[1]),
        row_log: usize::from(header[2]),
        min_length: usize::from(header[3]),
        predict_match_length: header[4] != 0,
        lz_min_length: usize::from(header[5]),
        rep_min_length: usize::from(header[6]),
    };
    if params.context_depth != ROLZ_DEPRECATED_PARAMS.context_depth
        || params.context_log != ROLZ_DEPRECATED_PARAMS.context_log
        || params.row_log != ROLZ_DEPRECATED_PARAMS.row_log
        || params.min_length != ROLZ_DEPRECATED_PARAMS.min_length
        || params.predict_match_length != ROLZ_DEPRECATED_PARAMS.predict_match_length
        || params.lz_min_length != ROLZ_DEPRECATED_PARAMS.lz_min_length
        || params.rep_min_length != ROLZ_DEPRECATED_PARAMS.rep_min_length
    {
        return Err(Error::new(ErrorKind::Unsupported)
            .with_detail("rolz_deprecated parameters are unsupported"));
    }
    Ok(params)
}

fn decode_rolz_deprecated_payload(
    payload: RolzDeprecatedPayload<'_>,
    decoded_size: usize,
    limits: Limits,
) -> Result<Vec<u8>> {
    let mut output = Vec::new();
    output.try_reserve_exact(decoded_size).map_err(|_| {
        Error::new(ErrorKind::LimitExceeded).with_detail("rolz_deprecated allocation failed")
    })?;
    let mut literals = RolzDeprecatedLiteralCursor::new(payload.literals);
    let mut reps = ROLZ_DEPRECATED_INITIAL_REPS;
    let mut table = if payload
        .match_types
        .contains(&ROLZ_DEPRECATED_MATCH_TYPE_ROLZ)
    {
        Some(RolzDeprecatedTable::new(payload.params, limits)?)
    } else {
        None
    };

    for index in 0..payload.match_types.len() {
        let literal_start = output.len();
        append_rolz_deprecated_literals(
            &mut literals,
            &mut output,
            payload.literal_lengths[index],
            decoded_size,
        )?;
        if let Some(table) = table.as_mut() {
            insert_rolz_deprecated_literals(
                table,
                &output,
                literal_start,
                payload.literal_lengths[index],
                payload.params,
            )?;
        }
        let match_type = payload.match_types[index];
        let match_code = payload.match_codes[index];
        let match_len = payload.match_lengths[index];
        let match_start = output.len();
        let (match_offset, match_len) = if match_type == ROLZ_DEPRECATED_MATCH_TYPE_ROLZ {
            let table = table
                .as_ref()
                .ok_or_else(|| Error::new(ErrorKind::Malformed))?;
            resolve_rolz_deprecated_rolz_match(
                table,
                &output,
                match_start,
                match_code,
                match_len,
                payload.params,
            )?
        } else {
            resolve_rolz_deprecated_match(match_type, match_code, match_len, payload.params, &reps)?
        };
        if match_offset == 0 {
            return Err(
                Error::new(ErrorKind::Malformed).with_detail("rolz_deprecated offset is zero")
            );
        }
        if match_offset > output.len() {
            return Err(Error::new(ErrorKind::Malformed)
                .with_detail("rolz_deprecated offset exceeds decoded prefix"));
        }
        let match_end = output
            .len()
            .checked_add(match_len)
            .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
        if match_end > decoded_size {
            return Err(Error::new(ErrorKind::Malformed)
                .with_detail("rolz_deprecated match length exceeds output size"));
        }
        update_rolz_deprecated_reps(&mut reps, match_type, match_code, match_offset)?;
        if match_type == ROLZ_DEPRECATED_MATCH_TYPE_ROLZ
            && let Some(table) = table.as_mut()
        {
            let context = rolz_deprecated_context(&output, match_start, payload.params)?;
            table.put(
                context,
                rolz_deprecated_output_index(match_start)?,
                match_len,
            )?;
        }
        append_lz_match(&mut output, match_start, match_offset, match_len);
        if match_type != ROLZ_DEPRECATED_MATCH_TYPE_ROLZ
            && let Some(table) = table.as_mut()
        {
            insert_rolz_deprecated_lz_match(
                table,
                &output,
                match_start,
                match_len,
                payload.params,
            )?;
        }
    }

    let remaining_literals = literals.remaining_len()?;
    let output_end = output
        .len()
        .checked_add(remaining_literals)
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
    if output_end != decoded_size {
        return Err(Error::new(ErrorKind::Malformed)
            .with_detail("rolz_deprecated output size does not match prefix"));
    }
    literals.extend_remaining(&mut output)?;
    Ok(output)
}

fn append_rolz_deprecated_literals(
    literals: &mut RolzDeprecatedLiteralCursor<'_>,
    output: &mut Vec<u8>,
    len: usize,
    decoded_size: usize,
) -> Result<()> {
    let output_end = output
        .len()
        .checked_add(len)
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
    if output_end > decoded_size {
        return Err(Error::new(ErrorKind::Malformed)
            .with_detail("rolz_deprecated literal length exceeds output size"));
    }
    literals.extend_next(len, output)
}

fn insert_rolz_deprecated_literals(
    table: &mut RolzDeprecatedTable,
    output: &[u8],
    start: usize,
    len: usize,
    params: RolzDeprecatedParams,
) -> Result<()> {
    let end = start
        .checked_add(len)
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
    let first = start.max(params.context_depth);
    for pos in first..end {
        let context = rolz_deprecated_context(output, pos, params)?;
        table.put(context, rolz_deprecated_output_index(pos)?, 0)?;
    }
    Ok(())
}

fn insert_rolz_deprecated_lz_match(
    table: &mut RolzDeprecatedTable,
    output: &[u8],
    match_start: usize,
    match_len: usize,
    params: RolzDeprecatedParams,
) -> Result<()> {
    if match_start < params.context_depth {
        return Ok(());
    }
    let context = rolz_deprecated_context(output, match_start, params)?;
    table.put(
        context,
        rolz_deprecated_output_index(match_start)?,
        match_len,
    )?;
    let next_pos = match_start
        .checked_add(1)
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
    let context = rolz_deprecated_context(output, next_pos, params)?;
    table.put(
        context,
        rolz_deprecated_output_index(next_pos)?,
        match_len - 1,
    )
}

fn resolve_rolz_deprecated_rolz_match(
    table: &RolzDeprecatedTable,
    output: &[u8],
    match_start: usize,
    match_code: usize,
    encoded_match_len: usize,
    params: RolzDeprecatedParams,
) -> Result<(usize, usize)> {
    let context = rolz_deprecated_context(output, match_start, params)?;
    let (match_pos, match_len) = table.get(context, match_code, encoded_match_len, params)?;
    if match_pos >= match_start {
        return Err(
            Error::new(ErrorKind::Malformed).with_detail("rolz_deprecated match index is invalid")
        );
    }
    let match_offset = match_start
        .checked_sub(match_pos)
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
    Ok((match_offset, match_len))
}

fn resolve_rolz_deprecated_match(
    match_type: u8,
    match_code: usize,
    match_len: usize,
    params: RolzDeprecatedParams,
    reps: &[usize; 3],
) -> Result<(usize, usize)> {
    match match_type {
        ROLZ_DEPRECATED_MATCH_TYPE_LZ => {
            if match_code == 0 {
                return Err(Error::new(ErrorKind::Malformed)
                    .with_detail("rolz_deprecated lz offset is zero"));
            }
            let match_len = match_len
                .checked_add(params.lz_min_length)
                .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
            Ok((match_code, match_len))
        }
        ROLZ_DEPRECATED_MATCH_TYPE_ROLZ => Err(Error::new(ErrorKind::Malformed)
            .with_detail("rolz_deprecated rolz match used non-rolz resolver")),
        ROLZ_DEPRECATED_MATCH_TYPE_REP0 | ROLZ_DEPRECATED_MATCH_TYPE_REP => {
            if match_code & 3 == 3 {
                return Err(Error::new(ErrorKind::Malformed)
                    .with_detail("rolz_deprecated rep code is invalid"));
            }
            let match_len = match_len
                .checked_add(params.rep_min_length)
                .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
            let match_offset = rolz_deprecated_rep_offset(match_code, reps)?;
            Ok((match_offset, match_len))
        }
        _ => {
            Err(Error::new(ErrorKind::Malformed)
                .with_detail("rolz_deprecated match type is invalid"))
        }
    }
}

fn rolz_deprecated_rep_offset(match_code: usize, reps: &[usize; 3]) -> Result<usize> {
    let rep = match_code & 3;
    let prev = reps
        .get(rep)
        .copied()
        .ok_or_else(|| Error::new(ErrorKind::Malformed))?;
    if match_code == 0 {
        return Ok(prev);
    }
    let delta = match_code >> 2;
    if delta >= ROLZ_DEPRECATED_REP_SUB {
        prev.checked_add(delta - ROLZ_DEPRECATED_REP_SUB)
            .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))
    } else {
        prev.checked_sub(ROLZ_DEPRECATED_REP_SUB - delta)
            .ok_or_else(|| {
                Error::new(ErrorKind::Malformed)
                    .with_detail("rolz_deprecated rep offset is invalid")
            })
    }
}

fn rolz_deprecated_decode_match_length(
    min_length: usize,
    expected: usize,
    encoded: usize,
) -> Result<usize> {
    let encoded_plus_min = encoded
        .checked_add(min_length)
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
    if encoded_plus_min
        >= expected
            .checked_add(1)
            .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?
    {
        return Ok(encoded_plus_min);
    }
    if encoded >= 1 {
        return encoded_plus_min
            .checked_sub(1)
            .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow));
    }
    expected
        .checked_add(encoded)
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))
}

fn rolz_deprecated_output_index(position: usize) -> Result<usize> {
    position
        .checked_add(1)
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))
}

fn rolz_deprecated_context(
    output: &[u8],
    position: usize,
    params: RolzDeprecatedParams,
) -> Result<usize> {
    if params.context_depth != 2 || params.context_log > 32 {
        return Err(Error::new(ErrorKind::Unsupported)
            .with_detail("rolz_deprecated parameters are unsupported"));
    }
    let context_start = position.checked_sub(params.context_depth).ok_or_else(|| {
        Error::new(ErrorKind::Malformed).with_detail("rolz_deprecated context is unavailable")
    })?;
    let context = output.get(context_start..position).ok_or_else(|| {
        Error::new(ErrorKind::Malformed).with_detail("rolz_deprecated context is unavailable")
    })?;
    let value = u32::from(u16::from_le_bytes([context[0], context[1]]));
    let hash = value
        .wrapping_shl(16)
        .wrapping_mul(506_832_829)
        .wrapping_shr(
            32 - u32::try_from(params.context_log).map_err(|_| {
                Error::new(ErrorKind::LimitExceeded)
                    .with_detail("rolz_deprecated context log is too large")
            })?,
        );
    usize::try_from(hash).map_err(|_| Error::new(ErrorKind::IntegerOverflow))
}

fn update_rolz_deprecated_reps(
    reps: &mut [usize; 3],
    match_type: u8,
    match_code: usize,
    offset: usize,
) -> Result<()> {
    match match_type {
        ROLZ_DEPRECATED_MATCH_TYPE_LZ | ROLZ_DEPRECATED_MATCH_TYPE_ROLZ => {
            reps[2] = reps[1];
            reps[1] = reps[0];
            reps[0] = offset;
        }
        ROLZ_DEPRECATED_MATCH_TYPE_REP0 | ROLZ_DEPRECATED_MATCH_TYPE_REP => match match_code & 3 {
            0 => {}
            1 => {
                reps[1] = reps[0];
                reps[0] = offset;
            }
            2 => {
                reps[2] = reps[1];
                reps[1] = reps[0];
                reps[0] = offset;
            }
            _ => {
                return Err(Error::new(ErrorKind::Malformed)
                    .with_detail("rolz_deprecated rep code is invalid"));
            }
        },
        _ => {
            return Err(Error::new(ErrorKind::Malformed)
                .with_detail("rolz_deprecated match type is invalid"));
        }
    }
    Ok(())
}

fn decode_rolz_deprecated_seq_values(
    source: &[u8],
    offset: &mut usize,
    match_types: &[u8],
    limits: Limits,
    transform_name: &str,
) -> Result<Vec<usize>> {
    let num_sequences = match_types.len();
    let mut values = Vec::new();
    values.try_reserve_exact(num_sequences).map_err(|_| {
        Error::new(ErrorKind::LimitExceeded)
            .with_detail(format!("{transform_name} allocation failed"))
    })?;
    if num_sequences == 0 {
        return Ok(values);
    }

    let bit_size = usize::try_from(read_deprecated_lz_le_u32(source, *offset, transform_name)?)
        .map_err(|_| {
            Error::new(ErrorKind::LimitExceeded)
                .with_detail(format!("{transform_name} bitstream is too large"))
        })?;
    *offset = (*offset)
        .checked_add(4)
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
    let mut totals = [0usize; ROLZ_DEPRECATED_MARKOV_STATES];
    for total in &mut totals {
        *total = usize::try_from(read_deprecated_lz_le_u32(source, *offset, transform_name)?)
            .map_err(|_| {
                Error::new(ErrorKind::LimitExceeded)
                    .with_detail(format!("{transform_name} state total is too large"))
            })?;
        *offset = (*offset)
            .checked_add(4)
            .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
    }
    validate_rolz_deprecated_seq_totals(&totals, num_sequences, transform_name)?;

    let bit_end = (*offset)
        .checked_add(bit_size)
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
    let bitstream = source.get(*offset..bit_end).ok_or_else(|| {
        Error::new(ErrorKind::Truncated).with_detail(format!("{transform_name} is truncated"))
    })?;
    *offset = bit_end;

    let mut codes = Vec::new();
    codes.try_reserve_exact(num_sequences).map_err(|_| {
        Error::new(ErrorKind::LimitExceeded)
            .with_detail(format!("{transform_name} code allocation failed"))
    })?;
    codes.resize(num_sequences, 0);
    for state in 0..ROLZ_DEPRECATED_MARKOV_STATES {
        let begin = if state == 0 { 0 } else { totals[state - 1] };
        let end = totals[state];
        let decoded = decode_deprecated_lz_entropy_payload_to_vec(
            source,
            offset,
            end - begin,
            limits,
            transform_name,
        )?;
        codes[begin..end].copy_from_slice(&decoded);
    }

    let mut reader = ReverseBitReader::new(bitstream)
        .map_err(|err| Error::new(ErrorKind::Malformed).with_detail(format!("{err}")))?;
    let mut positions = [0usize; ROLZ_DEPRECATED_MARKOV_STATES];
    for state in 1..ROLZ_DEPRECATED_MARKOV_STATES {
        positions[state] = totals[state - 1];
    }
    let mut state = 0usize;
    for &match_type in match_types {
        state = rolz_deprecated_markov_next_state(state, match_type)?;
        let index = positions[state];
        if index >= totals[state] {
            return Err(Error::new(ErrorKind::Malformed)
                .with_detail(format!("{transform_name} state totals are invalid")));
        }
        positions[state] = positions[state]
            .checked_add(1)
            .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
        let code = usize::from(codes[index]);
        let base = *ROLZ_DEPRECATED_VALUE_BASE.get(code).ok_or_else(|| {
            Error::new(ErrorKind::Malformed)
                .with_detail(format!("{transform_name} code is invalid"))
        })?;
        let bits = *ROLZ_DEPRECATED_VALUE_BITS.get(code).ok_or_else(|| {
            Error::new(ErrorKind::Malformed)
                .with_detail(format!("{transform_name} code is invalid"))
        })?;
        let extra = usize::try_from(reader.read_bits(bits).map_err(|err| {
            Error::new(ErrorKind::Malformed).with_detail(format!("{transform_name}: {err}"))
        })?)
        .map_err(|_| Error::new(ErrorKind::IntegerOverflow))?;
        values.push(
            base.checked_add(extra)
                .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?,
        );
    }
    validate_rolz_deprecated_seq_positions(&positions, &totals, transform_name)?;
    if reader.bits_remaining() != 0 {
        return Err(Error::new(ErrorKind::Malformed)
            .with_detail(format!("{transform_name} bitstream has trailing bits")));
    }
    Ok(values)
}

fn validate_rolz_deprecated_seq_totals(
    totals: &[usize; ROLZ_DEPRECATED_MARKOV_STATES],
    num_sequences: usize,
    transform_name: &str,
) -> Result<()> {
    let mut previous = 0usize;
    for &total in totals {
        if total < previous {
            return Err(Error::new(ErrorKind::Malformed)
                .with_detail(format!("{transform_name} state totals are invalid")));
        }
        previous = total;
    }
    if totals[ROLZ_DEPRECATED_MARKOV_STATES - 1] != num_sequences {
        return Err(Error::new(ErrorKind::Malformed)
            .with_detail(format!("{transform_name} sequence count is invalid")));
    }
    Ok(())
}

fn validate_rolz_deprecated_seq_positions(
    positions: &[usize; ROLZ_DEPRECATED_MARKOV_STATES],
    totals: &[usize; ROLZ_DEPRECATED_MARKOV_STATES],
    transform_name: &str,
) -> Result<()> {
    for state in 0..ROLZ_DEPRECATED_MARKOV_STATES {
        if positions[state] != totals[state] {
            return Err(Error::new(ErrorKind::Malformed)
                .with_detail(format!("{transform_name} state totals are invalid")));
        }
    }
    Ok(())
}

fn rolz_deprecated_markov_next_state(state: usize, match_type: u8) -> Result<usize> {
    const NEXT: [[usize; 4]; ROLZ_DEPRECATED_MARKOV_STATES] = [
        [0, 1, 2, 5],
        [0, 1, 3, 5],
        [0, 1, 4, 5],
        [0, 1, 4, 5],
        [0, 1, 4, 5],
        [0, 1, 2, 5],
    ];
    let match_type = usize::from(match_type);
    NEXT.get(state)
        .and_then(|row| row.get(match_type))
        .copied()
        .ok_or_else(|| {
            Error::new(ErrorKind::Malformed).with_detail("rolz_deprecated match type is invalid")
        })
}

fn decode_deprecated_lz_entropy_payload_to_vec(
    source: &[u8],
    offset: &mut usize,
    expected_len: usize,
    limits: Limits,
    transform_name: &str,
) -> Result<Vec<u8>> {
    let payload = parse_legacy_literal_entropy_payload(source, offset, 1, transform_name)?;
    if payload.byte_len()? != expected_len {
        return Err(Error::new(ErrorKind::Malformed)
            .with_detail(format!("{transform_name} count is invalid")));
    }
    if expected_len > limits.max_buffer_bytes {
        return Err(Error::new(ErrorKind::LimitExceeded)
            .with_detail(format!("{transform_name} exceeds buffer limit")));
    }
    copy_deprecated_lz_literals(payload, transform_name)
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

fn parse_legacy_literal_entropy_payload<'a>(
    source: &'a [u8],
    offset: &mut usize,
    element_width: usize,
    transform_name: &str,
) -> Result<LegacyLiteralPayload<'a>> {
    let (entropy_type, decoded_elements) =
        read_legacy_entropy_header(source, offset, transform_name)?;
    match entropy_type {
        2 => {
            let end = (*offset)
                .checked_add(element_width)
                .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
            let value = source
                .get(*offset..end)
                .ok_or_else(|| Error::new(ErrorKind::Truncated))?;
            *offset = end;
            Ok(LegacyLiteralPayload::Constant {
                value,
                decoded_elements,
                element_width,
            })
        }
        3 => {
            let output_len = legacy_entropy_output_len(decoded_elements, element_width)?;
            let end = (*offset)
                .checked_add(output_len)
                .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
            let payload = source
                .get(*offset..end)
                .ok_or_else(|| Error::new(ErrorKind::Truncated))?;
            *offset = end;
            Ok(LegacyLiteralPayload::Raw(payload))
        }
        6 | 7 => Err(Error::new(ErrorKind::Malformed)
            .with_detail(format!("{transform_name} entropy mode is reserved"))),
        _ => Err(Error::new(ErrorKind::Unsupported)
            .with_detail(format!("{transform_name} entropy mode is unsupported"))),
    }
}

fn parse_legacy_raw_entropy_slice<'a>(
    source: &'a [u8],
    offset: &mut usize,
    element_width: usize,
    transform_name: &str,
) -> Result<&'a [u8]> {
    let (entropy_type, decoded_elements) =
        read_legacy_entropy_header(source, offset, transform_name)?;
    match entropy_type {
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

    let output_len = legacy_entropy_output_len(decoded_elements, element_width)?;
    let end = (*offset)
        .checked_add(output_len)
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
    let payload = source
        .get(*offset..end)
        .ok_or_else(|| Error::new(ErrorKind::Truncated))?;
    *offset = end;
    Ok(payload)
}

fn read_legacy_entropy_header(
    source: &[u8],
    offset: &mut usize,
    transform_name: &str,
) -> Result<(u8, usize)> {
    let header = *source.get(*offset).ok_or_else(|| {
        Error::new(ErrorKind::Truncated)
            .with_detail(format!("{transform_name} entropy header is truncated"))
    })?;
    *offset = (*offset)
        .checked_add(1)
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
    let decoded_elements = read_legacy_entropy_size(header, source, offset, transform_name)?;
    Ok((header & 0x07, decoded_elements))
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

fn legacy_entropy_output_len(decoded_elements: usize, element_width: usize) -> Result<usize> {
    decoded_elements
        .checked_mul(element_width)
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))
}

fn read_legacy_literal_byte(
    literals: &LegacyLiteralPayload<'_>,
    offset: usize,
    transform_name: &str,
) -> Result<u8> {
    match literals {
        LegacyLiteralPayload::Raw(bytes) => bytes.get(offset).copied().ok_or_else(|| {
            Error::new(ErrorKind::Malformed)
                .with_detail(format!("{transform_name} stream is too short"))
        }),
        LegacyLiteralPayload::Constant {
            value,
            decoded_elements,
            element_width,
        } => {
            let len = legacy_entropy_output_len(*decoded_elements, *element_width)?;
            if offset >= len {
                return Err(Error::new(ErrorKind::Malformed)
                    .with_detail(format!("{transform_name} stream is too short")));
            }
            let value_offset = offset.checked_rem(*element_width).ok_or_else(|| {
                Error::new(ErrorKind::Malformed)
                    .with_detail(format!("{transform_name} literal width is invalid"))
            })?;
            value.get(value_offset).copied().ok_or_else(|| {
                Error::new(ErrorKind::Malformed)
                    .with_detail(format!("{transform_name} stream is too short"))
            })
        }
    }
}

fn read_deprecated_lz_le_u32(source: &[u8], offset: usize, transform_name: &str) -> Result<u32> {
    let end = offset
        .checked_add(4)
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
    let bytes = source.get(offset..end).ok_or_else(|| {
        Error::new(ErrorKind::Truncated).with_detail(format!("{transform_name} is truncated"))
    })?;
    Ok(u32::from_le_bytes(
        bytes
            .try_into()
            .map_err(|_| Error::new(ErrorKind::Malformed))?,
    ))
}

fn read_deprecated_lz_sized_slice<'a>(
    source: &'a [u8],
    offset: &mut usize,
    transform_name: &str,
) -> Result<&'a [u8]> {
    let size = usize::try_from(read_var_u64(source, offset)?).map_err(|_| {
        Error::new(ErrorKind::LimitExceeded)
            .with_detail(format!("{transform_name} stream is too large"))
    })?;
    let end = (*offset)
        .checked_add(size)
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
    let slice = source.get(*offset..end).ok_or_else(|| {
        Error::new(ErrorKind::Truncated)
            .with_detail(format!("{transform_name} stream is truncated"))
    })?;
    *offset = end;
    Ok(slice)
}

fn copy_deprecated_lz_literals(
    literals: LegacyLiteralPayload<'_>,
    transform_name: &str,
) -> Result<Vec<u8>> {
    let output_len = literals.byte_len()?;
    let mut output = Vec::new();
    output.try_reserve_exact(output_len).map_err(|_| {
        Error::new(ErrorKind::LimitExceeded)
            .with_detail(format!("{transform_name} allocation failed"))
    })?;
    match literals {
        LegacyLiteralPayload::Raw(bytes) => output.extend_from_slice(bytes),
        LegacyLiteralPayload::Constant {
            value,
            decoded_elements,
            ..
        } => {
            for _ in 0..decoded_elements {
                output.extend_from_slice(value);
            }
        }
    }
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
