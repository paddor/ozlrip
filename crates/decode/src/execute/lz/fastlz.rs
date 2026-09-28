//! The deprecated `fastlz` node: literal and token streams in the legacy
//! entropy container, followed by offsets and extra lengths.

use alloc::vec::Vec;

use ozlrip_core::{Error, ErrorKind, Limits, Result};

use super::legacy_literals::{
    LegacyLiteralCursor, LegacyLiteralPayload, copy_deprecated_lz_literals,
    parse_deprecated_lz_stored_stream, parse_legacy_literal_entropy_payload,
    read_deprecated_lz_sized_slice,
};
use super::sequences::append_lz_match;
use crate::execute::header::require_empty_header;
use crate::execute::streams::StreamInput;

struct FastLzDeprecatedPayload<'a> {
    literals: LegacyLiteralPayload<'a>,
    tokens: LegacyLiteralPayload<'a>,
    offsets: &'a [u8],
    extras: &'a [u8],
}

const FASTLZ_DEPRECATED_MIN_OFFSET: usize = 16;

pub(in crate::execute) fn decode_fastlz_deprecated_node(
    source: StreamInput<'_>,
    header: &[u8],
    limits: Limits,
) -> Result<Vec<u8>> {
    require_empty_header(header, "fastlz_deprecated headers are unsupported")?;
    let (decoded_size, payload) =
        parse_deprecated_lz_stored_stream(source, limits, "fastlz_deprecated")?;
    let payload = parse_fastlz_deprecated_payload(payload, limits)?;
    decode_fastlz_deprecated_payload(payload, decoded_size)
}

fn parse_fastlz_deprecated_payload(
    payload: &[u8],
    limits: Limits,
) -> Result<FastLzDeprecatedPayload<'_>> {
    let mut offset = 0usize;
    let literals = parse_legacy_literal_entropy_payload(
        payload,
        &mut offset,
        1,
        limits,
        "fastlz_deprecated literals",
    )?;
    let tokens = parse_legacy_literal_entropy_payload(
        payload,
        &mut offset,
        2,
        limits,
        "fastlz_deprecated tokens",
    )?;
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
        Error::new(ErrorKind::AllocationFailed).with_detail("fastlz_deprecated allocation failed")
    })?;
    let mut literals = LegacyLiteralCursor::new(payload.literals);
    let tokens = copy_deprecated_lz_literals(payload.tokens, "fastlz_deprecated tokens")?;
    let mut offsets_pos = 0usize;
    let mut extras_pos = 0usize;
    let mut rep = FASTLZ_DEPRECATED_MIN_OFFSET;

    for (index, token) in tokens.as_chunks::<2>().0.iter().enumerate() {
        let token = u16::from_le_bytes(*token);
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
        append_fastlz_deprecated_match(&mut output, offset, match_len, decoded_size)?;
    }

    if offsets_pos != payload.offsets.len() || extras_pos != payload.extras.len() {
        return Err(Error::new(ErrorKind::Malformed)
            .with_detail("fastlz_deprecated auxiliary stream was not fully consumed"));
    }
    finish_fastlz_deprecated_output(literals, output, decoded_size)
}

/// Checks one FastLZ match against the decoded prefix and the output size,
/// then copies it.
fn append_fastlz_deprecated_match(
    output: &mut Vec<u8>,
    offset: usize,
    match_len: usize,
    decoded_size: usize,
) -> Result<()> {
    if offset < FASTLZ_DEPRECATED_MIN_OFFSET {
        return Err(
            Error::new(ErrorKind::Malformed).with_detail("fastlz_deprecated offset is too small")
        );
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
    append_lz_match(output, out_pos, offset, match_len);
    Ok(())
}

/// Appends the literals after the last token, which must end the output at
/// exactly `decoded_size`.
fn finish_fastlz_deprecated_output(
    mut literals: LegacyLiteralCursor<'_>,
    mut output: Vec<u8>,
    decoded_size: usize,
) -> Result<Vec<u8>> {
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
