//! A dispatch_string source stream and the checks the CSV fast paths run
//! on it.

#[cfg(not(feature = "paranoid"))]
use ozlrip_core::{Error, ErrorKind, Result};

/// One string source of a dispatch_string node, with a cursor over its
/// strings and bytes.
pub(super) struct DispatchStringSource<'a> {
    pub(super) bytes: &'a [u8],
    pub(super) lengths: &'a [u32],
    pub(super) position: usize,
    pub(super) byte_position: usize,
}

#[cfg(not(feature = "paranoid"))]
pub(super) fn remaining_string_bytes(source: &DispatchStringSource<'_>) -> Result<usize> {
    source.lengths[source.position..]
        .iter()
        .try_fold(0usize, |sum, &length| {
            sum.checked_add(length as usize)
                .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))
        })
}

/// Whether `source` holds exactly `count` more strings, and its remaining
/// bytes are exactly those strings.
#[cfg(not(feature = "paranoid"))]
pub(super) fn whole_strings_remaining(
    source: &DispatchStringSource<'_>,
    count: usize,
) -> Result<bool> {
    Ok(
        source.lengths.len().saturating_sub(source.position) == count
            && source.bytes.len().saturating_sub(source.byte_position)
                == remaining_string_bytes(source)?,
    )
}

/// Whether `source` holds exactly `count` more strings of one byte each.
#[cfg(not(feature = "paranoid"))]
pub(super) fn one_byte_strings_remaining(source: &DispatchStringSource<'_>, count: usize) -> bool {
    source.lengths.len().saturating_sub(source.position) == count
        && source.lengths[source.position..]
            .iter()
            .all(|&length| length == 1)
        && source.bytes.len().saturating_sub(source.byte_position) == count
}

#[cfg(not(feature = "paranoid"))]
pub(super) fn fixed_length_source_remaining(
    source: &DispatchStringSource<'_>,
    count: usize,
    length: usize,
) -> bool {
    let Some(byte_count) = count.checked_mul(length) else {
        return false;
    };
    source.lengths.len().saturating_sub(source.position) == count
        && source.bytes.len().saturating_sub(source.byte_position) == byte_count
        && source.lengths[source.position..]
            .iter()
            .all(|&candidate| candidate as usize == length)
}

#[cfg(not(feature = "paranoid"))]
pub(super) fn delimiter_bytes_match_csv_rows(
    source: &DispatchStringSource<'_>,
    rows: usize,
) -> bool {
    let Some(byte_count) = rows.checked_mul(4) else {
        return false;
    };
    let remaining = &source.bytes[source.byte_position..];
    remaining.len() == byte_count && chunks_match_4(remaining, *b",,,\n")
}

#[cfg(not(feature = "paranoid"))]
pub(super) fn delimiter_bytes_match_csv_header_rows(
    source: &DispatchStringSource<'_>,
    rows: usize,
) -> bool {
    let Some(row_delimiter_bytes) = rows.checked_mul(4) else {
        return false;
    };
    let Some(byte_count) = row_delimiter_bytes.checked_add(1) else {
        return false;
    };
    let remaining = &source.bytes[source.byte_position..];
    remaining.len() == byte_count
        && remaining.first() == Some(&b'\n')
        && chunks_match_4(&remaining[1..], *b",,,\n")
}

/// Whether `bytes` is `pattern` repeated a whole number of times.
#[cfg(not(feature = "paranoid"))]
pub(super) fn chunks_match_16(bytes: &[u8], pattern: [u8; 16]) -> bool {
    let (chunks, rest) = bytes.as_chunks::<16>();
    let expected = u128::from_le_bytes(pattern);
    rest.is_empty()
        && chunks
            .iter()
            .all(|chunk| u128::from_le_bytes(*chunk) == expected)
}

/// Whether `bytes` is `pattern` repeated a whole number of times.
#[cfg(not(feature = "paranoid"))]
fn chunks_match_4(bytes: &[u8], pattern: [u8; 4]) -> bool {
    let (chunks, rest) = bytes.as_chunks::<4>();
    let expected = u32::from_le_bytes(pattern);
    rest.is_empty()
        && chunks
            .iter()
            .all(|chunk| u32::from_le_bytes(*chunk) == expected)
}
