//! A dispatch_string source stream and the checked appenders that copy its
//! next string.

use alloc::vec::Vec;

use ozlrip_core::{Error, ErrorKind, Result};

/// One string source of a dispatch_string node, with a cursor over its
/// strings and bytes.
pub(super) struct DispatchStringSource<'a> {
    pub(super) bytes: &'a [u8],
    pub(super) lengths: &'a [u32],
    pub(super) position: usize,
    pub(super) byte_position: usize,
}

#[expect(
    clippy::inline_always,
    reason = "profiled CSV dispatch hot path benefits from inlining this leaf"
)]
#[inline(always)]
pub(super) fn append_dispatched_string_to_serial(
    source: usize,
    sources: &mut [DispatchStringSource<'_>],
    output: &mut Vec<u8>,
) -> Result<()> {
    let source = sources.get_mut(source).ok_or_else(|| {
        Error::new(ErrorKind::Malformed).with_detail("dispatch_string source index is invalid")
    })?;
    let length = *source.lengths.get(source.position).ok_or_else(|| {
        Error::new(ErrorKind::Malformed).with_detail("dispatch_string source is exhausted")
    })?;
    let length = usize::try_from(length)
        .map_err(|_| Error::new(ErrorKind::LimitExceeded).with_detail("string length too large"))?;
    let offset = source.byte_position;
    let end = offset
        .checked_add(length)
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
    let bytes = source.bytes.get(offset..end).ok_or_else(|| {
        Error::new(ErrorKind::Malformed).with_detail("dispatch_string range is invalid")
    })?;
    output.extend_from_slice(bytes);
    source.position = source
        .position
        .checked_add(1)
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
    source.byte_position = end;
    Ok(())
}

#[expect(
    clippy::inline_always,
    reason = "profiled CSV dispatch hot path benefits from inlining this leaf"
)]
#[inline(always)]
pub(super) fn append_dispatched_string_source_to_serial(
    source: &mut DispatchStringSource<'_>,
    output: &mut Vec<u8>,
) -> Result<()> {
    let length = *source.lengths.get(source.position).ok_or_else(|| {
        Error::new(ErrorKind::Malformed).with_detail("dispatch_string source is exhausted")
    })?;
    let length = usize::try_from(length)
        .map_err(|_| Error::new(ErrorKind::LimitExceeded).with_detail("string length too large"))?;
    let offset = source.byte_position;
    let end = offset
        .checked_add(length)
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
    let bytes = source.bytes.get(offset..end).ok_or_else(|| {
        Error::new(ErrorKind::Malformed).with_detail("dispatch_string range is invalid")
    })?;
    output.extend_from_slice(bytes);
    source.position = source
        .position
        .checked_add(1)
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
    source.byte_position = end;
    Ok(())
}

#[expect(
    clippy::inline_always,
    reason = "profiled CSV dispatch hot path benefits from inlining this leaf"
)]
#[inline(always)]
pub(super) fn append_dispatched_single_byte_string_source_to_serial(
    source: &mut DispatchStringSource<'_>,
    output: &mut Vec<u8>,
) -> Result<()> {
    let length = *source.lengths.get(source.position).ok_or_else(|| {
        Error::new(ErrorKind::Malformed).with_detail("dispatch_string source is exhausted")
    })?;
    if length == 1 {
        let byte = *source.bytes.get(source.byte_position).ok_or_else(|| {
            Error::new(ErrorKind::Malformed).with_detail("dispatch_string range is invalid")
        })?;
        output.push(byte);
        source.position = source
            .position
            .checked_add(1)
            .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
        source.byte_position = source
            .byte_position
            .checked_add(1)
            .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
        return Ok(());
    }

    let length = usize::try_from(length)
        .map_err(|_| Error::new(ErrorKind::LimitExceeded).with_detail("string length too large"))?;
    let offset = source.byte_position;
    let end = offset
        .checked_add(length)
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
    let bytes = source.bytes.get(offset..end).ok_or_else(|| {
        Error::new(ErrorKind::Malformed).with_detail("dispatch_string range is invalid")
    })?;
    output.extend_from_slice(bytes);
    source.position = source
        .position
        .checked_add(1)
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
    source.byte_position = end;
    Ok(())
}
