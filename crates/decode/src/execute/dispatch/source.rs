//! A dispatch_string source stream, the serial output its strings go to,
//! and the checked appenders that copy its next string.

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

/// Bytes one fixed-size copy moves. A string of at most this many bytes
/// appends a whole chunk and truncates back to its end, when the chunk fits
/// in its source and in spare capacity. The constant size inlines the copy,
/// and appending writes each output byte once, with no zero fill.
const COPY_CHUNK: usize = 16;

/// The serial output of a dispatch_string node, with room reserved for
/// every source byte.
pub(super) struct SerialOutput<'o> {
    bytes: &'o mut Vec<u8>,
}

impl<'o> SerialOutput<'o> {
    pub(super) fn new(bytes: &'o mut Vec<u8>) -> Self {
        Self { bytes }
    }

    /// Appends `source[start..start + len]`, which must be in bounds.
    #[expect(clippy::inline_always, reason = "runs once per dispatched string")]
    #[inline(always)]
    fn write(&mut self, source: &[u8], start: usize, len: usize) {
        let end = self.bytes.len() + len;
        if len <= COPY_CHUNK
            && self.bytes.capacity() - self.bytes.len() >= COPY_CHUNK
            && let Some(chunk) = source
                .get(start..)
                .and_then(<[u8]>::first_chunk::<COPY_CHUNK>)
        {
            self.bytes.extend_from_slice(chunk);
            self.bytes.truncate(end);
        } else {
            self.bytes.extend_from_slice(&source[start..start + len]);
        }
    }

    #[expect(clippy::inline_always, reason = "runs once per dispatched string")]
    #[inline(always)]
    fn push(&mut self, byte: u8) {
        self.bytes.push(byte);
    }
}

#[expect(
    clippy::inline_always,
    reason = "profiled CSV dispatch hot path benefits from inlining this leaf"
)]
#[inline(always)]
pub(super) fn append_dispatched_string_to_serial(
    source: usize,
    sources: &mut [DispatchStringSource<'_>],
    output: &mut SerialOutput<'_>,
) -> Result<()> {
    let source = sources.get_mut(source).ok_or_else(|| {
        Error::new(ErrorKind::Malformed).with_detail("dispatch_string source index is invalid")
    })?;
    append_dispatched_string_source_to_serial(source, output)
}

#[expect(
    clippy::inline_always,
    reason = "profiled CSV dispatch hot path benefits from inlining this leaf"
)]
#[inline(always)]
pub(super) fn append_dispatched_string_source_to_serial(
    source: &mut DispatchStringSource<'_>,
    output: &mut SerialOutput<'_>,
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
    if end > source.bytes.len() {
        return Err(
            Error::new(ErrorKind::Malformed).with_detail("dispatch_string range is invalid")
        );
    }
    output.write(source.bytes, offset, length);
    // `position` indexes `lengths`, so it cannot overflow.
    source.position += 1;
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
    output: &mut SerialOutput<'_>,
) -> Result<()> {
    if source.lengths.get(source.position) == Some(&1)
        && let Some(&byte) = source.bytes.get(source.byte_position)
    {
        output.push(byte);
        // Both cursors index their slices, so they cannot overflow.
        source.position += 1;
        source.byte_position += 1;
        return Ok(());
    }
    append_dispatched_string_source_to_serial(source, output)
}
