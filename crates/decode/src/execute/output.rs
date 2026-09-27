use alloc::vec::Vec;

use ozlrip_core::{Error, ErrorKind, Limits, Result};

use crate::parse::FramePlan;

pub(super) enum DecodedChunk<'a> {
    Borrowed(&'a [u8]),
    Owned(Vec<u8>),
}

impl DecodedChunk<'_> {
    pub(super) fn as_slice(&self) -> &[u8] {
        match self {
            Self::Borrowed(bytes) => bytes,
            Self::Owned(bytes) => bytes,
        }
    }
}

/// Tracks one frame output against the size its header declares.
///
/// Built before anything is reserved or written, so a tiny frame that
/// declares a huge output fails on the configured limits or the expansion
/// ratio instead of reserving that output. Chunks are charged as they are
/// decoded, and the total must match the declared size exactly.
pub(super) struct OutputBudget {
    declared: usize,
    written: usize,
    reserved: bool,
}

impl OutputBudget {
    /// Budget for output `index` of `plan`. `encoded_size` is the size of the
    /// whole frame.
    pub(super) fn for_output(
        plan: &FramePlan,
        index: usize,
        encoded_size: usize,
        limits: Limits,
    ) -> Result<Self> {
        let declared = plan
            .info
            .output_sizes
            .get(index)
            .copied()
            .flatten()
            .ok_or_else(|| {
                Error::new(ErrorKind::Unsupported)
                    .with_detail("unknown OpenZL output sizes are unsupported")
            })?;
        let declared = usize::try_from(declared).map_err(|_| {
            Error::new(ErrorKind::LimitExceeded).with_detail("decoded output size is too large")
        })?;
        Self::new(declared, encoded_size, limits)
    }

    pub(super) fn new(declared: usize, encoded_size: usize, limits: Limits) -> Result<Self> {
        if declared > limits.max_decoded_bytes || declared > limits.max_buffer_bytes {
            return Err(
                Error::new(ErrorKind::LimitExceeded).with_detail("decoded output limit exceeded")
            );
        }
        let max_expanded = encoded_size
            .checked_mul(limits.max_expansion_ratio)
            .ok_or_else(|| {
                Error::new(ErrorKind::IntegerOverflow)
                    .with_detail("encoded size expansion limit overflowed")
            })?;
        if declared > max_expanded {
            return Err(Error::new(ErrorKind::LimitExceeded)
                .with_detail("decoded expansion ratio exceeded"));
        }
        Ok(Self {
            declared,
            written: 0,
            reserved: false,
        })
    }

    /// Bytes the output may still grow by.
    pub(super) fn remaining(&self) -> usize {
        self.declared - self.written
    }

    /// Reserves the rest of the declared size in `dst`, once.
    pub(super) fn reserve(&mut self, dst: &mut Vec<u8>) -> Result<()> {
        if !self.reserved {
            dst.try_reserve_exact(self.remaining()).map_err(|_| {
                Error::new(ErrorKind::LimitExceeded).with_detail("output allocation failed")
            })?;
            self.reserved = true;
        }
        Ok(())
    }

    /// Charges `len` decoded bytes; fails if they exceed the declared size.
    pub(super) fn consume(&mut self, len: usize) -> Result<()> {
        if len > self.remaining() {
            return Err(size_mismatch());
        }
        self.written += len;
        Ok(())
    }

    /// Fails unless exactly the declared size was decoded.
    pub(super) fn finish(&self) -> Result<()> {
        if self.written == self.declared {
            Ok(())
        } else {
            Err(size_mismatch())
        }
    }
}

/// The error for output that does not match its declared size.
pub(super) fn size_mismatch() -> Error {
    Error::new(ErrorKind::Malformed).with_detail("stored output size does not match frame header")
}

#[cfg(feature = "checksum")]
pub(super) fn verify_decoded_checksum(output: &[u8], expected: Option<u32>) -> Result<()> {
    if let Some(expected) = expected {
        let actual = (xxhash_rust::xxh3::xxh3_64(output) & 0xffff_ffff) as u32;
        if actual != expected {
            return Err(Error::new(ErrorKind::ChecksumMismatch)
                .with_detail("OpenZL decoded checksum mismatch"));
        }
    }
    Ok(())
}
