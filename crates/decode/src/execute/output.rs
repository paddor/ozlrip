use alloc::vec::Vec;

use ozlrip_core::{Error, ErrorKind, Limits, Result};

use crate::parse::FramePlan;

pub(super) struct DecodedOutput<'a> {
    pub(super) chunks: Vec<DecodedChunk<'a>>,
    pub(super) total_len: usize,
}

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

pub(super) fn check_output_size(
    size: usize,
    encoded_size: usize,
    plan: &FramePlan,
    limits: Limits,
) -> Result<()> {
    if size > limits.max_decoded_bytes || size > limits.max_buffer_bytes {
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
    if size > max_expanded {
        return Err(
            Error::new(ErrorKind::LimitExceeded).with_detail("decoded expansion ratio exceeded")
        );
    }
    if let Some(expected) = plan.info.output_sizes.first().and_then(|size| *size) {
        let expected = usize::try_from(expected).map_err(|_| {
            Error::new(ErrorKind::LimitExceeded).with_detail("decoded output size is too large")
        })?;
        if expected != size {
            return Err(Error::new(ErrorKind::Malformed)
                .with_detail("stored output size does not match frame header"));
        }
    }
    Ok(())
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
