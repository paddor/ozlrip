#[cfg(feature = "lz4")]
use alloc::format;
use alloc::vec::Vec;

use ozlrip_core::{Error, ErrorKind, Limits, Result};

#[cfg(feature = "lz4")]
use super::numeric::read_var_u64;

/// Most bytes one LZ4 block byte can decode to. A match sequence spends a
/// token and a 2-byte offset on at most 19 bytes, and each length extension
/// byte adds at most 255.
#[cfg(feature = "lz4")]
pub(super) const LZ4_MAX_EXPANSION: usize = 255;

#[cfg(feature = "lz4")]
pub(super) fn decode_lz4_chunk(stored: &[u8], header: &[u8], limits: Limits) -> Result<Vec<u8>> {
    let decoded_size = read_single_varint_header(header)?;
    if decoded_size > limits.max_decoded_bytes || decoded_size > limits.max_buffer_bytes {
        return Err(
            Error::new(ErrorKind::LimitExceeded).with_detail("decoded output limit exceeded")
        );
    }
    if decoded_size > stored.len().saturating_mul(LZ4_MAX_EXPANSION) {
        return Err(Error::new(ErrorKind::Malformed)
            .with_detail("lz4 decoded size exceeds the block's maximum expansion"));
    }
    let mut output = alloc::vec![0; decoded_size];
    let written = lz4rip_decode::decompress_into(stored, &mut output).map_err(|err| {
        Error::new(ErrorKind::Malformed).with_detail(format!("OpenZL lz4 block failed: {err}"))
    })?;
    if written != decoded_size {
        return Err(Error::new(ErrorKind::Malformed).with_detail("OpenZL lz4 output size mismatch"));
    }
    Ok(output)
}

#[cfg(not(feature = "lz4"))]
pub(super) fn decode_lz4_chunk(_stored: &[u8], _header: &[u8], _limits: Limits) -> Result<Vec<u8>> {
    Err(Error::new(ErrorKind::Unsupported).with_detail("lz4 support is disabled"))
}

#[cfg(feature = "lz4")]
pub(super) fn read_single_varint_header(header: &[u8]) -> Result<usize> {
    let mut offset = 0usize;
    let value = read_var_u64(header, &mut offset)?;
    if offset != header.len() {
        return Err(
            Error::new(ErrorKind::Malformed).with_detail("unexpected transform header bytes")
        );
    }
    usize::try_from(value).map_err(|_| {
        Error::new(ErrorKind::LimitExceeded).with_detail("transform header value is too large")
    })
}
