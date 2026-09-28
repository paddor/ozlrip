//! Literal and token streams of the deprecated LZ nodes, stored in the
//! legacy entropy container, and a cursor that reads them in order.

use alloc::format;
use alloc::vec::Vec;

use ozlrip_core::{Error, ErrorKind, Limits, Result};

use crate::execute::elements::read_var_u64;
use crate::execute::entropy::{LegacyLimit, LegacyParams, LegacyPayload, parse_legacy_payload};
use crate::execute::output::check_output_len;
use crate::execute::streams::StreamInput;

pub(super) struct LegacyLiteralCursor<'a> {
    payload: LegacyPayload<'a>,
    offset: usize,
}

impl<'a> LegacyLiteralCursor<'a> {
    pub(super) const fn new(payload: LegacyPayload<'a>) -> Self {
        Self { payload, offset: 0 }
    }

    pub(super) fn remaining_len(&self) -> Result<usize> {
        self.payload
            .byte_len()?
            .checked_sub(self.offset)
            .ok_or_else(|| {
                Error::new(ErrorKind::Malformed)
                    .with_detail("fastlz_deprecated literal stream is too short")
            })
    }

    pub(super) fn extend_next(&mut self, len: usize, output: &mut Vec<u8>) -> Result<()> {
        let end = self
            .offset
            .checked_add(len)
            .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
        if end > self.payload.byte_len()? {
            return Err(Error::new(ErrorKind::Malformed)
                .with_detail("fastlz_deprecated literal stream is too short"));
        }
        match &self.payload {
            LegacyPayload::Raw(bytes) => {
                let chunk = bytes.get(self.offset..end).ok_or_else(|| {
                    Error::new(ErrorKind::Malformed)
                        .with_detail("fastlz_deprecated literal stream is too short")
                })?;
                output.extend_from_slice(chunk);
            }
            LegacyPayload::Decoded(bytes) => {
                let chunk = bytes.get(self.offset..end).ok_or_else(|| {
                    Error::new(ErrorKind::Malformed)
                        .with_detail("fastlz_deprecated literal stream is too short")
                })?;
                output.extend_from_slice(chunk);
            }
            LegacyPayload::Constant {
                value,
                element_width,
                ..
            } => {
                if !self.offset.is_multiple_of(*element_width)
                    || !len.is_multiple_of(*element_width)
                {
                    return Err(Error::new(ErrorKind::Malformed)
                        .with_detail("deprecated lz constant literal range is misaligned"));
                }
                let elements = len / *element_width;
                for _ in 0..elements {
                    output.extend_from_slice(value);
                }
            }
        }
        self.offset = end;
        Ok(())
    }

    pub(super) fn extend_remaining(&mut self, output: &mut Vec<u8>) -> Result<()> {
        let len = self.remaining_len()?;
        self.extend_next(len, output)
    }
}

pub(super) fn decode_deprecated_lz_entropy_payload_to_vec(
    source: &[u8],
    offset: &mut usize,
    expected_len: usize,
    limits: Limits,
    transform_name: &str,
) -> Result<Vec<u8>> {
    let payload = parse_legacy_literal_entropy_payload(source, offset, 1, limits, transform_name)?;
    if payload.byte_len()? != expected_len {
        return Err(Error::new(ErrorKind::Malformed)
            .with_detail(format!("{transform_name} count is invalid")));
    }
    if expected_len > limits.max_buffer_bytes {
        return Err(Error::new(ErrorKind::LimitExceeded)
            .with_detail(format!("{transform_name} exceeds buffer limit")));
    }
    payload.into_vec(transform_name)
}

pub(super) fn parse_deprecated_lz_stored_stream<'a>(
    source: StreamInput<'a>,
    limits: Limits,
    transform_name: &str,
) -> Result<(usize, &'a [u8])> {
    if source.element_width != 1 {
        return Err(Error::new(ErrorKind::InvalidType)
            .with_detail(format!("{transform_name} input must be serial")));
    }
    let size_prefix = source.bytes.get(..4).ok_or_else(|| {
        Error::new(ErrorKind::Malformed).with_detail("deprecated lz stream is missing size prefix")
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
    check_output_len(decoded_size, limits)?;
    Ok((decoded_size, &source.bytes[4..]))
}

/// A literal or token stream of a deprecated LZ node. Its decoded size
/// counts against the buffer limit.
pub(super) fn parse_legacy_literal_entropy_payload<'a>(
    source: &'a [u8],
    offset: &mut usize,
    element_width: usize,
    limits: Limits,
    transform_name: &str,
) -> Result<LegacyPayload<'a>> {
    let params = LegacyParams {
        element_width,
        fse_states: 2,
        limit: LegacyLimit::Buffer,
        limits,
        transform_name,
    };
    parse_legacy_payload(source, offset, params)
}

pub(super) fn read_legacy_literal_byte(
    literals: &LegacyPayload<'_>,
    offset: usize,
    transform_name: &str,
) -> Result<u8> {
    match literals {
        LegacyPayload::Raw(bytes) => bytes.get(offset).copied().ok_or_else(|| {
            Error::new(ErrorKind::Malformed)
                .with_detail(format!("{transform_name} stream is too short"))
        }),
        LegacyPayload::Decoded(bytes) => bytes.get(offset).copied().ok_or_else(|| {
            Error::new(ErrorKind::Malformed)
                .with_detail(format!("{transform_name} stream is too short"))
        }),
        LegacyPayload::Constant {
            value,
            element_width,
            ..
        } => {
            let len = literals.byte_len()?;
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

pub(super) fn read_deprecated_lz_le_u32(
    source: &[u8],
    offset: usize,
    transform_name: &str,
) -> Result<u32> {
    let end = offset
        .checked_add(4)
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
    let bytes = source.get(offset..end).ok_or_else(|| {
        Error::new(ErrorKind::Malformed).with_detail(format!("{transform_name} is truncated"))
    })?;
    Ok(u32::from_le_bytes(
        bytes
            .try_into()
            .map_err(|_| Error::new(ErrorKind::Malformed))?,
    ))
}

pub(super) fn read_deprecated_lz_sized_slice<'a>(
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
        Error::new(ErrorKind::Malformed)
            .with_detail(format!("{transform_name} stream is truncated"))
    })?;
    *offset = end;
    Ok(slice)
}
