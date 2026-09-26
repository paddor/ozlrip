use alloc::format;

use ozlrip_core::{Error, ErrorKind, Result};

use super::streams::StreamInput;

pub(super) fn max_numeric_value(element_width: usize) -> Result<u64> {
    match element_width {
        1 => Ok(u64::from(u8::MAX)),
        2 => Ok(u64::from(u16::MAX)),
        4 => Ok(u64::from(u32::MAX)),
        8 => Ok(u64::MAX),
        _ => Err(Error::new(ErrorKind::InvalidType).with_detail("numeric width is unsupported")),
    }
}

#[inline]
pub(super) fn read_numeric_element(
    bytes: &[u8],
    element_width: usize,
    index: usize,
) -> Result<u64> {
    let start = index
        .checked_mul(element_width)
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
    let element = bytes.get(start..start + element_width).ok_or_else(|| {
        Error::new(ErrorKind::Malformed).with_detail("numeric stream is truncated")
    })?;
    let mut value = [0u8; 8];
    value[..element_width].copy_from_slice(element);
    Ok(u64::from_le_bytes(value))
}

#[expect(
    clippy::cast_possible_truncation,
    clippy::inline_always,
    reason = "profiled numeric decode paths pay measurable call overhead"
)]
#[inline(always)]
pub(super) fn write_numeric_element(dst: &mut [u8], element_width: usize, value: u64) {
    match element_width {
        1 => dst[0] = value as u8,
        2 => dst[..2].copy_from_slice(&(value as u16).to_le_bytes()),
        4 => dst[..4].copy_from_slice(&(value as u32).to_le_bytes()),
        8 => dst[..8].copy_from_slice(&value.to_le_bytes()),
        _ => dst[..element_width].copy_from_slice(&value.to_le_bytes()[..element_width]),
    }
}

pub(super) fn validate_numeric_stream_width(element_width: usize, name: &str) -> Result<()> {
    if matches!(element_width, 1 | 2 | 4 | 8) {
        Ok(())
    } else {
        Err(Error::new(ErrorKind::InvalidType).with_detail(format!("{name} width is unsupported")))
    }
}

pub(super) fn numeric_element_count(bytes: &[u8], element_width: usize) -> Result<usize> {
    if !bytes.len().is_multiple_of(element_width) {
        return Err(
            Error::new(ErrorKind::Malformed).with_detail("numeric stream has partial element")
        );
    }
    Ok(bytes.len() / element_width)
}

#[expect(
    clippy::inline_always,
    reason = "profiled CSV dispatch/tag hot path benefits from inlining this leaf"
)]
#[inline(always)]
pub(super) fn read_usize_numeric_element(
    bytes: &[u8],
    element_width: usize,
    index: usize,
) -> Result<usize> {
    let start = index
        .checked_mul(element_width)
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
    let value = match element_width {
        1 => usize::from(*bytes.get(start).ok_or_else(|| {
            Error::new(ErrorKind::Malformed).with_detail("numeric stream is truncated")
        })?),
        2 => usize::from(read_u16_element(bytes, index)?),
        4 => usize::try_from(read_u32_element(bytes, index)?).map_err(|_| {
            Error::new(ErrorKind::LimitExceeded).with_detail("numeric value is too large")
        })?,
        8 => {
            let element = bytes.get(start..start + 8).ok_or_else(|| {
                Error::new(ErrorKind::Malformed).with_detail("numeric stream is truncated")
            })?;
            u64::from_le_bytes([
                element[0], element[1], element[2], element[3], element[4], element[5], element[6],
                element[7],
            ])
            .try_into()
            .map_err(|_| {
                Error::new(ErrorKind::LimitExceeded).with_detail("numeric value is too large")
            })?
        }
        _ => {
            return Err(
                Error::new(ErrorKind::InvalidType).with_detail("numeric width is unsupported")
            );
        }
    };
    Ok(value)
}

#[inline]
pub(super) fn read_u16_element(bytes: &[u8], index: usize) -> Result<u16> {
    let start = index
        .checked_mul(2)
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
    let element = bytes.get(start..start + 2).ok_or_else(|| {
        Error::new(ErrorKind::Malformed).with_detail("numeric stream is truncated")
    })?;
    Ok(u16::from_le_bytes([element[0], element[1]]))
}

#[inline]
pub(super) fn read_u32_element(bytes: &[u8], index: usize) -> Result<u32> {
    let start = index
        .checked_mul(4)
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
    let element = bytes.get(start..start + 4).ok_or_else(|| {
        Error::new(ErrorKind::Malformed).with_detail("numeric stream is truncated")
    })?;
    Ok(u32::from_le_bytes([
        element[0], element[1], element[2], element[3],
    ]))
}

pub(super) fn checked_sum_u32(values: &[u32]) -> Result<usize> {
    let mut total = 0usize;
    for &value in values {
        let value = usize::try_from(value)
            .map_err(|_| Error::new(ErrorKind::LimitExceeded).with_detail("value is too large"))?;
        total = total
            .checked_add(value)
            .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
    }
    Ok(total)
}

pub(super) fn require_numeric_width(
    stream: &StreamInput<'_>,
    expected: usize,
    name: &str,
) -> Result<()> {
    if stream.element_width != expected {
        return Err(
            Error::new(ErrorKind::InvalidType).with_detail(format!("{name} width is unsupported"))
        );
    }
    numeric_element_count(stream.bytes, expected)?;
    Ok(())
}

pub(super) fn read_var_u64(input: &[u8], offset: &mut usize) -> Result<u64> {
    let start = *offset;
    let mut value = 0u64;
    for index in 0..10 {
        let byte = *input
            .get(*offset)
            .ok_or_else(|| Error::at(ErrorKind::Truncated, *offset))?;
        *offset = (*offset)
            .checked_add(1)
            .ok_or_else(|| Error::at(ErrorKind::IntegerOverflow, *offset))?;
        let payload = u64::from(byte & 0x7f);
        if index == 9 && payload > 1 {
            return Err(Error::at(ErrorKind::IntegerOverflow, start)
                .with_detail("u64 varint payload overflows"));
        }
        let shift = index * 7;
        let shifted = payload
            .checked_shl(shift)
            .ok_or_else(|| Error::at(ErrorKind::IntegerOverflow, start))?;
        value = value
            .checked_add(shifted)
            .ok_or_else(|| Error::at(ErrorKind::IntegerOverflow, start))?;
        if byte & 0x80 == 0 {
            return Ok(value);
        }
    }
    Err(Error::at(ErrorKind::Malformed, start).with_detail("u64 varint is too long"))
}
