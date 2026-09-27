use alloc::vec::Vec;

use ozlrip_core::{Error, ErrorKind, Result};
use smallvec::SmallVec;

pub(super) fn read_bitpacked_u32(
    reader: &mut Reader<'_>,
    count: usize,
    bits: usize,
) -> Result<Vec<u32>> {
    if bits > 32 {
        return Err(Error::new(ErrorKind::Malformed).with_detail("bitpacked width is too large"));
    }
    let bytes = bitpacked_bytes(count, bits)?;
    let packed = reader.read_slice(bytes)?;
    let mut out = Vec::new();
    out.try_reserve_exact(count).map_err(|_| {
        Error::new(ErrorKind::LimitExceeded).with_detail("bitpacked value allocation failed")
    })?;
    for index in 0..count {
        out.push(read_packed_value(packed, index, bits)?);
    }
    Ok(out)
}

pub(super) fn read_bitpacked_u32_inline<const N: usize>(
    reader: &mut Reader<'_>,
    count: usize,
    bits: usize,
) -> Result<SmallVec<[u32; N]>> {
    if bits > 32 {
        return Err(Error::new(ErrorKind::Malformed).with_detail("bitpacked width is too large"));
    }
    let bytes = bitpacked_bytes(count, bits)?;
    let packed = reader.read_slice(bytes)?;
    let mut out = SmallVec::new();
    out.try_reserve_exact(count).map_err(|_| {
        Error::new(ErrorKind::LimitExceeded).with_detail("bitpacked value allocation failed")
    })?;
    for index in 0..count {
        out.push(read_packed_value(packed, index, bits)?);
    }
    Ok(out)
}

pub(super) fn read_bitpacked_single_u32(reader: &mut Reader<'_>, bits: usize) -> Result<u32> {
    if bits > 32 {
        return Err(Error::new(ErrorKind::Malformed).with_detail("bitpacked width is too large"));
    }
    let bytes = bitpacked_bytes(1, bits)?;
    let packed = reader.read_slice(bytes)?;
    read_packed_value(packed, 0, bits)
}

#[cfg(feature = "zstd")]
pub(super) fn read_single_low_bits_u32(reader: &mut Reader<'_>, bits: usize) -> Result<u32> {
    if bits > 8 {
        return read_bitpacked_single_u32(reader, bits);
    }
    if bits == 0 {
        return Ok(0);
    }
    let byte = reader.read_byte()?;
    let mask = (1u16 << bits) - 1;
    Ok(u32::from(u16::from(byte) & mask))
}

pub(super) fn read_packed_value(bytes: &[u8], index: usize, bits: usize) -> Result<u32> {
    if bits == 0 {
        return Ok(0);
    }
    let bit_offset = checked_mul(index, bits)?;
    let byte_start = bit_offset / 8;
    let shift = bit_offset % 8;
    let needed_bits = checked_add(bits, shift)?;
    let needed_bytes = bitpacked_bytes(1, needed_bits)?;
    let mut word = 0u64;
    for offset in 0..needed_bytes {
        let byte = *bytes
            .get(checked_add(byte_start, offset)?)
            .ok_or_else(|| Error::new(ErrorKind::Truncated))?;
        let shift = u32::try_from(checked_mul(offset, 8)?)
            .map_err(|_| Error::new(ErrorKind::IntegerOverflow))?;
        word |= u64::from(byte) << shift;
    }
    let mask = if bits == 32 {
        u64::from(u32::MAX)
    } else {
        (1u64 << bits) - 1
    };
    u32::try_from((word >> shift) & mask).map_err(|_| Error::new(ErrorKind::IntegerOverflow))
}

pub(super) fn bitpacked_bytes(count: usize, bits: usize) -> Result<usize> {
    checked_add(checked_mul(count, bits)?, 7).map(|bits| bits / 8)
}

pub(super) fn bits_needed(max_value: usize) -> usize {
    if max_value <= 1 {
        0
    } else {
        usize::BITS as usize - (max_value - 1).leading_zeros() as usize
    }
}

pub(super) fn check_limit(value: usize, limit: usize, kind: ErrorKind) -> Result<()> {
    if value > limit {
        return Err(Error::new(kind).with_detail("configured limit exceeded"));
    }
    Ok(())
}

pub(super) fn checked_add(lhs: usize, rhs: usize) -> Result<usize> {
    lhs.checked_add(rhs)
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))
}

pub(super) fn checked_mul(lhs: usize, rhs: usize) -> Result<usize> {
    lhs.checked_mul(rhs)
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))
}

pub(super) fn sum_u32_as_usize(values: &[u32]) -> Result<usize> {
    let mut total = 0usize;
    for &value in values {
        let value = usize::try_from(value).map_err(|_| Error::new(ErrorKind::LimitExceeded))?;
        total = checked_add(total, value)?;
    }
    Ok(total)
}

pub(super) fn sum_usize(values: &[usize]) -> Result<usize> {
    let mut total = 0usize;
    for &value in values {
        total = checked_add(total, value)?;
    }
    Ok(total)
}

pub(super) struct Reader<'a> {
    pub(super) bytes: &'a [u8],
    pub(super) offset: usize,
}

impl<'a> Reader<'a> {
    pub(super) const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    pub(super) const fn offset(&self) -> usize {
        self.offset
    }

    pub(super) const fn is_empty(&self) -> bool {
        self.offset >= self.bytes.len()
    }

    pub(super) fn read_slice(&mut self, len: usize) -> Result<&'a [u8]> {
        let end = self
            .offset
            .checked_add(len)
            .ok_or_else(|| Error::at(ErrorKind::IntegerOverflow, self.offset))?;
        let slice = self
            .bytes
            .get(self.offset..end)
            .ok_or_else(|| Error::at(ErrorKind::Truncated, self.offset))?;
        self.offset = end;
        Ok(slice)
    }

    pub(super) fn read_byte(&mut self) -> Result<u8> {
        let byte = self.peek_byte()?;
        self.offset = self
            .offset
            .checked_add(1)
            .ok_or_else(|| Error::at(ErrorKind::IntegerOverflow, self.offset))?;
        Ok(byte)
    }

    pub(super) fn peek_byte(&self) -> Result<u8> {
        self.bytes
            .get(self.offset)
            .copied()
            .ok_or_else(|| Error::at(ErrorKind::Truncated, self.offset))
    }

    pub(super) fn read_u16_le(&mut self) -> Result<u16> {
        let bytes = self.read_array::<2>()?;
        Ok(u16::from_le_bytes(bytes))
    }

    pub(super) fn read_u32_le(&mut self) -> Result<u32> {
        let bytes = self.read_array::<4>()?;
        Ok(u32::from_le_bytes(bytes))
    }

    pub(super) fn read_array<const N: usize>(&mut self) -> Result<[u8; N]> {
        let slice = self.read_slice(N)?;
        let mut out = [0; N];
        out.copy_from_slice(slice);
        Ok(out)
    }

    pub(super) fn read_var_u64(&mut self) -> Result<u64> {
        let start = self.offset;
        let mut value = 0u64;
        let mut shift = 0u32;
        for index in 0..10 {
            let absolute = start
                .checked_add(index)
                .ok_or_else(|| Error::at(ErrorKind::IntegerOverflow, start))?;
            let byte = *self
                .bytes
                .get(absolute)
                .ok_or_else(|| Error::at(ErrorKind::Truncated, absolute))?;
            let payload = u64::from(byte & 0x7f);
            if index == 9 && payload > 1 {
                return Err(Error::at(ErrorKind::IntegerOverflow, start)
                    .with_detail("u64 varint payload overflows"));
            }
            value |= payload << shift;
            if byte & 0x80 == 0 {
                self.offset = absolute
                    .checked_add(1)
                    .ok_or_else(|| Error::at(ErrorKind::IntegerOverflow, absolute))?;
                return Ok(value);
            }
            shift += 7;
        }
        Err(Error::at(ErrorKind::Malformed, start).with_detail("u64 varint is too long"))
    }
}
