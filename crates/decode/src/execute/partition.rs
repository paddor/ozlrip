use alloc::vec::Vec;

use ozlrip_core::{Error, ErrorKind, Limits, Result};

use super::{
    OwnedStream, StreamInput, fast_partition, max_numeric_value, read_var_u64,
    require_numeric_width,
};

pub(super) struct QuantizeParams {
    bits: &'static [u8],
    base: &'static [u32],
}

const QUANTIZE_OFFSETS_BITS: [u8; 32] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
    26, 27, 28, 29, 30, 31,
];
const QUANTIZE_OFFSETS_BASE: [u32; 32] = [
    0x1,
    0x2,
    0x4,
    0x8,
    0x10,
    0x20,
    0x40,
    0x80,
    0x100,
    0x200,
    0x400,
    0x800,
    0x1000,
    0x2000,
    0x4000,
    0x8000,
    0x1_0000,
    0x2_0000,
    0x4_0000,
    0x8_0000,
    0x10_0000,
    0x20_0000,
    0x40_0000,
    0x80_0000,
    0x100_0000,
    0x200_0000,
    0x400_0000,
    0x800_0000,
    0x1000_0000,
    0x2000_0000,
    0x4000_0000,
    0x8000_0000,
];
const QUANTIZE_LENGTHS_BITS: [u8; 44] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
    17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
];
const QUANTIZE_LENGTHS_BASE: [u32; 44] = [
    0,
    1,
    2,
    3,
    4,
    5,
    6,
    7,
    8,
    9,
    10,
    11,
    12,
    13,
    14,
    15,
    0x10,
    0x20,
    0x40,
    0x80,
    0x100,
    0x200,
    0x400,
    0x800,
    0x1000,
    0x2000,
    0x4000,
    0x8000,
    0x1_0000,
    0x2_0000,
    0x4_0000,
    0x8_0000,
    0x10_0000,
    0x20_0000,
    0x40_0000,
    0x80_0000,
    0x100_0000,
    0x200_0000,
    0x400_0000,
    0x800_0000,
    0x1000_0000,
    0x2000_0000,
    0x4000_0000,
    0x8000_0000,
];
pub(super) const QUANTIZE_OFFSETS: QuantizeParams = QuantizeParams {
    bits: &QUANTIZE_OFFSETS_BITS,
    base: &QUANTIZE_OFFSETS_BASE,
};
pub(super) const QUANTIZE_LENGTHS: QuantizeParams = QuantizeParams {
    bits: &QUANTIZE_LENGTHS_BITS,
    base: &QUANTIZE_LENGTHS_BASE,
};

pub(super) fn decode_quantize_node(
    inputs: &[StreamInput<'_>],
    header: &[u8],
    limits: Limits,
    params: &QuantizeParams,
) -> Result<OwnedStream> {
    if !header.is_empty() {
        return Err(
            Error::new(ErrorKind::Unsupported).with_detail("quantize headers are unsupported")
        );
    }
    let [codes, extra_bits] = inputs else {
        return Err(Error::new(ErrorKind::InvalidGraph)
            .with_detail("quantize input count does not match node shape"));
    };
    require_numeric_width(codes, 1, "quantize codes")?;
    if extra_bits.element_width != 1 {
        return Err(Error::new(ErrorKind::InvalidType).with_detail("quantize bits must be serial"));
    }
    let output_len = codes
        .bytes
        .len()
        .checked_mul(4)
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
    if output_len > limits.max_decoded_bytes || output_len > limits.max_buffer_bytes {
        return Err(
            Error::new(ErrorKind::LimitExceeded).with_detail("decoded output limit exceeded")
        );
    }

    let mut base_table = [0u32; 256];
    let mut bit_table = [u8::MAX; 256];
    for (code, (&bits, &base)) in params.bits.iter().zip(params.base).enumerate() {
        base_table[code] = base;
        bit_table[code] = bits;
    }

    let mut reader = ForwardBitReader::new(extra_bits.bytes);
    let mut output = Vec::new();
    output.try_reserve_exact(output_len).map_err(|_| {
        Error::new(ErrorKind::LimitExceeded).with_detail("quantize allocation failed")
    })?;
    output.resize(output_len, 0);
    let mut out_pos = 0usize;
    for &code in codes.bytes {
        let code_index = usize::from(code);
        let bits = bit_table[code_index];
        if bits == u8::MAX {
            return Err(
                Error::new(ErrorKind::Malformed).with_detail("quantize code is out of range")
            );
        }
        let base = base_table[code_index];
        let extra = reader.read_u32(bits)?;
        let value = base
            .checked_add(extra)
            .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
        output[out_pos..out_pos + 4].copy_from_slice(&value.to_le_bytes());
        out_pos += 4;
    }
    reader.finish_zero_padding()?;
    Ok(OwnedStream {
        bytes: output,
        element_width: 4,
        string_lengths: None,
        recyclable: false,
    })
}

const PARTITION_MAX_PARTITIONS: usize = 256;
const PARTITION_HEADER_IS_PRESET_BIT: u8 = 0x04;
const PARTITION_HEADER_IS_FIRST_VALUE_ZERO_BIT: u8 = 0x08;
const PARTITION_HEADER_IS_POW2_BIT: u8 = 0x20;

const PARTITION_QUANTIZE_OFFSETS_SIZES: [u64; 32] = [
    0x1,
    0x2,
    0x4,
    0x8,
    0x10,
    0x20,
    0x40,
    0x80,
    0x100,
    0x200,
    0x400,
    0x800,
    0x1000,
    0x2000,
    0x4000,
    0x8000,
    0x1_0000,
    0x2_0000,
    0x4_0000,
    0x8_0000,
    0x10_0000,
    0x20_0000,
    0x40_0000,
    0x80_0000,
    0x100_0000,
    0x200_0000,
    0x400_0000,
    0x800_0000,
    0x1000_0000,
    0x2000_0000,
    0x4000_0000,
    0x8000_0000,
];
const PARTITION_QUANTIZE_LENGTHS_SIZES: [u64; 44] = [
    0x1,
    0x1,
    0x1,
    0x1,
    0x1,
    0x1,
    0x1,
    0x1,
    0x1,
    0x1,
    0x1,
    0x1,
    0x1,
    0x1,
    0x1,
    0x1,
    0x10,
    0x20,
    0x40,
    0x80,
    0x100,
    0x200,
    0x400,
    0x800,
    0x1000,
    0x2000,
    0x4000,
    0x8000,
    0x10000,
    0x20000,
    0x4_0000,
    0x8_0000,
    0x10_0000,
    0x20_0000,
    0x40_0000,
    0x80_0000,
    0x100_0000,
    0x200_0000,
    0x400_0000,
    0x800_0000,
    0x1000_0000,
    0x2000_0000,
    0x4000_0000,
    0x8000_0000,
];
const PARTITION_VARBYTE16_SIZES: [u64; 16] = [
    0x2, 0x2, 0x4, 0x8, 0x10, 0x20, 0x40, 0x80, 0x100, 0x200, 0x400, 0x800, 0x1000, 0x2000, 0x4000,
    0x8000,
];

struct PartitionParams {
    start_value: u64,
    sizes: Vec<u64>,
}

#[inline(never)]
pub(super) fn decode_partition_node(
    inputs: &[StreamInput<'_>],
    header: &[u8],
    limits: Limits,
) -> Result<OwnedStream> {
    let [buckets, offsets] = inputs else {
        return Err(Error::new(ErrorKind::InvalidGraph)
            .with_detail("partition input count does not match node shape"));
    };
    require_numeric_width(buckets, 1, "partition buckets")?;
    if offsets.element_width != 1 {
        return Err(Error::new(ErrorKind::InvalidType).with_detail("partition bits must be serial"));
    }

    let (params, element_width) = parse_partition_header(header)?;
    let output_len = buckets
        .bytes
        .len()
        .checked_mul(element_width)
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
    if output_len > limits.max_decoded_bytes || output_len > limits.max_buffer_bytes {
        return Err(
            Error::new(ErrorKind::LimitExceeded).with_detail("decoded output limit exceeded")
        );
    }

    let bases = partition_bases(&params)?;
    let bits = partition_bits(&params)?;
    #[cfg(not(feature = "paranoid"))]
    if element_width == 4 {
        return fast_partition::decode_u32_node(
            buckets.bytes,
            offsets.bytes,
            &bases,
            &bits,
            output_len,
        );
    }
    #[cfg(feature = "paranoid")]
    if element_width == 4 {
        return fast_partition::decode_u32_node(
            buckets.bytes,
            offsets.bytes,
            &bases,
            &bits,
            output_len,
        );
    }

    let max_value = max_numeric_value(element_width)?;
    let mut reader = ForwardBitReader::new(offsets.bytes);
    let mut output = Vec::new();
    output.try_reserve_exact(output_len).map_err(|_| {
        Error::new(ErrorKind::LimitExceeded).with_detail("partition allocation failed")
    })?;

    for &bucket in buckets.bytes {
        let bucket = usize::from(bucket);
        let base = *bases.get(bucket).ok_or_else(|| {
            Error::new(ErrorKind::Malformed).with_detail("partition bucket is out of range")
        })?;
        let bit_width = *bits.get(bucket).ok_or_else(|| {
            Error::new(ErrorKind::Malformed).with_detail("partition bucket is out of range")
        })?;
        let offset = reader.read_u64(usize::from(bit_width))?;
        let value = base
            .checked_add(offset)
            .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
        if value > max_value {
            return Err(Error::new(ErrorKind::Malformed)
                .with_detail("partition value exceeds output element width"));
        }
        write_numeric_element_vec(&mut output, element_width, value);
    }

    Ok(OwnedStream {
        bytes: output,
        element_width,
        string_lengths: None,
        recyclable: false,
    })
}

fn parse_partition_header(header: &[u8]) -> Result<(PartitionParams, usize)> {
    let (&flags, mut rest) = header
        .split_first()
        .ok_or_else(|| Error::new(ErrorKind::Malformed).with_detail("partition header is empty"))?;
    let element_width = 1usize
        .checked_shl(u32::from(flags & 0x03))
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;

    let params = if (flags & PARTITION_HEADER_IS_PRESET_BIT) != 0 {
        if !rest.is_empty() {
            return Err(Error::new(ErrorKind::Malformed)
                .with_detail("partition preset header has trailing bytes"));
        }
        partition_preset(flags >> 3)?
    } else {
        let start_value = if (flags & PARTITION_HEADER_IS_FIRST_VALUE_ZERO_BIT) != 0 {
            0
        } else {
            read_var_u64_from_slice(&mut rest)?
        };
        let sizes = if (flags & PARTITION_HEADER_IS_POW2_BIT) != 0 {
            parse_partition_pow2_sizes(flags, rest)?
        } else {
            parse_partition_varint_sizes(rest)?
        };
        PartitionParams { start_value, sizes }
    };

    validate_partition_params(&params)?;
    Ok((params, element_width))
}

fn partition_preset(preset: u8) -> Result<PartitionParams> {
    let (start_value, sizes): (u64, &[u64]) = match preset {
        0 => (1, &PARTITION_QUANTIZE_OFFSETS_SIZES),
        1 => (0, &PARTITION_QUANTIZE_LENGTHS_SIZES),
        2 => (0, &PARTITION_VARBYTE16_SIZES),
        _ => {
            return Err(Error::new(ErrorKind::Malformed).with_detail("partition preset is unknown"));
        }
    };
    Ok(PartitionParams {
        start_value,
        sizes: sizes.to_vec(),
    })
}

fn parse_partition_pow2_sizes(flags: u8, bytes: &[u8]) -> Result<Vec<u64>> {
    if bytes.is_empty() {
        return Err(Error::new(ErrorKind::Malformed).with_detail("partition sizes are missing"));
    }
    let last = *bytes.last().unwrap_or(&0);
    if last == 0 {
        return Err(
            Error::new(ErrorKind::Malformed).with_detail("partition sizes bitstream is corrupt")
        );
    }
    let num_bits = usize::from(flags >> 6) + 3;
    let high_bit = usize::try_from(u8::BITS - 1 - last.leading_zeros())
        .map_err(|_| Error::new(ErrorKind::IntegerOverflow))?;
    let unused_bits = 8usize
        .checked_sub(high_bit)
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
    let total_bits = bytes
        .len()
        .checked_mul(8)
        .and_then(|bits| bits.checked_sub(unused_bits))
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
    if total_bits % num_bits != 0 {
        return Err(
            Error::new(ErrorKind::Malformed).with_detail("partition size bitstream is misaligned")
        );
    }
    let count = total_bits / num_bits;
    if count > PARTITION_MAX_PARTITIONS {
        return Err(Error::new(ErrorKind::Malformed).with_detail("partition count exceeds maximum"));
    }
    let mut reader = ForwardBitReader::new(bytes);
    let mut sizes = Vec::new();
    sizes.try_reserve_exact(count).map_err(|_| {
        Error::new(ErrorKind::LimitExceeded).with_detail("partition sizes allocation failed")
    })?;
    for _ in 0..count {
        let log2_size = reader.read_u64(num_bits)?;
        if log2_size >= u64::BITS.into() {
            return Err(
                Error::new(ErrorKind::Malformed).with_detail("partition size shift is invalid")
            );
        }
        sizes.push(1u64 << log2_size);
    }
    Ok(sizes)
}

fn parse_partition_varint_sizes(mut bytes: &[u8]) -> Result<Vec<u64>> {
    let mut sizes = Vec::new();
    while !bytes.is_empty() {
        if sizes.len() >= PARTITION_MAX_PARTITIONS {
            return Err(
                Error::new(ErrorKind::Malformed).with_detail("partition count exceeds maximum")
            );
        }
        sizes.push(read_var_u64_from_slice(&mut bytes)?);
    }
    Ok(sizes)
}

fn validate_partition_params(params: &PartitionParams) -> Result<()> {
    if params.sizes.is_empty()
        || params.sizes.len() > PARTITION_MAX_PARTITIONS
        || (params.sizes.len() == 1 && params.start_value == 0)
    {
        return Err(
            Error::new(ErrorKind::Malformed).with_detail("partition parameters are invalid")
        );
    }
    let mut sum = params.start_value;
    for (index, &size) in params.sizes.iter().enumerate() {
        if size == 0 {
            return Err(
                Error::new(ErrorKind::Malformed).with_detail("partition size must be nonzero")
            );
        }
        match sum.checked_add(size) {
            Some(next) => sum = next,
            None if index + 1 == params.sizes.len() => sum = sum.wrapping_add(size),
            None => {
                return Err(Error::new(ErrorKind::IntegerOverflow)
                    .with_detail("partition size sum overflowed"));
            }
        }
    }
    let _ = sum;
    Ok(())
}

fn partition_bases(params: &PartitionParams) -> Result<Vec<u64>> {
    let mut bases = Vec::new();
    bases.try_reserve_exact(params.sizes.len()).map_err(|_| {
        Error::new(ErrorKind::LimitExceeded).with_detail("partition bases allocation failed")
    })?;
    let mut base = params.start_value;
    for &size in &params.sizes {
        bases.push(base);
        base = base.wrapping_add(size);
    }
    Ok(bases)
}

fn partition_bits(params: &PartitionParams) -> Result<Vec<u8>> {
    let mut bits = Vec::new();
    bits.try_reserve_exact(params.sizes.len()).map_err(|_| {
        Error::new(ErrorKind::LimitExceeded).with_detail("partition bits allocation failed")
    })?;
    for &size in &params.sizes {
        let bit_width = if size <= 1 {
            0
        } else {
            u8::try_from(u64::BITS - (size - 1).leading_zeros())
                .map_err(|_| Error::new(ErrorKind::IntegerOverflow))?
        };
        bits.push(bit_width);
    }
    Ok(bits)
}

fn read_var_u64_from_slice(bytes: &mut &[u8]) -> Result<u64> {
    let mut offset = 0usize;
    let value = read_var_u64(bytes, &mut offset)?;
    *bytes = bytes
        .get(offset..)
        .ok_or_else(|| Error::new(ErrorKind::Malformed).with_detail("varint offset is invalid"))?;
    Ok(value)
}

#[expect(
    clippy::cast_possible_truncation,
    clippy::inline_always,
    reason = "profiled numeric decode paths pay measurable call overhead"
)]
#[inline(always)]
pub(super) fn write_numeric_element_vec(output: &mut Vec<u8>, element_width: usize, value: u64) {
    match element_width {
        1 => output.push(value as u8),
        2 => output.extend_from_slice(&(value as u16).to_le_bytes()),
        4 => output.extend_from_slice(&(value as u32).to_le_bytes()),
        8 => output.extend_from_slice(&value.to_le_bytes()),
        _ => unreachable!("numeric element width was validated"),
    }
}

/// Forward (least significant bit first) bit reader. Pending bits sit in a
/// 64-bit register, so most reads are a mask and a shift, and a refill
/// loads eight bytes at once while that many remain.
pub(super) struct ForwardBitReader<'a> {
    bytes: &'a [u8],
    /// Next byte to load into `container`.
    next_byte: usize,
    /// Pending bits, the next one at bit 0. Bits from `available` up may
    /// hold copies of the bytes from `next_byte` on, at the positions a
    /// later refill ORs them into, so that refill leaves them unchanged.
    container: u64,
    /// Number of pending bits in `container`.
    available: u32,
}

impl<'a> ForwardBitReader<'a> {
    pub(super) const fn new(bytes: &'a [u8]) -> Self {
        Self {
            bytes,
            next_byte: 0,
            container: 0,
            available: 0,
        }
    }

    /// Tops up `container` to at least 56 pending bits, or to every bit
    /// left in the input.
    fn refill(&mut self) {
        if let Some(word) = self
            .bytes
            .get(self.next_byte..)
            .and_then(<[u8]>::first_chunk::<8>)
        {
            debug_assert!(self.available < 64);
            self.container |= u64::from_le_bytes(*word) << self.available;
            let loaded = (63 - self.available) / 8;
            self.next_byte += loaded as usize;
            self.available += loaded * 8;
        } else {
            while self.available <= 56 {
                let Some(&byte) = self.bytes.get(self.next_byte) else {
                    break;
                };
                self.container |= u64::from(byte) << self.available;
                self.next_byte += 1;
                self.available += 8;
            }
        }
    }

    /// Reads up to 56 bits.
    fn take(&mut self, bits: u32) -> Result<u64> {
        debug_assert!(bits <= 56);
        if self.available < bits {
            self.refill();
            if self.available < bits {
                return Err(
                    Error::new(ErrorKind::Malformed).with_detail("forward bitstream is truncated")
                );
            }
        }
        let value = self.container & ((1u64 << bits) - 1);
        self.container >>= bits;
        self.available -= bits;
        Ok(value)
    }

    /// Reads up to 32 bits.
    #[expect(
        clippy::cast_possible_truncation,
        reason = "take masks the value to at most 32 bits"
    )]
    pub(super) fn read_u32(&mut self, bits: u8) -> Result<u32> {
        debug_assert!(bits <= 32);
        Ok(self.take(u32::from(bits))? as u32)
    }

    pub(super) fn read_u64(&mut self, bits: usize) -> Result<u64> {
        let Ok(bits @ 0..=64) = u32::try_from(bits) else {
            return Err(
                Error::new(ErrorKind::Malformed).with_detail("forward bit width is unsupported")
            );
        };
        if bits <= 56 {
            return self.take(bits);
        }
        let low = self.take(32)?;
        let high = self.take(bits - 32)?;
        Ok(low | (high << 32))
    }

    /// Checks that every bit after the last read is zero.
    pub(super) fn finish_zero_padding(&self) -> Result<()> {
        let pending = if self.available >= 64 {
            self.container
        } else {
            self.container & ((1u64 << self.available) - 1)
        };
        if pending != 0 || self.bytes[self.next_byte..].iter().any(|&byte| byte != 0) {
            return Err(Error::new(ErrorKind::Malformed)
                .with_detail("forward bitstream has nonzero padding"));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::ForwardBitReader;
    use alloc::vec::Vec;

    /// Bit `index` of `bytes`, least significant bit first.
    fn bit(bytes: &[u8], index: usize) -> u64 {
        u64::from((bytes[index / 8] >> (index % 8)) & 1)
    }

    /// Reads of every width from 0 to 64, at every alignment, match a
    /// bit-by-bit reference, across the eight-byte refill boundary and the
    /// byte-by-byte tail.
    #[test]
    fn reads_match_bit_by_bit_reference() {
        let mut seed = 0x9e37_79b9_u32;
        let bytes: Vec<u8> = (0..64)
            .map(|_| {
                seed = seed.wrapping_mul(1_103_515_245).wrapping_add(12_345);
                (seed >> 24) as u8
            })
            .collect();
        for skip in 0..8 {
            for bits in 0..=64 {
                let mut reader = ForwardBitReader::new(&bytes);
                reader.read_u64(skip).unwrap();
                let mut pos = skip;
                while pos + bits <= bytes.len() * 8 {
                    let expected = (0..bits).fold(0u64, |acc, k| acc | (bit(&bytes, pos + k) << k));
                    assert_eq!(
                        reader.read_u64(bits).unwrap(),
                        expected,
                        "skip={skip} bits={bits} pos={pos}"
                    );
                    pos += bits;
                    if bits == 0 {
                        break;
                    }
                }
                if bits > 0 {
                    assert!(
                        reader.read_u64(bits).is_err(),
                        "skip={skip} bits={bits} past the end"
                    );
                }
            }
        }
    }

    #[test]
    fn checks_zero_padding_in_register_and_unread_bytes() {
        let bytes = [0b0000_0101, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let mut reader = ForwardBitReader::new(&bytes);
        assert_eq!(reader.read_u32(3).unwrap(), 0b101);
        reader.finish_zero_padding().unwrap();

        let mut reader = ForwardBitReader::new(&bytes);
        assert_eq!(reader.read_u32(2).unwrap(), 0b01);
        assert!(reader.finish_zero_padding().is_err());

        let bytes = [0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let mut reader = ForwardBitReader::new(&bytes);
        assert_eq!(reader.read_u32(3).unwrap(), 0);
        assert!(reader.finish_zero_padding().is_err());
    }
}
