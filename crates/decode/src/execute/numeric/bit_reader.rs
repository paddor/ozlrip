use ozlrip_core::{Error, ErrorKind, Result};

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
    #[expect(
        clippy::inline_always,
        reason = "profiled: when LLVM outlines this from read_u64, quantize and \
                  partition decoding lose 3-4% (lorem-serial-sample, era5)"
    )]
    #[inline(always)]
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
    #[expect(
        clippy::inline_always,
        reason = "profiled: quantize reads one value per element; outlined, era5 \
                  decodes 3% slower"
    )]
    #[inline(always)]
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
