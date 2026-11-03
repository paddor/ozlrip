use alloc::vec::Vec;

use ozlrip_core::{Error, ErrorKind, Result};

/// Replaces `output` with the unpacked elements. `output` may hold stale
/// bytes: every byte is overwritten. On error `output` holds unspecified
/// bytes.
pub(super) fn unpack_lsb_bits(
    stored: &[u8],
    bits: usize,
    element_width: usize,
    elements: usize,
    output: &mut Vec<u8>,
) -> Result<()> {
    let output_len = elements
        .checked_mul(element_width)
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
    let full_width_bits = element_width
        .checked_mul(8)
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
    if bits == full_width_bits {
        let src = stored.get(..output_len).ok_or_else(|| {
            Error::new(ErrorKind::Malformed).with_detail("bitpack input is truncated")
        })?;
        output.clear();
        output.extend_from_slice(src);
        return Ok(());
    }

    unpack_lsb_bits_packed(stored, bits, element_width, elements, output)
}

fn unpack_lsb_bits_packed(
    stored: &[u8],
    bits: usize,
    element_width: usize,
    elements: usize,
    output: &mut Vec<u8>,
) -> Result<()> {
    if element_width == 2 && bits < 16 {
        return unpack_lsb_bits_u16_window(stored, bits, elements, output);
    }

    let output_len = elements
        .checked_mul(element_width)
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
    output.resize(output_len, 0);
    let out = output.as_mut_slice();
    if bits <= 56 {
        return unpack_lsb_bits_u64(stored, bits, element_width, out);
    }
    unpack_lsb_bits_u128(stored, bits, element_width, out)
}

#[expect(
    clippy::cast_possible_truncation,
    reason = "the mask keeps values below 2^16"
)]
fn unpack_lsb_bits_u16_window(
    stored: &[u8],
    bits: usize,
    elements: usize,
    output: &mut Vec<u8>,
) -> Result<()> {
    let required_bits = elements
        .checked_mul(bits)
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
    let required_bytes = required_bits.div_ceil(8);
    if stored.len() < required_bytes {
        return Err(Error::new(ErrorKind::Malformed).with_detail("bitpack input is truncated"));
    }

    let mask = (1u32 << bits) - 1;
    let output_len = elements
        .checked_mul(2)
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
    output.resize(output_len, 0);

    let mut bit_index = 0usize;
    for out in output.as_chunks_mut::<2>().0 {
        let byte_index = bit_index / 8;
        // One check and one load per element; only the last few elements
        // read a short window.
        let word = match stored.get(byte_index..).and_then(<[u8]>::first_chunk::<4>) {
            Some(window) => u32::from_le_bytes(*window),
            None => short_window(stored, byte_index),
        };
        *out = (((word >> (bit_index & 7)) & mask) as u16).to_le_bytes();
        bit_index += bits;
    }
    Ok(())
}

/// The little-endian bytes from `byte_index` to the end of `stored`, fewer
/// than four.
#[cold]
fn short_window(stored: &[u8], byte_index: usize) -> u32 {
    stored
        .get(byte_index..)
        .unwrap_or_default()
        .iter()
        .rev()
        .fold(0, |word, &byte| (word << 8) | u32::from(byte))
}

fn unpack_lsb_bits_u64(
    stored: &[u8],
    bits: usize,
    element_width: usize,
    output: &mut [u8],
) -> Result<()> {
    let mask = (1u64 << bits) - 1;
    let mut byte_index = 0usize;
    let mut bit_buffer = 0u64;
    let mut available_bits = 0usize;

    for out in output.chunks_exact_mut(element_width) {
        while available_bits < bits {
            let byte = *stored.get(byte_index).ok_or_else(|| {
                Error::new(ErrorKind::Malformed).with_detail("bitpack input is truncated")
            })?;
            bit_buffer |= u64::from(byte) << available_bits;
            available_bits += 8;
            byte_index += 1;
        }
        let value = bit_buffer & mask;
        write_value(out, value, element_width);
        bit_buffer >>= bits;
        available_bits -= bits;
    }
    Ok(())
}

#[expect(
    clippy::cast_possible_truncation,
    reason = "the mask keeps values within 64 bits"
)]
fn unpack_lsb_bits_u128(
    stored: &[u8],
    bits: usize,
    element_width: usize,
    output: &mut [u8],
) -> Result<()> {
    let mask = (1u128 << bits) - 1;
    let mut byte_index = 0usize;
    let mut bit_buffer = 0u128;
    let mut available_bits = 0usize;

    for out in output.chunks_exact_mut(element_width) {
        while available_bits < bits {
            let byte = *stored.get(byte_index).ok_or_else(|| {
                Error::new(ErrorKind::Malformed).with_detail("bitpack input is truncated")
            })?;
            bit_buffer |= u128::from(byte) << available_bits;
            available_bits += 8;
            byte_index += 1;
        }
        let value = bit_buffer & mask;
        write_value(out, value as u64, element_width);
        bit_buffer >>= bits;
        available_bits -= bits;
    }
    Ok(())
}

#[expect(
    clippy::inline_always,
    reason = "bitpack writes one tiny scalar per decoded value"
)]
#[inline(always)]
fn write_value(out: &mut [u8], value: u64, element_width: usize) {
    let bytes = value.to_le_bytes();
    match element_width {
        1 => out[0] = bytes[0],
        2 => {
            out[0] = bytes[0];
            out[1] = bytes[1];
        }
        4 => {
            out[0] = bytes[0];
            out[1] = bytes[1];
            out[2] = bytes[2];
            out[3] = bytes[3];
        }
        8 => {
            out[0] = bytes[0];
            out[1] = bytes[1];
            out[2] = bytes[2];
            out[3] = bytes[3];
            out[4] = bytes[4];
            out[5] = bytes[5];
            out[6] = bytes[6];
            out[7] = bytes[7];
        }
        _ => unreachable!("validated bitpack element width"),
    }
}

#[cfg(test)]
mod tests {
    use alloc::{vec, vec::Vec};

    use super::unpack_lsb_bits;

    /// Packs `values` LSB first, `bits` bits each.
    fn pack(values: &[u64], bits: usize) -> Vec<u8> {
        let mut packed = vec![0u8; (values.len() * bits).div_ceil(8)];
        for (element, &value) in values.iter().enumerate() {
            for bit in 0..bits {
                if value >> bit & 1 == 1 {
                    let index = element * bits + bit;
                    packed[index / 8] |= 1 << (index % 8);
                }
            }
        }
        packed
    }

    #[test]
    fn unpacks_every_width_and_tail_length_over_stale_output() {
        let mut seed = 0x9e37_79b9_7f4a_7c15u64;
        for (element_width, max_bits) in [(1, 8), (2, 16), (4, 32), (8, 64)] {
            for bits in 1..=max_bits {
                for elements in 0..40 {
                    let values: Vec<u64> = (0..elements)
                        .map(|_| {
                            seed = seed.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
                            (seed >> 7) & (u64::MAX >> (64 - bits))
                        })
                        .collect();
                    let expected: Vec<u8> = values
                        .iter()
                        .flat_map(|value| value.to_le_bytes()[..element_width].to_vec())
                        .collect();
                    // Stale bytes both longer and shorter than the output.
                    let mut output = vec![0xa5; 3 * elements + 5];

                    unpack_lsb_bits(
                        &pack(&values, bits),
                        bits,
                        element_width,
                        elements,
                        &mut output,
                    )
                    .unwrap();

                    assert_eq!(
                        output, expected,
                        "width {element_width} bits {bits} n {elements}"
                    );
                }
            }
        }
    }

    #[test]
    fn rejects_truncated_u16_window_input() {
        let mut output = Vec::new();

        let err = unpack_lsb_bits(&[0xff], 5, 2, 2, &mut output).unwrap_err();

        assert_eq!(err.kind(), ozlrip_core::ErrorKind::Malformed);
    }
}
