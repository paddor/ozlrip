use alloc::vec::Vec;

use ozlrip_core::{Error, ErrorKind, Result};

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

    let start = output.len();
    let output_len = elements
        .checked_mul(element_width)
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
    output.resize(start + output_len, 0);
    let out = &mut output[start..start + output_len];
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
    let start = output.len();
    let output_len = elements
        .checked_mul(2)
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
    output.resize(start + output_len, 0);

    for (element, out) in output[start..]
        .as_chunks_mut::<2>()
        .0
        .iter_mut()
        .enumerate()
    {
        let bit_index = element * bits;
        let byte_index = bit_index / 8;
        let shift = bit_index & 7;
        let mut word = 0u32;
        if stored.len() - byte_index >= 4 {
            word = u32::from_le_bytes([
                stored[byte_index],
                stored[byte_index + 1],
                stored[byte_index + 2],
                stored[byte_index + 3],
            ]);
        } else {
            for (offset, &byte) in stored[byte_index..].iter().enumerate() {
                word |= u32::from(byte) << (offset * 8);
            }
        }
        let value = ((word >> shift) & mask) as u16;
        let bytes = value.to_le_bytes();
        out[0] = bytes[0];
        out[1] = bytes[1];
    }
    Ok(())
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
