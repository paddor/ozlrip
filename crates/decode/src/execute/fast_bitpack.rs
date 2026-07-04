#![cfg_attr(feature = "paranoid", forbid(unsafe_code))]
#![allow(
    clippy::cast_possible_truncation,
    clippy::ptr_as_ptr,
    reason = "non-paranoid bitpack fast paths validate bit widths before unchecked writes"
)]

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

    #[cfg(not(feature = "paranoid"))]
    {
        unpack_lsb_bits_fast(stored, bits, element_width, elements, output)
    }
    #[cfg(feature = "paranoid")]
    {
        unpack_lsb_bits_safe(stored, bits, element_width, elements, output)
    }
}

#[cfg(feature = "paranoid")]
fn unpack_lsb_bits_safe(
    stored: &[u8],
    bits: usize,
    element_width: usize,
    elements: usize,
    output: &mut Vec<u8>,
) -> Result<()> {
    if element_width == 2 && bits < 16 {
        return unpack_lsb_bits_u16_window_safe(stored, bits, elements, output);
    }

    let start = output.len();
    let output_len = elements
        .checked_mul(element_width)
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
    output.resize(start + output_len, 0);
    let out = &mut output[start..start + output_len];
    if bits <= 56 {
        return unpack_lsb_bits_u64_safe(stored, bits, element_width, out);
    }
    unpack_lsb_bits_u128_safe(stored, bits, element_width, out)
}

#[cfg(feature = "paranoid")]
fn unpack_lsb_bits_u16_window_safe(
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

    for (element, out) in output[start..].chunks_exact_mut(2).enumerate() {
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

#[cfg(not(feature = "paranoid"))]
fn unpack_lsb_bits_fast(
    stored: &[u8],
    bits: usize,
    element_width: usize,
    elements: usize,
    output: &mut Vec<u8>,
) -> Result<()> {
    let output_len = elements
        .checked_mul(element_width)
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
    debug_assert!(output.capacity() >= output.len() + output_len);
    if element_width == 2 && bits < 16 {
        return unpack_lsb_bits_u16_window_fast(stored, bits, elements, output);
    }
    if bits <= 56 {
        return unpack_lsb_bits_u64_fast(stored, bits, element_width, elements, output);
    }
    unpack_lsb_bits_u128_fast(stored, bits, element_width, elements, output)
}

#[cfg(not(feature = "paranoid"))]
fn unpack_lsb_bits_u16_window_fast(
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
    let start_len = output.len();
    let output_len = elements
        .checked_mul(2)
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;

    unsafe {
        let mut out = output.as_mut_ptr().add(start_len);
        for element in 0..elements {
            let bit_index = element * bits;
            let byte_index = bit_index / 8;
            let shift = bit_index & 7;
            let value = if stored.len() - byte_index >= 4 {
                let word = (stored.as_ptr().add(byte_index) as *const u32).read_unaligned();
                u32::from_le(word) >> shift
            } else {
                let mut word = 0u32;
                for (offset, &byte) in stored[byte_index..].iter().enumerate() {
                    word |= u32::from(byte) << (offset * 8);
                }
                word >> shift
            } & mask;
            (out as *mut u16).write_unaligned((value as u16).to_le());
            out = out.add(2);
        }
        output.set_len(start_len + output_len);
    }
    Ok(())
}

#[cfg(not(feature = "paranoid"))]
fn unpack_lsb_bits_u64_fast(
    stored: &[u8],
    bits: usize,
    element_width: usize,
    elements: usize,
    output: &mut Vec<u8>,
) -> Result<()> {
    let mask = (1u64 << bits) - 1;
    let start_len = output.len();
    let output_len = elements
        .checked_mul(element_width)
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
    let mut byte_index = 0usize;
    let mut bit_buffer = 0u64;
    let mut available_bits = 0usize;

    unsafe {
        let mut out = output.as_mut_ptr().add(start_len);
        for _ in 0..elements {
            while available_bits < bits {
                let byte = *stored.get(byte_index).ok_or_else(|| {
                    Error::new(ErrorKind::Malformed).with_detail("bitpack input is truncated")
                })?;
                bit_buffer |= u64::from(byte) << available_bits;
                available_bits += 8;
                byte_index += 1;
            }
            write_value(&mut out, bit_buffer & mask, element_width);
            bit_buffer >>= bits;
            available_bits -= bits;
        }
        output.set_len(start_len + output_len);
    }
    Ok(())
}

#[cfg(not(feature = "paranoid"))]
fn unpack_lsb_bits_u128_fast(
    stored: &[u8],
    bits: usize,
    element_width: usize,
    elements: usize,
    output: &mut Vec<u8>,
) -> Result<()> {
    let mask = (1u128 << bits) - 1;
    let start_len = output.len();
    let output_len = elements
        .checked_mul(element_width)
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
    let mut byte_index = 0usize;
    let mut bit_buffer = 0u128;
    let mut available_bits = 0usize;

    unsafe {
        let mut out = output.as_mut_ptr().add(start_len);
        for _ in 0..elements {
            while available_bits < bits {
                let byte = *stored.get(byte_index).ok_or_else(|| {
                    Error::new(ErrorKind::Malformed).with_detail("bitpack input is truncated")
                })?;
                bit_buffer |= u128::from(byte) << available_bits;
                available_bits += 8;
                byte_index += 1;
            }
            write_value(&mut out, (bit_buffer & mask) as u64, element_width);
            bit_buffer >>= bits;
            available_bits -= bits;
        }
        output.set_len(start_len + output_len);
    }
    Ok(())
}

#[cfg(not(feature = "paranoid"))]
unsafe fn write_value(out: &mut *mut u8, value: u64, element_width: usize) {
    match element_width {
        1 => unsafe {
            (*out).write(value as u8);
            *out = (*out).add(1);
        },
        2 => unsafe {
            (*out as *mut u16).write_unaligned((value as u16).to_le());
            *out = (*out).add(2);
        },
        4 => unsafe {
            (*out as *mut u32).write_unaligned((value as u32).to_le());
            *out = (*out).add(4);
        },
        8 => unsafe {
            (*out as *mut u64).write_unaligned(value.to_le());
            *out = (*out).add(8);
        },
        _ => unreachable!("validated bitpack element width"),
    }
}

#[cfg(feature = "paranoid")]
fn unpack_lsb_bits_u64_safe(
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
        write_value_safe(out, value, element_width);
        bit_buffer >>= bits;
        available_bits -= bits;
    }
    Ok(())
}

#[cfg(feature = "paranoid")]
fn unpack_lsb_bits_u128_safe(
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
        write_value_safe(out, value as u64, element_width);
        bit_buffer >>= bits;
        available_bits -= bits;
    }
    Ok(())
}

#[cfg(feature = "paranoid")]
#[inline(always)]
fn write_value_safe(out: &mut [u8], value: u64, element_width: usize) {
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
