#![cfg_attr(feature = "paranoid", forbid(unsafe_code))]

use alloc::vec::Vec;

use ozlrip_core::{Error, ErrorKind, Result};

use super::{OwnedStream, partition::ForwardBitReader};

pub(super) fn decode_u32_node(
    buckets: &[u8],
    offset_bits: &[u8],
    bases: &[u64],
    bits: &[u8],
    output_len: usize,
) -> Result<OwnedStream> {
    #[cfg(not(feature = "paranoid"))]
    {
        decode_u32_node_fast(buckets, offset_bits, bases, bits, output_len)
    }
    #[cfg(feature = "paranoid")]
    {
        decode_u32_node_safe(buckets, offset_bits, bases, bits, output_len)
    }
}

#[cfg(feature = "paranoid")]
fn decode_u32_node_safe(
    buckets: &[u8],
    offset_bits: &[u8],
    bases: &[u64],
    bits: &[u8],
    output_len: usize,
) -> Result<OwnedStream> {
    let mut reader = ForwardBitReader::new(offset_bits);
    let mut output = Vec::new();
    output.try_reserve_exact(output_len).map_err(|_| {
        Error::new(ErrorKind::LimitExceeded).with_detail("partition allocation failed")
    })?;
    output.resize(output_len, 0);

    let mut base_table = [0u64; 256];
    let mut bit_table = [u8::MAX; 256];
    let mut mask_table = [0u32; 256];
    for (bucket, (&base, &bit_width)) in bases.iter().zip(bits).enumerate() {
        base_table[bucket] = base;
        bit_table[bucket] = bit_width;
        if bit_width <= 32 {
            mask_table[bucket] = bit_mask_u32(bit_width);
        }
    }

    let mut out_pos = 0usize;
    for &bucket in buckets {
        let bucket = usize::from(bucket);
        let bit_width = bit_table[bucket];
        if bit_width == u8::MAX {
            return Err(
                Error::new(ErrorKind::Malformed).with_detail("partition bucket is out of range")
            );
        }
        let base = base_table[bucket];
        let bit_width = usize::from(bit_width);
        let offset = if bit_width <= 32 {
            u64::from(reader.read_u32_window(bit_width, mask_table[bucket])?)
        } else {
            reader.read_u64(bit_width)?
        };
        let value = base
            .checked_add(offset)
            .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
        let value = u32::try_from(value).map_err(|_| {
            Error::new(ErrorKind::Malformed)
                .with_detail("partition value exceeds output element width")
        })?;
        output[out_pos..out_pos + 4].copy_from_slice(&value.to_le_bytes());
        out_pos += 4;
    }

    Ok(OwnedStream {
        bytes: output,
        element_width: 4,
        string_lengths: None,
        recyclable: false,
    })
}

#[cfg(not(feature = "paranoid"))]
fn decode_u32_node_fast(
    buckets: &[u8],
    offset_bits: &[u8],
    bases: &[u64],
    bits: &[u8],
    output_len: usize,
) -> Result<OwnedStream> {
    let mut reader = ForwardBitReader::new(offset_bits);
    let mut output = Vec::new();
    output.try_reserve_exact(output_len).map_err(|_| {
        Error::new(ErrorKind::LimitExceeded).with_detail("partition allocation failed")
    })?;

    let mut base_table = [0u64; 256];
    let mut bit_table = [u8::MAX; 256];
    let mut mask_table = [0u32; 256];
    for (bucket, (&base, &bit_width)) in bases.iter().zip(bits).enumerate() {
        base_table[bucket] = base;
        bit_table[bucket] = bit_width;
        if bit_width <= 32 {
            mask_table[bucket] = bit_mask_u32(bit_width);
        }
    }

    let mut out_pos = 0usize;
    for &bucket in buckets {
        let bucket = usize::from(bucket);
        let bit_width = bit_table[bucket];
        if bit_width == u8::MAX {
            return Err(
                Error::new(ErrorKind::Malformed).with_detail("partition bucket is out of range")
            );
        }
        let base = base_table[bucket];
        let bit_width = usize::from(bit_width);
        let offset = if bit_width <= 32 {
            u64::from(reader.read_u32_window(bit_width, mask_table[bucket])?)
        } else {
            reader.read_u64(bit_width)?
        };
        let value = base
            .checked_add(offset)
            .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
        let value = u32::try_from(value).map_err(|_| {
            Error::new(ErrorKind::Malformed)
                .with_detail("partition value exceeds output element width")
        })?;
        debug_assert!(out_pos + 4 <= output.capacity());
        unsafe {
            write_u32_le_spare(&mut output, out_pos, value);
        }
        out_pos += 4;
    }

    debug_assert_eq!(out_pos, output_len);
    unsafe {
        // SAFETY: the loop wrote every 4-byte value in `0..output_len`.
        output.set_len(output_len);
    }
    Ok(OwnedStream {
        bytes: output,
        element_width: 4,
        string_lengths: None,
        recyclable: false,
    })
}

#[cfg(not(feature = "paranoid"))]
unsafe fn write_u32_le_spare(output: &mut Vec<u8>, offset: usize, value: u32) {
    debug_assert!(offset + 4 <= output.capacity());
    debug_assert!(output.len() <= offset);
    unsafe {
        core::ptr::write_unaligned(
            output.as_mut_ptr().add(offset).cast::<[u8; 4]>(),
            value.to_le_bytes(),
        );
    }
}

fn bit_mask_u32(bits: u8) -> u32 {
    if bits == 32 {
        u32::MAX
    } else {
        (1u32 << bits) - 1
    }
}
