#![cfg_attr(feature = "paranoid", forbid(unsafe_code))]

use alloc::vec::Vec;

pub(super) fn decode_numeric(input: &[u8], element_width: usize, output: &mut Vec<u8>) {
    #[cfg(not(feature = "paranoid"))]
    if decode_numeric_fast(input, element_width, output) {
        return;
    }
    decode_numeric_safe(input, element_width, output);
}

fn decode_numeric_safe(input: &[u8], element_width: usize, output: &mut Vec<u8>) {
    match element_width {
        1 => {
            for &encoded in input {
                let mask = 0u8.wrapping_sub(encoded & 1);
                output.push((encoded >> 1) ^ mask);
            }
        }
        2 => {
            for encoded in input.chunks_exact(2) {
                let value = u16::from_le_bytes([encoded[0], encoded[1]]);
                let mask = 0u16.wrapping_sub(value & 1);
                output.extend_from_slice(&((value >> 1) ^ mask).to_le_bytes());
            }
        }
        4 => {
            for encoded in input.chunks_exact(4) {
                let value = u32::from_le_bytes([encoded[0], encoded[1], encoded[2], encoded[3]]);
                let mask = 0u32.wrapping_sub(value & 1);
                output.extend_from_slice(&((value >> 1) ^ mask).to_le_bytes());
            }
        }
        8 => {
            for encoded in input.chunks_exact(8) {
                let value = u64::from_le_bytes([
                    encoded[0], encoded[1], encoded[2], encoded[3], encoded[4], encoded[5],
                    encoded[6], encoded[7],
                ]);
                let mask = 0u64.wrapping_sub(value & 1);
                output.extend_from_slice(&((value >> 1) ^ mask).to_le_bytes());
            }
        }
        _ => unreachable!("validate_numeric_stream_width accepted only supported widths"),
    }
}

#[cfg(not(feature = "paranoid"))]
fn decode_numeric_fast(input: &[u8], element_width: usize, output: &mut Vec<u8>) -> bool {
    match element_width {
        2 => decode_u16_fast(input, output),
        4 => decode_u32_fast(input, output),
        8 => decode_u64_fast(input, output),
        _ => false,
    }
}

#[cfg(not(feature = "paranoid"))]
fn decode_u16_fast(input: &[u8], output: &mut Vec<u8>) -> bool {
    if !input.len().is_multiple_of(2) {
        return false;
    }
    debug_assert!(output.len() + input.len() <= output.capacity());
    let start = output.len();
    unsafe {
        // SAFETY: the caller reserved `input.len()` bytes in `output` and the
        // width validation above ensures exact 2-byte chunks.
        let dst = output.as_mut_ptr().add(start);
        for (index, encoded) in input.chunks_exact(2).enumerate() {
            let value = u16::from_le_bytes([encoded[0], encoded[1]]);
            let mask = 0u16.wrapping_sub(value & 1);
            dst.add(index * 2)
                .cast::<u16>()
                .write_unaligned(((value >> 1) ^ mask).to_le());
        }
        output.set_len(start + input.len());
    }
    true
}

#[cfg(not(feature = "paranoid"))]
fn decode_u32_fast(input: &[u8], output: &mut Vec<u8>) -> bool {
    if !input.len().is_multiple_of(4) {
        return false;
    }
    debug_assert!(output.len() + input.len() <= output.capacity());
    let start = output.len();
    unsafe {
        // SAFETY: the caller reserved `input.len()` bytes in `output` and the
        // width validation above ensures exact 4-byte chunks.
        let dst = output.as_mut_ptr().add(start);
        for (index, encoded) in input.chunks_exact(4).enumerate() {
            let value = u32::from_le_bytes([encoded[0], encoded[1], encoded[2], encoded[3]]);
            let mask = 0u32.wrapping_sub(value & 1);
            dst.add(index * 4)
                .cast::<u32>()
                .write_unaligned(((value >> 1) ^ mask).to_le());
        }
        output.set_len(start + input.len());
    }
    true
}

#[cfg(not(feature = "paranoid"))]
fn decode_u64_fast(input: &[u8], output: &mut Vec<u8>) -> bool {
    if !input.len().is_multiple_of(8) {
        return false;
    }
    debug_assert!(output.len() + input.len() <= output.capacity());
    let start = output.len();
    unsafe {
        // SAFETY: the caller reserved `input.len()` bytes in `output` and the
        // width validation above ensures exact 8-byte chunks.
        let dst = output.as_mut_ptr().add(start);
        for (index, encoded) in input.chunks_exact(8).enumerate() {
            let value = u64::from_le_bytes([
                encoded[0], encoded[1], encoded[2], encoded[3], encoded[4], encoded[5], encoded[6],
                encoded[7],
            ]);
            let mask = 0u64.wrapping_sub(value & 1);
            dst.add(index * 8)
                .cast::<u64>()
                .write_unaligned(((value >> 1) ^ mask).to_le());
        }
        output.set_len(start + input.len());
    }
    true
}
