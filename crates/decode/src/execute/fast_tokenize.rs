#![cfg_attr(feature = "paranoid", forbid(unsafe_code))]

use alloc::vec::Vec;

use ozlrip_core::{Error, ErrorKind, Result};

#[cfg(not(feature = "paranoid"))]
pub(super) fn decode_tokenize_indices(
    alphabet: &[u8],
    alphabet_size: usize,
    element_width: usize,
    indices: &[u8],
    index_width: usize,
    output: &mut Vec<u8>,
) -> Result<()> {
    let output_len = (indices.len() / index_width) * element_width;
    debug_assert!(output.capacity() >= output.len() + output_len);
    match (index_width, element_width) {
        (1, 1) => decode_index_width_1::<1>(alphabet, alphabet_size, indices, output),
        (1, 2) => decode_index_width_1::<2>(alphabet, alphabet_size, indices, output),
        (1, 4) => decode_index_width_1::<4>(alphabet, alphabet_size, indices, output),
        (1, 8) => decode_index_width_1::<8>(alphabet, alphabet_size, indices, output),
        (2, 1) => decode_index_width_2::<1>(alphabet, alphabet_size, indices, output),
        (2, 2) => decode_index_width_2::<2>(alphabet, alphabet_size, indices, output),
        (2, 4) => decode_index_width_2::<4>(alphabet, alphabet_size, indices, output),
        (2, 8) => decode_index_width_2::<8>(alphabet, alphabet_size, indices, output),
        (4, 1) => decode_index_width_4::<1>(alphabet, alphabet_size, indices, output),
        (4, 2) => decode_index_width_4::<2>(alphabet, alphabet_size, indices, output),
        (4, 4) => decode_index_width_4::<4>(alphabet, alphabet_size, indices, output),
        (4, 8) => decode_index_width_4::<8>(alphabet, alphabet_size, indices, output),
        (8, 1) => decode_index_width_8::<1>(alphabet, alphabet_size, indices, output),
        (8, 2) => decode_index_width_8::<2>(alphabet, alphabet_size, indices, output),
        (8, 4) => decode_index_width_8::<4>(alphabet, alphabet_size, indices, output),
        (8, 8) => decode_index_width_8::<8>(alphabet, alphabet_size, indices, output),
        _ => decode_tokenize_indices_safe(
            alphabet,
            alphabet_size,
            element_width,
            indices,
            index_width,
            output,
        ),
    }
}

#[cfg(feature = "paranoid")]
pub(super) fn decode_tokenize_indices(
    alphabet: &[u8],
    alphabet_size: usize,
    element_width: usize,
    indices: &[u8],
    index_width: usize,
    output: &mut Vec<u8>,
) -> Result<()> {
    match (index_width, element_width) {
        (1, 1) => decode_index_width_1_safe::<1>(alphabet, alphabet_size, indices, output),
        (1, 2) => decode_index_width_1_safe::<2>(alphabet, alphabet_size, indices, output),
        (1, 4) => decode_index_width_1_safe::<4>(alphabet, alphabet_size, indices, output),
        (1, 8) => decode_index_width_1_safe::<8>(alphabet, alphabet_size, indices, output),
        (2, 1) => decode_index_width_2_safe::<1>(alphabet, alphabet_size, indices, output),
        (2, 2) => decode_index_width_2_safe::<2>(alphabet, alphabet_size, indices, output),
        (2, 4) => decode_index_width_2_safe::<4>(alphabet, alphabet_size, indices, output),
        (2, 8) => decode_index_width_2_safe::<8>(alphabet, alphabet_size, indices, output),
        (4, 1) => decode_index_width_4_safe::<1>(alphabet, alphabet_size, indices, output),
        (4, 2) => decode_index_width_4_safe::<2>(alphabet, alphabet_size, indices, output),
        (4, 4) => decode_index_width_4_safe::<4>(alphabet, alphabet_size, indices, output),
        (4, 8) => decode_index_width_4_safe::<8>(alphabet, alphabet_size, indices, output),
        (8, 1) => decode_index_width_8_safe::<1>(alphabet, alphabet_size, indices, output),
        (8, 2) => decode_index_width_8_safe::<2>(alphabet, alphabet_size, indices, output),
        (8, 4) => decode_index_width_8_safe::<4>(alphabet, alphabet_size, indices, output),
        (8, 8) => decode_index_width_8_safe::<8>(alphabet, alphabet_size, indices, output),
        _ => decode_tokenize_indices_safe(
            alphabet,
            alphabet_size,
            element_width,
            indices,
            index_width,
            output,
        ),
    }
}

#[cfg(not(feature = "paranoid"))]
fn decode_index_width_1<const ELEMENT_WIDTH: usize>(
    alphabet: &[u8],
    alphabet_size: usize,
    indices: &[u8],
    output: &mut Vec<u8>,
) -> Result<()> {
    let start_len = output.len();
    unsafe {
        let alphabet_ptr = alphabet.as_ptr();
        let mut dst = output.as_mut_ptr().add(start_len);
        for &index in indices {
            let index = usize::from(index);
            validate_index(index, alphabet_size)?;
            copy_token::<ELEMENT_WIDTH>(alphabet_ptr.add(index * ELEMENT_WIDTH), dst);
            dst = dst.add(ELEMENT_WIDTH);
        }
        output.set_len(start_len + indices.len() * ELEMENT_WIDTH);
    }
    Ok(())
}

#[cfg(not(feature = "paranoid"))]
fn decode_index_width_2<const ELEMENT_WIDTH: usize>(
    alphabet: &[u8],
    alphabet_size: usize,
    indices: &[u8],
    output: &mut Vec<u8>,
) -> Result<()> {
    let start_len = output.len();
    let elements = indices.len() / 2;
    unsafe {
        let alphabet_ptr = alphabet.as_ptr();
        let index_ptr = indices.as_ptr();
        let mut dst = output.as_mut_ptr().add(start_len);
        for element in 0..elements {
            let raw = (index_ptr.add(element * 2) as *const u16).read_unaligned();
            let index = usize::from(u16::from_le(raw));
            validate_index(index, alphabet_size)?;
            copy_token::<ELEMENT_WIDTH>(alphabet_ptr.add(index * ELEMENT_WIDTH), dst);
            dst = dst.add(ELEMENT_WIDTH);
        }
        output.set_len(start_len + elements * ELEMENT_WIDTH);
    }
    Ok(())
}

#[cfg(not(feature = "paranoid"))]
fn decode_index_width_4<const ELEMENT_WIDTH: usize>(
    alphabet: &[u8],
    alphabet_size: usize,
    indices: &[u8],
    output: &mut Vec<u8>,
) -> Result<()> {
    let start_len = output.len();
    let elements = indices.len() / 4;
    unsafe {
        let alphabet_ptr = alphabet.as_ptr();
        let index_ptr = indices.as_ptr();
        let mut dst = output.as_mut_ptr().add(start_len);
        for element in 0..elements {
            let raw = (index_ptr.add(element * 4) as *const u32).read_unaligned();
            let index = usize::try_from(u32::from_le(raw)).map_err(|_| numeric_too_large())?;
            validate_index(index, alphabet_size)?;
            copy_token::<ELEMENT_WIDTH>(alphabet_ptr.add(index * ELEMENT_WIDTH), dst);
            dst = dst.add(ELEMENT_WIDTH);
        }
        output.set_len(start_len + elements * ELEMENT_WIDTH);
    }
    Ok(())
}

#[cfg(not(feature = "paranoid"))]
fn decode_index_width_8<const ELEMENT_WIDTH: usize>(
    alphabet: &[u8],
    alphabet_size: usize,
    indices: &[u8],
    output: &mut Vec<u8>,
) -> Result<()> {
    let start_len = output.len();
    let elements = indices.len() / 8;
    unsafe {
        let alphabet_ptr = alphabet.as_ptr();
        let index_ptr = indices.as_ptr();
        let mut dst = output.as_mut_ptr().add(start_len);
        for element in 0..elements {
            let raw = (index_ptr.add(element * 8) as *const u64).read_unaligned();
            let index = usize::try_from(u64::from_le(raw)).map_err(|_| numeric_too_large())?;
            validate_index(index, alphabet_size)?;
            copy_token::<ELEMENT_WIDTH>(alphabet_ptr.add(index * ELEMENT_WIDTH), dst);
            dst = dst.add(ELEMENT_WIDTH);
        }
        output.set_len(start_len + elements * ELEMENT_WIDTH);
    }
    Ok(())
}

#[cfg(not(feature = "paranoid"))]
unsafe fn copy_token<const ELEMENT_WIDTH: usize>(src: *const u8, dst: *mut u8) {
    unsafe {
        match ELEMENT_WIDTH {
            1 => dst.write(src.read()),
            2 => (dst as *mut u16).write_unaligned((src as *const u16).read_unaligned()),
            4 => (dst as *mut u32).write_unaligned((src as *const u32).read_unaligned()),
            8 => (dst as *mut u64).write_unaligned((src as *const u64).read_unaligned()),
            _ => unreachable!("token fast path only accepts fixed element widths"),
        }
    }
}

#[cfg(feature = "paranoid")]
fn decode_index_width_1_safe<const ELEMENT_WIDTH: usize>(
    alphabet: &[u8],
    alphabet_size: usize,
    indices: &[u8],
    output: &mut Vec<u8>,
) -> Result<()> {
    for &index in indices {
        append_tokenized_element_fixed::<ELEMENT_WIDTH>(
            alphabet,
            alphabet_size,
            usize::from(index),
            output,
        )?;
    }
    Ok(())
}

#[cfg(feature = "paranoid")]
fn decode_index_width_2_safe<const ELEMENT_WIDTH: usize>(
    alphabet: &[u8],
    alphabet_size: usize,
    indices: &[u8],
    output: &mut Vec<u8>,
) -> Result<()> {
    for index in indices.chunks_exact(2) {
        append_tokenized_element_fixed::<ELEMENT_WIDTH>(
            alphabet,
            alphabet_size,
            usize::from(u16::from_le_bytes([index[0], index[1]])),
            output,
        )?;
    }
    Ok(())
}

#[cfg(feature = "paranoid")]
fn decode_index_width_4_safe<const ELEMENT_WIDTH: usize>(
    alphabet: &[u8],
    alphabet_size: usize,
    indices: &[u8],
    output: &mut Vec<u8>,
) -> Result<()> {
    for index in indices.chunks_exact(4) {
        append_tokenized_element_fixed::<ELEMENT_WIDTH>(
            alphabet,
            alphabet_size,
            u32::from_le_bytes([index[0], index[1], index[2], index[3]])
                .try_into()
                .map_err(|_| numeric_too_large())?,
            output,
        )?;
    }
    Ok(())
}

#[cfg(feature = "paranoid")]
fn decode_index_width_8_safe<const ELEMENT_WIDTH: usize>(
    alphabet: &[u8],
    alphabet_size: usize,
    indices: &[u8],
    output: &mut Vec<u8>,
) -> Result<()> {
    for index in indices.chunks_exact(8) {
        append_tokenized_element_fixed::<ELEMENT_WIDTH>(
            alphabet,
            alphabet_size,
            u64::from_le_bytes([
                index[0], index[1], index[2], index[3], index[4], index[5], index[6], index[7],
            ])
            .try_into()
            .map_err(|_| numeric_too_large())?,
            output,
        )?;
    }
    Ok(())
}

fn decode_tokenize_indices_safe(
    alphabet: &[u8],
    alphabet_size: usize,
    element_width: usize,
    indices: &[u8],
    index_width: usize,
    output: &mut Vec<u8>,
) -> Result<()> {
    match index_width {
        1 => {
            for &index in indices {
                append_tokenized_element(
                    alphabet,
                    alphabet_size,
                    element_width,
                    index.into(),
                    output,
                )?;
            }
        }
        2 => {
            for index in indices.chunks_exact(2) {
                append_tokenized_element(
                    alphabet,
                    alphabet_size,
                    element_width,
                    u16::from_le_bytes([index[0], index[1]]).into(),
                    output,
                )?;
            }
        }
        4 => {
            for index in indices.chunks_exact(4) {
                append_tokenized_element(
                    alphabet,
                    alphabet_size,
                    element_width,
                    u32::from_le_bytes([index[0], index[1], index[2], index[3]])
                        .try_into()
                        .map_err(|_| numeric_too_large())?,
                    output,
                )?;
            }
        }
        8 => {
            for index in indices.chunks_exact(8) {
                append_tokenized_element(
                    alphabet,
                    alphabet_size,
                    element_width,
                    u64::from_le_bytes([
                        index[0], index[1], index[2], index[3], index[4], index[5], index[6],
                        index[7],
                    ])
                    .try_into()
                    .map_err(|_| numeric_too_large())?,
                    output,
                )?;
            }
        }
        _ => unreachable!("validate_numeric_stream_width accepted only supported widths"),
    }
    Ok(())
}

#[cfg(feature = "paranoid")]
#[inline(always)]
fn append_tokenized_element_fixed<const ELEMENT_WIDTH: usize>(
    alphabet: &[u8],
    alphabet_size: usize,
    index: usize,
    output: &mut Vec<u8>,
) -> Result<()> {
    validate_index(index, alphabet_size)?;
    let start = index * ELEMENT_WIDTH;
    output.extend_from_slice(&alphabet[start..start + ELEMENT_WIDTH]);
    Ok(())
}

#[inline(always)]
fn append_tokenized_element(
    alphabet: &[u8],
    alphabet_size: usize,
    element_width: usize,
    index: usize,
    output: &mut Vec<u8>,
) -> Result<()> {
    validate_index(index, alphabet_size)?;
    let start = index * element_width;
    output.extend_from_slice(&alphabet[start..start + element_width]);
    Ok(())
}

#[inline(always)]
fn validate_index(index: usize, alphabet_size: usize) -> Result<()> {
    if index >= alphabet_size {
        return Err(index_out_of_bounds());
    }
    Ok(())
}

fn index_out_of_bounds() -> Error {
    Error::new(ErrorKind::Malformed).with_detail("tokenize_fixed index is out of bounds")
}

fn numeric_too_large() -> Error {
    Error::new(ErrorKind::LimitExceeded).with_detail("numeric value is too large")
}
