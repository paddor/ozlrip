#![cfg_attr(feature = "paranoid", forbid(unsafe_code))]
#![allow(
    clippy::inline_always,
    clippy::too_many_arguments,
    reason = "profiled field-LZ fast path keeps validated stream arguments split"
)]

#[cfg(not(feature = "paranoid"))]
use alloc::vec::Vec;

#[cfg(not(feature = "paranoid"))]
use ozlrip_core::{Error, ErrorKind, Result};

#[cfg(not(feature = "paranoid"))]
pub(super) fn decode_to_output(
    literals: &[u8],
    tokens: &[u8],
    offsets: &[u8],
    extra_literal_lengths: &[u8],
    extra_match_lengths: &[u8],
    element_width: usize,
    output_len: usize,
    output: &mut Vec<u8>,
    output_base: usize,
) -> Result<()> {
    let output_limit = output_base
        .checked_add(output_len)
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
    if output.len() != output_base || output.capacity() < output_limit {
        return Err(Error::new(ErrorKind::InvalidGraph)
            .with_detail("field_lz output spare capacity is invalid"));
    }
    if !tokens.len().is_multiple_of(2)
        || !offsets.len().is_multiple_of(4)
        || !extra_literal_lengths.len().is_multiple_of(4)
        || !extra_match_lengths.len().is_multiple_of(4)
    {
        return Err(
            Error::new(ErrorKind::Malformed).with_detail("numeric stream has partial element")
        );
    }

    let min_match = match element_width {
        1 => 4usize,
        2 => 2usize,
        4 | 8 => 1usize,
        _ => {
            return Err(Error::new(ErrorKind::InvalidType)
                .with_detail("field_lz literal width is unsupported"));
        }
    };
    let mut reps = [element_width, element_width * 2, element_width * 4];
    let mut literal_pos = 0usize;
    let mut out_pos = output_base;
    let mut offset_pos = 0usize;
    let mut extra_literal_pos = 0usize;
    let mut extra_match_pos = 0usize;

    let output_ptr = output.as_mut_ptr();
    let literal_ptr = literals.as_ptr();
    for token_offset in (0..tokens.len()).step_by(2) {
        let token = u16::from_le_bytes([tokens[token_offset], tokens[token_offset + 1]]);
        let offset_code = usize::from(token & 0x3);
        let literal_code = usize::from((token >> 2) & 0x0f);
        let match_code = usize::from((token >> 6) & 0x0f);

        let match_offset = match offset_code {
            3 => {
                let raw_offset = read_u32_usize(offsets, offset_pos)?;
                offset_pos += 4;
                let byte_offset = raw_offset
                    .checked_mul(element_width)
                    .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
                reps[2] = reps[1];
                reps[1] = reps[0];
                reps[0] = byte_offset;
                byte_offset
            }
            0 => reps[0],
            1 => {
                let byte_offset = reps[1];
                reps.swap(1, 0);
                byte_offset
            }
            2 => {
                let byte_offset = reps[2];
                reps[2] = reps[1];
                reps[1] = reps[0];
                reps[0] = byte_offset;
                byte_offset
            }
            _ => unreachable!("offset code is masked to two bits"),
        };

        let mut literal_elements = literal_code;
        if literal_code == 15 {
            let extra = read_u32_usize(extra_literal_lengths, extra_literal_pos)?;
            extra_literal_pos += 4;
            literal_elements = literal_elements
                .checked_add(extra)
                .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
        }
        let literal_len = literal_elements
            .checked_mul(element_width)
            .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;

        let mut match_elements = match_code
            .checked_add(min_match)
            .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
        if match_code == 15 {
            let extra = read_u32_usize(extra_match_lengths, extra_match_pos)?;
            extra_match_pos += 4;
            match_elements = match_elements
                .checked_add(extra)
                .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
        }
        let match_len = match_elements
            .checked_mul(element_width)
            .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;

        let literal_end = literal_pos
            .checked_add(literal_len)
            .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
        let out_literal_end = out_pos
            .checked_add(literal_len)
            .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
        if literal_end > literals.len() {
            return Err(Error::new(ErrorKind::Malformed)
                .with_detail("field_lz literal stream is too short"));
        }
        if out_literal_end > output_limit {
            return Err(Error::new(ErrorKind::Malformed)
                .with_detail("field_lz literal length exceeds output size"));
        }
        unsafe {
            copy_literals(
                literal_ptr.add(literal_pos),
                output_ptr.add(out_pos),
                literal_len,
            );
        }
        literal_pos = literal_end;
        out_pos = out_literal_end;

        if match_offset == 0 {
            return Err(Error::new(ErrorKind::Malformed).with_detail("field_lz offset is zero"));
        }
        let chunk_len = out_pos
            .checked_sub(output_base)
            .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
        if match_offset > chunk_len {
            return Err(Error::new(ErrorKind::Malformed)
                .with_detail("field_lz offset exceeds decoded prefix"));
        }
        let out_match_end = out_pos
            .checked_add(match_len)
            .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
        if out_match_end > output_limit {
            return Err(Error::new(ErrorKind::Malformed)
                .with_detail("field_lz match length exceeds output size"));
        }
        unsafe {
            let src = output_ptr.add(out_pos - match_offset);
            let dst = output_ptr.add(out_pos);
            if match_len <= match_offset {
                copy_literals(src, dst, match_len);
            } else {
                copy_lz_match(src, dst, match_len, match_offset);
            }
        }
        out_pos = out_match_end;
    }

    let remaining_literals = literals.len() - literal_pos;
    let final_len = out_pos
        .checked_add(remaining_literals)
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
    if final_len > output_limit {
        return Err(Error::new(ErrorKind::Malformed)
            .with_detail("field_lz output size exceeds header capacity"));
    }
    if offset_pos != offsets.len()
        || extra_literal_pos != extra_literal_lengths.len()
        || extra_match_pos != extra_match_lengths.len()
    {
        return Err(Error::new(ErrorKind::Malformed)
            .with_detail("field_lz numeric stream was not fully consumed"));
    }
    unsafe {
        copy_literals(
            literal_ptr.add(literal_pos),
            output_ptr.add(out_pos),
            remaining_literals,
        );
        output.set_len(final_len);
    }
    Ok(())
}

#[cfg(not(feature = "paranoid"))]
#[inline(always)]
fn read_u32_usize(bytes: &[u8], offset: usize) -> Result<usize> {
    if offset.checked_add(4).is_none_or(|end| end > bytes.len()) {
        return Err(Error::new(ErrorKind::Malformed).with_detail("numeric stream is exhausted"));
    }
    unsafe {
        // SAFETY: bounds check above proves the 4-byte read is in-bounds.
        Ok(u32::from_le((bytes.as_ptr().add(offset).cast::<u32>()).read_unaligned()) as usize)
    }
}

#[cfg(not(feature = "paranoid"))]
#[inline(always)]
unsafe fn copy_literals(src: *const u8, dst: *mut u8, len: usize) {
    if len != 0 {
        unsafe {
            core::ptr::copy_nonoverlapping(src, dst, len);
        }
    }
}

#[cfg(not(feature = "paranoid"))]
#[inline(always)]
unsafe fn copy_lz_match(src: *const u8, dst: *mut u8, len: usize, offset: usize) {
    debug_assert!(offset != 0);
    debug_assert!(offset < len);
    unsafe {
        // SAFETY: caller validated that `src..src+offset` is readable and
        // `dst..dst+len` is writable. First copy seeds the repeated window;
        // later copies read only bytes already initialized by prior copies.
        core::ptr::copy_nonoverlapping(src, dst, offset);
        let mut copied = offset;
        while copied < len {
            let copy_len = copied.min(len - copied);
            core::ptr::copy_nonoverlapping(dst, dst.add(copied), copy_len);
            copied += copy_len;
        }
    }
}

#[cfg(all(test, not(feature = "paranoid")))]
mod tests {
    use alloc::vec::Vec;

    use super::decode_to_output;

    #[test]
    fn decodes_overlapping_explicit_offset_match() {
        let mut output = Vec::with_capacity(16);
        let token = 3 | (4 << 2) | (4 << 6);

        decode_to_output(
            b"abcdWXYZ",
            &u16::to_le_bytes(token),
            &u32::to_le_bytes(4),
            &[],
            &[],
            1,
            16,
            &mut output,
            0,
        )
        .unwrap();

        assert_eq!(output, b"abcdabcdabcdWXYZ");
    }

    #[test]
    fn decodes_long_overlapping_repeat() {
        let mut output = Vec::with_capacity(1024);
        let token = 3 | (15 << 2) | (15 << 6);

        decode_to_output(
            b"0123456789abcdef!",
            &u16::to_le_bytes(token),
            &u32::to_le_bytes(16),
            &u32::to_le_bytes(1),
            &u32::to_le_bytes(476),
            1,
            512,
            &mut output,
            0,
        )
        .unwrap();

        assert_eq!(&output[..16], b"0123456789abcdef");
        assert_eq!(output[16..511], b"0123456789abcdef".repeat(31)[..495]);
        assert_eq!(output[511], b'!');
    }

    #[test]
    fn decodes_with_nonzero_output_base() {
        let mut output = Vec::from(&b"pre"[..]);
        output.reserve_exact(8);
        let token = 3 | (3 << 2);

        decode_to_output(
            b"abcz",
            &u16::to_le_bytes(token),
            &u32::to_le_bytes(3),
            &[],
            &[],
            1,
            8,
            &mut output,
            3,
        )
        .unwrap();

        assert_eq!(output, b"preabcabcaz");
    }

    #[test]
    fn rejects_extra_numeric_values() {
        let mut output = Vec::with_capacity(8);
        let token = 3 | (4 << 2);

        let err = decode_to_output(
            b"abcd",
            &u16::to_le_bytes(token),
            &[4, 0, 0, 0, 7, 0, 0, 0],
            &[],
            &[],
            1,
            8,
            &mut output,
            0,
        )
        .unwrap_err();

        assert_eq!(err.kind(), ozlrip_core::ErrorKind::Malformed);
    }
}
