#![cfg_attr(feature = "paranoid", forbid(unsafe_code))]

#[cfg(not(feature = "paranoid"))]
use alloc::vec::Vec;

#[cfg(not(feature = "paranoid"))]
use ozlrip_core::{Error, ErrorKind, Result};

#[cfg(not(feature = "paranoid"))]
pub(super) fn decode_u8_u16_u16_to_output(
    literals: &[u8],
    offsets: &[u8],
    literal_lengths: &[u8],
    match_lengths: &[u8],
    sequence_count: usize,
    output_len: usize,
    output: &mut Vec<u8>,
    output_base: usize,
) -> Result<()> {
    validate_lengths(offsets, literal_lengths, match_lengths, sequence_count)?;
    let output_limit = output_base
        .checked_add(output_len)
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
    if output.len() != output_base || output.capacity() < output_limit {
        return Err(
            Error::new(ErrorKind::InvalidGraph).with_detail("lz output spare capacity is invalid")
        );
    }

    validate_lz_ranges(
        literals,
        offsets,
        literal_lengths,
        match_lengths,
        sequence_count,
        output_limit,
        output_base,
    )?;

    unsafe {
        write_lz_unchecked(
            literals,
            offsets,
            literal_lengths,
            match_lengths,
            sequence_count,
            output,
            output_base,
            output_limit,
        );
    }
    Ok(())
}

#[cfg(not(feature = "paranoid"))]
fn validate_lengths(
    offsets: &[u8],
    literal_lengths: &[u8],
    match_lengths: &[u8],
    sequence_count: usize,
) -> Result<()> {
    let length_bytes = sequence_count
        .checked_mul(2)
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
    if offsets.len() != sequence_count
        || literal_lengths.len() != length_bytes
        || match_lengths.len() != length_bytes
    {
        return Err(
            Error::new(ErrorKind::Malformed).with_detail("lz sequence stream counts do not match")
        );
    }
    Ok(())
}

#[cfg(not(feature = "paranoid"))]
fn validate_lz_ranges(
    literals: &[u8],
    offsets: &[u8],
    literal_lengths: &[u8],
    match_lengths: &[u8],
    sequence_count: usize,
    output_limit: usize,
    output_base: usize,
) -> Result<()> {
    let mut out_pos = output_base;
    let mut lit_pos = 0usize;
    for sequence in 0..sequence_count {
        let length_offset = sequence * 2;
        let literal_len = read_u16_usize(literal_lengths, length_offset);
        let match_offset = usize::from(offsets[sequence]);
        let match_len = read_u16_usize(match_lengths, length_offset);

        let literal_end = lit_pos
            .checked_add(literal_len)
            .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
        let out_literal_end = out_pos
            .checked_add(literal_len)
            .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
        if literal_end > literals.len() {
            return Err(
                Error::new(ErrorKind::Malformed).with_detail("lz literal stream is too short")
            );
        }
        if out_literal_end > output_limit {
            return Err(Error::new(ErrorKind::Malformed)
                .with_detail("lz literal length exceeds output size"));
        }
        lit_pos = literal_end;
        out_pos = out_literal_end;

        if match_offset == 0 {
            return Err(Error::new(ErrorKind::Malformed).with_detail("lz offset is zero"));
        }
        if match_offset > out_pos - output_base {
            return Err(
                Error::new(ErrorKind::Malformed).with_detail("lz offset exceeds decoded prefix")
            );
        }
        out_pos = out_pos
            .checked_add(match_len)
            .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
        if out_pos > output_limit {
            return Err(
                Error::new(ErrorKind::Malformed).with_detail("lz match length exceeds output size")
            );
        }
    }

    let out_end = out_pos
        .checked_add(literals.len() - lit_pos)
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
    if out_end != output_limit {
        return Err(
            Error::new(ErrorKind::Malformed).with_detail("lz output size does not match header")
        );
    }
    Ok(())
}

#[cfg(not(feature = "paranoid"))]
#[inline(always)]
fn read_u16_usize(bytes: &[u8], offset: usize) -> usize {
    usize::from(u16::from_le_bytes([bytes[offset], bytes[offset + 1]]))
}

#[cfg(not(feature = "paranoid"))]
unsafe fn write_lz_unchecked(
    literals: &[u8],
    offsets: &[u8],
    literal_lengths: &[u8],
    match_lengths: &[u8],
    sequence_count: usize,
    output: &mut Vec<u8>,
    output_base: usize,
    output_limit: usize,
) {
    debug_assert_eq!(output.len(), output_base);
    debug_assert!(output.capacity() >= output_limit);

    let output_ptr = output.as_mut_ptr();
    let literal_ptr = literals.as_ptr();
    let mut out_pos = output_base;
    let mut lit_pos = 0usize;
    unsafe {
        output.set_len(output_limit);
    }

    for sequence in 0..sequence_count {
        let length_offset = sequence * 2;
        let literal_len = read_u16_usize(literal_lengths, length_offset);
        let match_offset = usize::from(offsets[sequence]);
        let match_len = read_u16_usize(match_lengths, length_offset);

        unsafe {
            core::ptr::copy_nonoverlapping(
                literal_ptr.add(lit_pos),
                output_ptr.add(out_pos),
                literal_len,
            );
        }
        lit_pos += literal_len;
        out_pos += literal_len;

        unsafe {
            copy_lz_match(
                output_ptr.add(out_pos - match_offset),
                output_ptr.add(out_pos),
                match_len,
            );
        }
        out_pos += match_len;
    }

    unsafe {
        core::ptr::copy_nonoverlapping(
            literal_ptr.add(lit_pos),
            output_ptr.add(out_pos),
            literals.len() - lit_pos,
        );
    }
}

#[cfg(not(feature = "paranoid"))]
unsafe fn copy_lz_match(src: *const u8, dst: *mut u8, len: usize) {
    for index in 0..len {
        unsafe {
            *dst.add(index) = *src.add(index);
        }
    }
}

#[cfg(not(feature = "paranoid"))]
pub(super) fn append_nonoverlapping_match(
    output: &mut Vec<u8>,
    src_start: usize,
    match_len: usize,
) {
    let out_pos = output.len();
    debug_assert!(src_start <= out_pos);
    debug_assert!(src_start + match_len <= out_pos);
    debug_assert!(output.capacity() >= out_pos + match_len);

    unsafe {
        let ptr = output.as_mut_ptr();
        core::ptr::copy_nonoverlapping(ptr.add(src_start), ptr.add(out_pos), match_len);
        output.set_len(out_pos + match_len);
    }
}

#[cfg(all(test, not(feature = "paranoid")))]
mod tests {
    use super::{append_nonoverlapping_match, decode_u8_u16_u16_to_output};

    #[test]
    fn decodes_validated_u8_u16_u16_lz_into_spare_capacity() {
        let literals = b"abcxyZ";
        let offsets = [3, 2];
        let literal_lengths = [3, 0, 2, 0];
        let match_lengths = [3, 0, 4, 0];
        let mut output = b"pre".to_vec();
        output.reserve_exact(13);

        decode_u8_u16_u16_to_output(
            literals,
            &offsets,
            &literal_lengths,
            &match_lengths,
            2,
            13,
            &mut output,
            3,
        )
        .unwrap();

        assert_eq!(output, b"preabcabcxyxyxyZ");
    }

    #[test]
    fn rejects_malformed_lz_before_mutating_output() {
        let literals = b"a";
        let offsets = [1];
        let literal_lengths = [2, 0];
        let match_lengths = [0, 0];
        let mut output = b"pre".to_vec();
        output.reserve_exact(8);

        let err = decode_u8_u16_u16_to_output(
            literals,
            &offsets,
            &literal_lengths,
            &match_lengths,
            1,
            2,
            &mut output,
            3,
        )
        .unwrap_err();

        assert_eq!(err.kind(), ozlrip_core::ErrorKind::Malformed);
        assert_eq!(output, b"pre");
    }

    #[test]
    fn appends_nonoverlapping_match_from_spare_capacity() {
        let mut output = b"abcdef".to_vec();
        output.reserve_exact(3);

        append_nonoverlapping_match(&mut output, 2, 3);

        assert_eq!(output, b"abcdefcde");
    }
}
