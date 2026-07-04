#![cfg_attr(feature = "paranoid", forbid(unsafe_code))]
#![allow(
    clippy::inline_always,
    reason = "profiled CSV row loops pay measurable call overhead for tiny fields"
)]

#[cfg(not(feature = "paranoid"))]
use alloc::vec::Vec;

#[cfg(not(feature = "paranoid"))]
use ozlrip_core::{Error, ErrorKind, Result};

#[cfg(not(feature = "paranoid"))]
use super::DispatchStringSource;

#[cfg(not(feature = "paranoid"))]
pub(super) fn append_wide_header_pattern(
    rows: usize,
    data_sources: usize,
    delimiter_source: usize,
    header_source: usize,
    sources: &mut [DispatchStringSource<'_>],
    output: &mut Vec<u8>,
) -> Result<()> {
    let mut positions = sources
        .iter()
        .map(|source| source.position)
        .collect::<Vec<_>>();
    let mut byte_positions = sources
        .iter()
        .map(|source| source.byte_position)
        .collect::<Vec<_>>();
    let mut out_pos = output.len();
    let final_out_pos = sources.iter().try_fold(out_pos, |sum, source| {
        sum.checked_add(source.bytes.len().saturating_sub(source.byte_position))
            .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))
    })?;
    if final_out_pos > output.capacity() {
        return Err(
            Error::new(ErrorKind::InvalidGraph).with_detail("dispatch output capacity is invalid")
        );
    }
    let output_ptr = output.as_mut_ptr();

    append_wide_remaining_source_bytes_unchecked(
        &sources[header_source],
        &mut positions,
        &mut byte_positions,
        header_source,
        output_ptr,
        &mut out_pos,
    );
    for _ in 0..rows {
        for source_index in 0..data_sources {
            append_wide_delimiter_unchecked(
                &sources[delimiter_source],
                &mut positions,
                &mut byte_positions,
                delimiter_source,
                output_ptr,
                &mut out_pos,
            );
            append_wide_source_bytes_unchecked(
                &sources[source_index],
                &mut positions,
                &mut byte_positions,
                source_index,
                output_ptr,
                &mut out_pos,
            );
        }
    }
    append_wide_delimiter_unchecked(
        &sources[delimiter_source],
        &mut positions,
        &mut byte_positions,
        delimiter_source,
        output_ptr,
        &mut out_pos,
    );

    for (source, (position, byte_position)) in sources
        .iter_mut()
        .zip(positions.into_iter().zip(byte_positions.into_iter()))
    {
        source.position = position;
        source.byte_position = byte_position;
    }
    debug_assert!(out_pos <= output.capacity());
    unsafe {
        // SAFETY: validation checked every source range and total output
        // capacity. The append helpers initialized all bytes below `out_pos`.
        output.set_len(out_pos);
    }
    Ok(())
}

#[cfg(not(feature = "paranoid"))]
pub(super) fn append_2byte_csv_pattern_rows(
    rows: usize,
    sources: &mut [DispatchStringSource<'_>],
    output: &mut Vec<u8>,
) -> Result<()> {
    let final_out_pos = sources.iter().try_fold(output.len(), |sum, source| {
        sum.checked_add(source.bytes.len().saturating_sub(source.byte_position))
            .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))
    })?;
    if final_out_pos > output.capacity() {
        return Err(
            Error::new(ErrorKind::InvalidGraph).with_detail("dispatch output capacity is invalid")
        );
    }

    let mut positions = [
        sources[0].position,
        sources[1].position,
        sources[2].position,
        sources[3].position,
        sources[4].position,
    ];
    let mut byte_positions = [
        sources[0].byte_position,
        sources[1].byte_position,
        sources[2].byte_position,
        sources[3].byte_position,
        sources[4].byte_position,
    ];
    let mut out_pos = output.len();
    let output_ptr = output.as_mut_ptr();

    for _ in 0..rows {
        append_pattern_field_prevalidated_unchecked(
            0,
            sources,
            &mut positions,
            &mut byte_positions,
            output_ptr,
            &mut out_pos,
        );
        append_pattern_delimiter_unchecked(
            sources,
            &mut positions,
            &mut byte_positions,
            output_ptr,
            &mut out_pos,
        );
        append_pattern_field_prevalidated_unchecked(
            1,
            sources,
            &mut positions,
            &mut byte_positions,
            output_ptr,
            &mut out_pos,
        );
        append_pattern_delimiter_unchecked(
            sources,
            &mut positions,
            &mut byte_positions,
            output_ptr,
            &mut out_pos,
        );
        append_pattern_field_prevalidated_unchecked(
            2,
            sources,
            &mut positions,
            &mut byte_positions,
            output_ptr,
            &mut out_pos,
        );
        append_pattern_delimiter_unchecked(
            sources,
            &mut positions,
            &mut byte_positions,
            output_ptr,
            &mut out_pos,
        );
        append_pattern_field_prevalidated_unchecked(
            3,
            sources,
            &mut positions,
            &mut byte_positions,
            output_ptr,
            &mut out_pos,
        );
        append_pattern_delimiter_unchecked(
            sources,
            &mut positions,
            &mut byte_positions,
            output_ptr,
            &mut out_pos,
        );
    }

    commit_pattern_sources(sources, positions, byte_positions);
    set_output_len(output, out_pos);
    Ok(())
}

#[cfg(not(feature = "paranoid"))]
pub(super) fn append_2byte_csv_header_pattern_rows(
    rows: usize,
    sources: &mut [DispatchStringSource<'_>],
    output: &mut Vec<u8>,
) -> Result<()> {
    let final_out_pos = sources[..5].iter().try_fold(output.len(), |sum, source| {
        sum.checked_add(source.bytes.len().saturating_sub(source.byte_position))
            .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))
    })?;
    if final_out_pos > output.capacity() {
        return Err(
            Error::new(ErrorKind::InvalidGraph).with_detail("dispatch output capacity is invalid")
        );
    }

    let mut positions = [
        sources[0].position,
        sources[1].position,
        sources[2].position,
        sources[3].position,
        sources[4].position,
    ];
    let mut byte_positions = [
        sources[0].byte_position,
        sources[1].byte_position,
        sources[2].byte_position,
        sources[3].byte_position,
        sources[4].byte_position,
    ];
    let mut out_pos = output.len();
    let output_ptr = output.as_mut_ptr();

    for _ in 0..rows {
        append_pattern_delimiter_unchecked(
            sources,
            &mut positions,
            &mut byte_positions,
            output_ptr,
            &mut out_pos,
        );
        append_pattern_field_prevalidated_unchecked(
            0,
            sources,
            &mut positions,
            &mut byte_positions,
            output_ptr,
            &mut out_pos,
        );
        append_pattern_delimiter_unchecked(
            sources,
            &mut positions,
            &mut byte_positions,
            output_ptr,
            &mut out_pos,
        );
        append_pattern_field_prevalidated_unchecked(
            1,
            sources,
            &mut positions,
            &mut byte_positions,
            output_ptr,
            &mut out_pos,
        );
        append_pattern_delimiter_unchecked(
            sources,
            &mut positions,
            &mut byte_positions,
            output_ptr,
            &mut out_pos,
        );
        append_pattern_field_prevalidated_unchecked(
            2,
            sources,
            &mut positions,
            &mut byte_positions,
            output_ptr,
            &mut out_pos,
        );
        append_pattern_delimiter_unchecked(
            sources,
            &mut positions,
            &mut byte_positions,
            output_ptr,
            &mut out_pos,
        );
        append_pattern_field_prevalidated_unchecked(
            3,
            sources,
            &mut positions,
            &mut byte_positions,
            output_ptr,
            &mut out_pos,
        );
    }
    append_pattern_delimiter_unchecked(
        sources,
        &mut positions,
        &mut byte_positions,
        output_ptr,
        &mut out_pos,
    );

    commit_pattern_sources(sources, positions, byte_positions);
    set_output_len(output, out_pos);
    Ok(())
}

#[cfg(not(feature = "paranoid"))]
fn append_wide_remaining_source_bytes_unchecked(
    source: &DispatchStringSource<'_>,
    positions: &mut [usize],
    byte_positions: &mut [usize],
    source_index: usize,
    output_ptr: *mut u8,
    out_pos: &mut usize,
) {
    let src_start = byte_positions[source_index];
    let length = source.bytes.len() - src_start;
    let dst_end = *out_pos + length;
    unsafe {
        // SAFETY: caller prevalidated that all remaining source bytes belong
        // to this dispatch span and that output spare capacity is sufficient.
        core::ptr::copy_nonoverlapping(
            source.bytes.as_ptr().add(src_start),
            output_ptr.add(*out_pos),
            length,
        );
    }
    positions[source_index] = source.lengths.len();
    byte_positions[source_index] = source.bytes.len();
    *out_pos = dst_end;
}

#[cfg(not(feature = "paranoid"))]
fn append_wide_source_bytes_unchecked(
    source: &DispatchStringSource<'_>,
    positions: &mut [usize],
    byte_positions: &mut [usize],
    source_index: usize,
    output_ptr: *mut u8,
    out_pos: &mut usize,
) {
    let length = source.lengths[positions[source_index]] as usize;
    let src_start = byte_positions[source_index];
    let src_end = src_start + length;
    let dst_end = *out_pos + length;
    debug_assert!(src_end <= source.bytes.len());
    unsafe {
        // SAFETY: caller prevalidated source length tables, source byte
        // ranges, and output spare capacity for the whole dispatch node.
        copy_short_field_unchecked(
            source.bytes.as_ptr().add(src_start),
            output_ptr.add(*out_pos),
            length,
        );
    }
    positions[source_index] += 1;
    byte_positions[source_index] = src_end;
    *out_pos = dst_end;
}

#[cfg(not(feature = "paranoid"))]
fn append_wide_delimiter_unchecked(
    source: &DispatchStringSource<'_>,
    positions: &mut [usize],
    byte_positions: &mut [usize],
    source_index: usize,
    output_ptr: *mut u8,
    out_pos: &mut usize,
) {
    let src_pos = byte_positions[source_index];
    debug_assert!(src_pos < source.bytes.len());
    unsafe {
        // SAFETY: caller prevalidated that every remaining delimiter string is
        // exactly one byte and that the output has enough spare capacity.
        *output_ptr.add(*out_pos) = *source.bytes.as_ptr().add(src_pos);
    }
    positions[source_index] += 1;
    byte_positions[source_index] = src_pos + 1;
    *out_pos += 1;
}

#[cfg(not(feature = "paranoid"))]
fn append_pattern_field_prevalidated_unchecked(
    source_index: usize,
    sources: &[DispatchStringSource<'_>],
    positions: &mut [usize; 5],
    byte_positions: &mut [usize; 5],
    output_ptr: *mut u8,
    out_pos: &mut usize,
) {
    let source = &sources[source_index];
    let length = source.lengths[positions[source_index]] as usize;
    let src_start = byte_positions[source_index];
    let src_end = src_start + length;
    let dst_end = *out_pos + length;
    debug_assert!(src_end <= source.bytes.len());
    unsafe {
        // SAFETY: the caller prevalidated that remaining source lengths match
        // remaining source bytes and that the output has enough spare capacity.
        // The caller sets `Vec::len` only after the full append succeeds.
        copy_short_field_unchecked(
            source.bytes.as_ptr().add(src_start),
            output_ptr.add(*out_pos),
            length,
        );
    }
    positions[source_index] += 1;
    byte_positions[source_index] = src_end;
    *out_pos = dst_end;
}

#[cfg(not(feature = "paranoid"))]
fn append_pattern_delimiter_unchecked(
    sources: &[DispatchStringSource<'_>],
    positions: &mut [usize; 5],
    byte_positions: &mut [usize; 5],
    output_ptr: *mut u8,
    out_pos: &mut usize,
) {
    let source = &sources[4];
    let src_pos = byte_positions[4];
    debug_assert!(src_pos < source.bytes.len());
    unsafe {
        // SAFETY: the caller prevalidated that the delimiter source has
        // exactly one byte per remaining delimiter and that the output has
        // enough spare capacity before entering the fast path.
        let byte = *source.bytes.as_ptr().add(src_pos);
        *output_ptr.add(*out_pos) = byte;
    }
    positions[4] += 1;
    byte_positions[4] = src_pos + 1;
    *out_pos += 1;
}

#[cfg(not(feature = "paranoid"))]
fn commit_pattern_sources(
    sources: &mut [DispatchStringSource<'_>],
    positions: [usize; 5],
    byte_positions: [usize; 5],
) {
    for index in 0..5 {
        sources[index].position = positions[index];
        sources[index].byte_position = byte_positions[index];
    }
}

#[cfg(not(feature = "paranoid"))]
fn set_output_len(output: &mut Vec<u8>, out_pos: usize) {
    debug_assert!(out_pos <= output.capacity());
    unsafe {
        // SAFETY: callers write every byte below `out_pos` before committing
        // source positions and publishing the new vector length.
        output.set_len(out_pos);
    }
}

#[cfg(not(feature = "paranoid"))]
#[inline(always)]
unsafe fn copy_short_field_unchecked(src: *const u8, dst: *mut u8, length: usize) {
    match length {
        0 => {}
        1 => unsafe {
            // SAFETY: caller guarantees `src..src+length` is readable and
            // `dst..dst+length` is writable.
            core::ptr::write(dst, core::ptr::read(src));
        },
        2 => unsafe {
            // SAFETY: caller guarantees both 2-byte ranges are valid.
            core::ptr::write_unaligned(dst.cast::<u16>(), core::ptr::read_unaligned(src.cast()));
        },
        3..=4 => unsafe {
            // SAFETY: first and last 2-byte chunks stay within the field.
            core::ptr::write_unaligned(dst.cast::<u16>(), core::ptr::read_unaligned(src.cast()));
            core::ptr::write_unaligned(
                dst.add(length - 2).cast::<u16>(),
                core::ptr::read_unaligned(src.add(length - 2).cast()),
            );
        },
        5..=8 => unsafe {
            // SAFETY: first and last 4-byte chunks stay within the field.
            core::ptr::write_unaligned(dst.cast::<u32>(), core::ptr::read_unaligned(src.cast()));
            core::ptr::write_unaligned(
                dst.add(length - 4).cast::<u32>(),
                core::ptr::read_unaligned(src.add(length - 4).cast()),
            );
        },
        9..=16 => unsafe {
            // SAFETY: first and last 8-byte chunks stay within the field.
            core::ptr::write_unaligned(dst.cast::<u64>(), core::ptr::read_unaligned(src.cast()));
            core::ptr::write_unaligned(
                dst.add(length - 8).cast::<u64>(),
                core::ptr::read_unaligned(src.add(length - 8).cast()),
            );
        },
        _ => unsafe {
            // SAFETY: caller guarantees source and destination validity and
            // non-overlap for the full field.
            core::ptr::copy_nonoverlapping(src, dst, length);
        },
    }
}
