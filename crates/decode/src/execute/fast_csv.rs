#![cfg_attr(feature = "paranoid", forbid(unsafe_code))]
//! Row writers for CSV-shaped `dispatch_string` nodes.
//!
//! They copy fields and delimiters without bounds checks. Each entry point
//! checks that the output capacity holds every remaining source byte; the
//! caller must have checked the source shapes its `# Safety` section lists.
//! A "whole" source has as many remaining strings as the pattern reads from
//! it, and remaining bytes equal to the sum of their lengths.

#[cfg(not(feature = "paranoid"))]
use alloc::vec::Vec;

#[cfg(not(feature = "paranoid"))]
use ozlrip_core::{Error, ErrorKind, Result};

#[cfg(not(feature = "paranoid"))]
use super::dispatch_source::DispatchStringSource;

/// # Safety
///
/// `sources[..data_sources]` must be whole with `rows` strings each,
/// `sources[delimiter_source]` whole with `rows * data_sources + 1` one-byte
/// strings, and `sources[header_source]` whole.
#[cfg(not(feature = "paranoid"))]
pub(super) unsafe fn append_wide_header_pattern(
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
    check_output_capacity(sources, output)?;
    let output_ptr = output.as_mut_ptr();

    // SAFETY: the capacity check above covers every byte the sources hold,
    // and the caller's guarantees keep each field and delimiter read within
    // its source.
    unsafe {
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
    }

    for (source, (position, byte_position)) in sources
        .iter_mut()
        .zip(positions.into_iter().zip(byte_positions))
    {
        source.position = position;
        source.byte_position = byte_position;
    }
    debug_assert!(out_pos <= output.capacity());
    // SAFETY: validation checked every source range and total output
    // capacity. The append helpers initialized all bytes below `out_pos`.
    unsafe {
        output.set_len(out_pos);
    }
    Ok(())
}

/// # Safety
///
/// `sources[..4]` must be whole with `rows` strings each, and `sources[4]`
/// whole with `rows * 4` one-byte strings.
#[cfg(not(feature = "paranoid"))]
pub(super) unsafe fn append_2byte_csv_pattern_rows(
    rows: usize,
    sources: &mut [DispatchStringSource<'_>],
    output: &mut Vec<u8>,
) -> Result<()> {
    check_output_capacity(sources, output)?;

    let (mut positions, mut byte_positions) = pattern_positions(sources);
    let mut out_pos = output.len();
    let output_ptr = output.as_mut_ptr();

    // SAFETY: the capacity check above covers every byte the sources
    // hold, and the caller's guarantees keep each field and delimiter read
    // within its source.
    unsafe {
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
    }

    commit_pattern_sources(sources, positions, byte_positions);
    // SAFETY: the writes above initialized every byte below `out_pos`,
    // which the capacity check bounds.
    unsafe {
        set_output_len(output, out_pos);
    }
    Ok(())
}

/// # Safety
///
/// As for `append_2byte_csv_pattern_rows`, and `sources[0]` and
/// `sources[1]` must hold only 10-byte and 3-byte strings.
#[cfg(not(feature = "paranoid"))]
pub(super) unsafe fn append_2byte_csv_fixed_prefix_pattern_rows(
    rows: usize,
    sources: &mut [DispatchStringSource<'_>],
    output: &mut Vec<u8>,
) -> Result<()> {
    // SAFETY: our caller's guarantees.
    unsafe { append_2byte_csv_fixed_prefix_pattern_rows_impl::<false>(rows, sources, output) }
}

/// # Safety
///
/// As for `append_2byte_csv_fixed_prefix_pattern_rows`, and the delimiters
/// must repeat `,,,\n`.
#[cfg(not(feature = "paranoid"))]
pub(super) unsafe fn append_2byte_csv_fixed_prefix_comma_pattern_rows(
    rows: usize,
    sources: &mut [DispatchStringSource<'_>],
    output: &mut Vec<u8>,
) -> Result<()> {
    // SAFETY: our caller's guarantees.
    unsafe { append_2byte_csv_fixed_prefix_pattern_rows_impl::<true>(rows, sources, output) }
}

/// # Safety
///
/// As for `append_2byte_csv_fixed_prefix_pattern_rows`, or the comma variant when `COMMA_NEWLINE` is set.
#[cfg(not(feature = "paranoid"))]
unsafe fn append_2byte_csv_fixed_prefix_pattern_rows_impl<const COMMA_NEWLINE: bool>(
    rows: usize,
    sources: &mut [DispatchStringSource<'_>],
    output: &mut Vec<u8>,
) -> Result<()> {
    check_output_capacity(sources, output)?;

    let source0_bytes = sources[0].bytes.as_ptr();
    let source1_bytes = sources[1].bytes.as_ptr();
    let mut source0_byte = sources[0].byte_position;
    let mut source1_byte = sources[1].byte_position;
    let (mut positions, mut byte_positions) = pattern_positions(sources);
    let mut out_pos = output.len();
    let output_ptr = output.as_mut_ptr();

    // SAFETY: the capacity check above covers every byte the sources
    // hold, and the caller's guarantees keep each field and delimiter read
    // within its source.
    unsafe {
        for _ in 0..rows {
            copy_10_unchecked(source0_bytes.add(source0_byte), output_ptr.add(out_pos));
            source0_byte += 10;
            out_pos += 10;
            if COMMA_NEWLINE {
                append_const_byte_unchecked(output_ptr, &mut out_pos, b',');
            } else {
                append_pattern_delimiter_unchecked(
                    sources,
                    &mut positions,
                    &mut byte_positions,
                    output_ptr,
                    &mut out_pos,
                );
            }
            copy_3_unchecked(source1_bytes.add(source1_byte), output_ptr.add(out_pos));
            source1_byte += 3;
            out_pos += 3;
            if COMMA_NEWLINE {
                append_const_byte_unchecked(output_ptr, &mut out_pos, b',');
            } else {
                append_pattern_delimiter_unchecked(
                    sources,
                    &mut positions,
                    &mut byte_positions,
                    output_ptr,
                    &mut out_pos,
                );
            }
            append_pattern_field_prevalidated_unchecked(
                2,
                sources,
                &mut positions,
                &mut byte_positions,
                output_ptr,
                &mut out_pos,
            );
            if COMMA_NEWLINE {
                append_const_byte_unchecked(output_ptr, &mut out_pos, b',');
            } else {
                append_pattern_delimiter_unchecked(
                    sources,
                    &mut positions,
                    &mut byte_positions,
                    output_ptr,
                    &mut out_pos,
                );
            }
            append_pattern_field_prevalidated_unchecked(
                3,
                sources,
                &mut positions,
                &mut byte_positions,
                output_ptr,
                &mut out_pos,
            );
            if COMMA_NEWLINE {
                append_const_byte_unchecked(output_ptr, &mut out_pos, b'\n');
            } else {
                append_pattern_delimiter_unchecked(
                    sources,
                    &mut positions,
                    &mut byte_positions,
                    output_ptr,
                    &mut out_pos,
                );
            }
        }
    }

    positions[0] = sources[0].position + rows;
    positions[1] = sources[1].position + rows;
    byte_positions[0] = source0_byte;
    byte_positions[1] = source1_byte;
    if COMMA_NEWLINE {
        let delimiter_count = rows
            .checked_mul(4)
            .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
        positions[4] = sources[4].position + delimiter_count;
        byte_positions[4] = sources[4].byte_position + delimiter_count;
    }
    commit_pattern_sources(sources, positions, byte_positions);
    // SAFETY: the writes above initialized every byte below `out_pos`,
    // which the capacity check bounds.
    unsafe {
        set_output_len(output, out_pos);
    }
    Ok(())
}

/// # Safety
///
/// `sources[..4]` must be whole with `rows` strings each, and `sources[4]`
/// whole with `rows * 4 + 1` one-byte strings.
#[cfg(not(feature = "paranoid"))]
pub(super) unsafe fn append_2byte_csv_header_pattern_rows(
    rows: usize,
    sources: &mut [DispatchStringSource<'_>],
    output: &mut Vec<u8>,
) -> Result<()> {
    check_output_capacity(&sources[..5], output)?;

    let (mut positions, mut byte_positions) = pattern_positions(sources);
    let mut out_pos = output.len();
    let output_ptr = output.as_mut_ptr();

    // SAFETY: the capacity check above covers every byte the sources
    // hold, and the caller's guarantees keep each field and delimiter read
    // within its source.
    unsafe {
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
    }
    // SAFETY: as for the row loop.
    unsafe {
        append_pattern_delimiter_unchecked(
            sources,
            &mut positions,
            &mut byte_positions,
            output_ptr,
            &mut out_pos,
        );
    }

    commit_pattern_sources(sources, positions, byte_positions);
    // SAFETY: the writes above initialized every byte below `out_pos`,
    // which the capacity check bounds.
    unsafe {
        set_output_len(output, out_pos);
    }
    Ok(())
}

/// # Safety
///
/// As for `append_2byte_csv_header_pattern_rows`, and `sources[0]` and
/// `sources[1]` must hold only 10-byte and 3-byte strings.
#[cfg(not(feature = "paranoid"))]
pub(super) unsafe fn append_2byte_csv_fixed_prefix_header_pattern_rows(
    rows: usize,
    sources: &mut [DispatchStringSource<'_>],
    output: &mut Vec<u8>,
) -> Result<()> {
    // SAFETY: our caller's guarantees.
    unsafe {
        append_2byte_csv_fixed_prefix_header_pattern_rows_impl::<false>(rows, sources, output)
    }
}

/// # Safety
///
/// As for `append_2byte_csv_fixed_prefix_header_pattern_rows`, and the
/// delimiters must be `\n` followed by repeats of `,,,\n`.
#[cfg(not(feature = "paranoid"))]
pub(super) unsafe fn append_2byte_csv_fixed_prefix_comma_header_pattern_rows(
    rows: usize,
    sources: &mut [DispatchStringSource<'_>],
    output: &mut Vec<u8>,
) -> Result<()> {
    // SAFETY: our caller's guarantees.
    unsafe { append_2byte_csv_fixed_prefix_header_pattern_rows_impl::<true>(rows, sources, output) }
}

/// # Safety
///
/// As for `append_2byte_csv_fixed_prefix_header_pattern_rows`, or the comma variant when `COMMA_NEWLINE` is set.
#[cfg(not(feature = "paranoid"))]
unsafe fn append_2byte_csv_fixed_prefix_header_pattern_rows_impl<const COMMA_NEWLINE: bool>(
    rows: usize,
    sources: &mut [DispatchStringSource<'_>],
    output: &mut Vec<u8>,
) -> Result<()> {
    check_output_capacity(&sources[..5], output)?;

    let source0_bytes = sources[0].bytes.as_ptr();
    let source1_bytes = sources[1].bytes.as_ptr();
    let mut source0_byte = sources[0].byte_position;
    let mut source1_byte = sources[1].byte_position;
    let (mut positions, mut byte_positions) = pattern_positions(sources);
    let mut out_pos = output.len();
    let output_ptr = output.as_mut_ptr();

    // SAFETY: the capacity check above covers every byte the sources
    // hold, and the caller's guarantees keep each field and delimiter read
    // within its source.
    unsafe {
        for _ in 0..rows {
            if COMMA_NEWLINE {
                append_const_byte_unchecked(output_ptr, &mut out_pos, b'\n');
            } else {
                append_pattern_delimiter_unchecked(
                    sources,
                    &mut positions,
                    &mut byte_positions,
                    output_ptr,
                    &mut out_pos,
                );
            }
            copy_10_unchecked(source0_bytes.add(source0_byte), output_ptr.add(out_pos));
            source0_byte += 10;
            out_pos += 10;
            if COMMA_NEWLINE {
                append_const_byte_unchecked(output_ptr, &mut out_pos, b',');
            } else {
                append_pattern_delimiter_unchecked(
                    sources,
                    &mut positions,
                    &mut byte_positions,
                    output_ptr,
                    &mut out_pos,
                );
            }
            copy_3_unchecked(source1_bytes.add(source1_byte), output_ptr.add(out_pos));
            source1_byte += 3;
            out_pos += 3;
            if COMMA_NEWLINE {
                append_const_byte_unchecked(output_ptr, &mut out_pos, b',');
            } else {
                append_pattern_delimiter_unchecked(
                    sources,
                    &mut positions,
                    &mut byte_positions,
                    output_ptr,
                    &mut out_pos,
                );
            }
            append_pattern_field_prevalidated_unchecked(
                2,
                sources,
                &mut positions,
                &mut byte_positions,
                output_ptr,
                &mut out_pos,
            );
            if COMMA_NEWLINE {
                append_const_byte_unchecked(output_ptr, &mut out_pos, b',');
            } else {
                append_pattern_delimiter_unchecked(
                    sources,
                    &mut positions,
                    &mut byte_positions,
                    output_ptr,
                    &mut out_pos,
                );
            }
            append_pattern_field_prevalidated_unchecked(
                3,
                sources,
                &mut positions,
                &mut byte_positions,
                output_ptr,
                &mut out_pos,
            );
        }
    }
    // SAFETY: as for the row loop.
    unsafe {
        if COMMA_NEWLINE {
            append_const_byte_unchecked(output_ptr, &mut out_pos, b'\n');
        } else {
            append_pattern_delimiter_unchecked(
                sources,
                &mut positions,
                &mut byte_positions,
                output_ptr,
                &mut out_pos,
            );
        }
    }

    positions[0] = sources[0].position + rows;
    positions[1] = sources[1].position + rows;
    byte_positions[0] = source0_byte;
    byte_positions[1] = source1_byte;
    if COMMA_NEWLINE {
        let delimiter_count = rows
            .checked_mul(4)
            .and_then(|count| count.checked_add(1))
            .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
        positions[4] = sources[4].position + delimiter_count;
        byte_positions[4] = sources[4].byte_position + delimiter_count;
    }
    commit_pattern_sources(sources, positions, byte_positions);
    // SAFETY: the writes above initialized every byte below `out_pos`,
    // which the capacity check bounds.
    unsafe {
        set_output_len(output, out_pos);
    }
    Ok(())
}

/// Copies all remaining bytes of `source` to `output_ptr + *out_pos`.
///
/// # Safety
///
/// The spare capacity from `*out_pos` must hold those bytes.
#[cfg(not(feature = "paranoid"))]
unsafe fn append_wide_remaining_source_bytes_unchecked(
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
    // SAFETY: caller prevalidated that all remaining source bytes belong
    // to this dispatch span and that output spare capacity is sufficient.
    unsafe {
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

/// Copies the next string of `source` to `output_ptr + *out_pos`.
///
/// # Safety
///
/// `source` must be whole with a string left, and the spare capacity from
/// `*out_pos` must hold it.
#[cfg(not(feature = "paranoid"))]
unsafe fn append_wide_source_bytes_unchecked(
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
    // SAFETY: caller prevalidated source length tables, source byte
    // ranges, and output spare capacity for the whole dispatch node.
    unsafe {
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

/// Copies the next one-byte string of `source` to `output_ptr + *out_pos`.
///
/// # Safety
///
/// `source` must have a byte left, and the spare capacity from `*out_pos`
/// must hold it.
#[cfg(not(feature = "paranoid"))]
unsafe fn append_wide_delimiter_unchecked(
    source: &DispatchStringSource<'_>,
    positions: &mut [usize],
    byte_positions: &mut [usize],
    source_index: usize,
    output_ptr: *mut u8,
    out_pos: &mut usize,
) {
    let src_pos = byte_positions[source_index];
    debug_assert!(src_pos < source.bytes.len());
    // SAFETY: caller prevalidated that every remaining delimiter string is
    // exactly one byte and that the output has enough spare capacity.
    unsafe {
        *output_ptr.add(*out_pos) = *source.bytes.as_ptr().add(src_pos);
    }
    positions[source_index] += 1;
    byte_positions[source_index] = src_pos + 1;
    *out_pos += 1;
}

/// Copies the next string of `sources[source_index]` to
/// `output_ptr + *out_pos`.
///
/// # Safety
///
/// The source must be whole with a string left, and the spare capacity from
/// `*out_pos` must hold it.
#[cfg(not(feature = "paranoid"))]
#[expect(
    clippy::inline_always,
    reason = "profiled: CSV rows pay measurable call overhead for tiny fields"
)]
#[inline(always)]
unsafe fn append_pattern_field_prevalidated_unchecked(
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
    // SAFETY: the caller prevalidated that remaining source lengths match
    // remaining source bytes and that the output has enough spare capacity.
    // The caller sets `Vec::len` only after the full append succeeds.
    unsafe {
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

/// Copies the next byte of the delimiter source `sources[4]` to
/// `output_ptr + *out_pos`.
///
/// # Safety
///
/// The delimiter source must have a byte left, and the spare capacity from
/// `*out_pos` must hold it.
#[cfg(not(feature = "paranoid"))]
#[expect(
    clippy::inline_always,
    reason = "profiled: CSV rows pay measurable call overhead for tiny fields"
)]
#[inline(always)]
unsafe fn append_pattern_delimiter_unchecked(
    sources: &[DispatchStringSource<'_>],
    positions: &mut [usize; 5],
    byte_positions: &mut [usize; 5],
    output_ptr: *mut u8,
    out_pos: &mut usize,
) {
    let source = &sources[4];
    let src_pos = byte_positions[4];
    debug_assert!(src_pos < source.bytes.len());
    // SAFETY: the caller prevalidated that the delimiter source has
    // exactly one byte per remaining delimiter and that the output has
    // enough spare capacity before entering the fast path.
    unsafe {
        let byte = *source.bytes.as_ptr().add(src_pos);
        *output_ptr.add(*out_pos) = byte;
    }
    positions[4] += 1;
    byte_positions[4] = src_pos + 1;
    *out_pos += 1;
}

/// Fails unless `output`'s capacity holds every byte the sources have
/// left, which bounds all unchecked writes of a row writer.
#[cfg(not(feature = "paranoid"))]
#[expect(
    clippy::inline_always,
    reason = "runs once before a hot row loop; keeps the writers' code unchanged"
)]
#[inline(always)]
fn check_output_capacity(sources: &[DispatchStringSource<'_>], output: &Vec<u8>) -> Result<()> {
    let final_out_pos = sources.iter().try_fold(output.len(), |sum, source| {
        sum.checked_add(source.bytes.len().saturating_sub(source.byte_position))
            .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))
    })?;
    if final_out_pos > output.capacity() {
        return Err(
            Error::new(ErrorKind::InvalidGraph).with_detail("dispatch output capacity is invalid")
        );
    }
    Ok(())
}

/// The string and byte positions of the five pattern sources.
#[cfg(not(feature = "paranoid"))]
#[expect(
    clippy::inline_always,
    reason = "runs once before a hot row loop; keeps the writers' code unchanged"
)]
#[inline(always)]
fn pattern_positions(sources: &[DispatchStringSource<'_>]) -> ([usize; 5], [usize; 5]) {
    let positions = [
        sources[0].position,
        sources[1].position,
        sources[2].position,
        sources[3].position,
        sources[4].position,
    ];
    let byte_positions = [
        sources[0].byte_position,
        sources[1].byte_position,
        sources[2].byte_position,
        sources[3].byte_position,
        sources[4].byte_position,
    ];
    (positions, byte_positions)
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

/// # Safety
///
/// `out_pos` must be at most the capacity, with every byte below it
/// initialized.
#[cfg(not(feature = "paranoid"))]
unsafe fn set_output_len(output: &mut Vec<u8>, out_pos: usize) {
    debug_assert!(out_pos <= output.capacity());
    // SAFETY: callers write every byte below `out_pos` before committing
    // source positions and publishing the new vector length.
    unsafe {
        output.set_len(out_pos);
    }
}

/// # Safety
///
/// The spare capacity from `*out_pos` must hold one byte.
#[cfg(not(feature = "paranoid"))]
#[expect(
    clippy::inline_always,
    reason = "profiled: CSV rows pay measurable call overhead for tiny fields"
)]
#[inline(always)]
unsafe fn append_const_byte_unchecked(output_ptr: *mut u8, out_pos: &mut usize, byte: u8) {
    // SAFETY: caller prevalidated output spare capacity for full pattern.
    unsafe {
        *output_ptr.add(*out_pos) = byte;
    }
    *out_pos += 1;
}

/// Copies a `length`-byte field with at most two overlapping loads.
///
/// # Safety
///
/// `src` must be valid for `length` reads and `dst` for `length` writes,
/// in different buffers.
#[cfg(not(feature = "paranoid"))]
#[expect(
    clippy::inline_always,
    reason = "profiled: CSV rows pay measurable call overhead for tiny fields"
)]
#[inline(always)]
unsafe fn copy_short_field_unchecked(src: *const u8, dst: *mut u8, length: usize) {
    match length {
        0 => {}
        // SAFETY: caller guarantees `src..src+length` is readable and
        // `dst..dst+length` is writable.
        1 => unsafe {
            core::ptr::write(dst, core::ptr::read(src));
        },
        // SAFETY: caller guarantees both 2-byte ranges are valid.
        2 => unsafe {
            core::ptr::write_unaligned(dst.cast::<u16>(), core::ptr::read_unaligned(src.cast()));
        },
        // SAFETY: first and last 2-byte chunks stay within the field.
        3 => unsafe {
            core::ptr::write_unaligned(dst.cast::<u16>(), core::ptr::read_unaligned(src.cast()));
            core::ptr::write_unaligned(
                dst.add(length - 2).cast::<u16>(),
                core::ptr::read_unaligned(src.add(length - 2).cast()),
            );
        },
        // SAFETY: caller guarantees both 4-byte ranges are valid.
        4 => unsafe {
            core::ptr::write_unaligned(dst.cast::<u32>(), core::ptr::read_unaligned(src.cast()));
        },
        // SAFETY: first and last 4-byte chunks stay within the field.
        5..=7 => unsafe {
            core::ptr::write_unaligned(dst.cast::<u32>(), core::ptr::read_unaligned(src.cast()));
            core::ptr::write_unaligned(
                dst.add(length - 4).cast::<u32>(),
                core::ptr::read_unaligned(src.add(length - 4).cast()),
            );
        },
        // SAFETY: caller guarantees both 8-byte ranges are valid.
        8 => unsafe {
            core::ptr::write_unaligned(dst.cast::<u64>(), core::ptr::read_unaligned(src.cast()));
        },
        // SAFETY: first and last 8-byte chunks stay within the field.
        9..=16 => unsafe {
            core::ptr::write_unaligned(dst.cast::<u64>(), core::ptr::read_unaligned(src.cast()));
            core::ptr::write_unaligned(
                dst.add(length - 8).cast::<u64>(),
                core::ptr::read_unaligned(src.add(length - 8).cast()),
            );
        },
        // SAFETY: caller guarantees source and destination validity and
        // non-overlap for the full field.
        _ => unsafe {
            core::ptr::copy_nonoverlapping(src, dst, length);
        },
    }
}

/// # Safety
///
/// `src` must be valid for 10 reads and `dst` for 10 writes, in different
/// buffers.
#[cfg(not(feature = "paranoid"))]
#[expect(
    clippy::inline_always,
    reason = "profiled: CSV rows pay measurable call overhead for tiny fields"
)]
#[inline(always)]
unsafe fn copy_10_unchecked(src: *const u8, dst: *mut u8) {
    // SAFETY: caller guarantees both 10-byte ranges are valid.
    unsafe {
        core::ptr::write_unaligned(dst.cast::<u64>(), core::ptr::read_unaligned(src.cast()));
        core::ptr::write_unaligned(
            dst.add(8).cast::<u16>(),
            core::ptr::read_unaligned(src.add(8).cast()),
        );
    }
}

/// # Safety
///
/// `src` must be valid for 3 reads and `dst` for 3 writes, in different
/// buffers.
#[cfg(not(feature = "paranoid"))]
#[expect(
    clippy::inline_always,
    reason = "profiled: CSV rows pay measurable call overhead for tiny fields"
)]
#[inline(always)]
unsafe fn copy_3_unchecked(src: *const u8, dst: *mut u8) {
    // SAFETY: caller guarantees both 3-byte ranges are valid.
    unsafe {
        core::ptr::write_unaligned(dst.cast::<u16>(), core::ptr::read_unaligned(src.cast()));
        core::ptr::write(dst.add(2), core::ptr::read(src.add(2)));
    }
}
