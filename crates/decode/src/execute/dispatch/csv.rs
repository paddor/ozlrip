//! CSV-shaped `dispatch_string` indices: a loop that copies whole rows of
//! the 5-source pattern at a time.

use alloc::vec::Vec;

use ozlrip_core::Result;

use super::source::{
    DispatchStringSource, append_dispatched_single_byte_string_source_to_serial,
    append_dispatched_string_source_to_serial, append_dispatched_string_to_serial,
};

/// Appends the strings 16-bit `indices` select.
pub(super) fn append_u16_dispatched_to_serial(
    indices: &[u8],
    sources: &mut [DispatchStringSource<'_>],
    output: &mut Vec<u8>,
) -> Result<()> {
    if sources.len() == 5 {
        return append_dispatched_string_2byte_csv_pattern(indices, sources, output);
    }
    for source in indices.as_chunks::<2>().0 {
        append_dispatched_string_to_serial(
            usize::from(u16::from_le_bytes(*source)),
            sources,
            output,
        )?;
    }
    Ok(())
}

fn append_dispatched_string_2byte_csv_pattern(
    indices: &[u8],
    sources: &mut [DispatchStringSource<'_>],
    output: &mut Vec<u8>,
) -> Result<()> {
    const CSV_PATTERN: [u8; 16] = [0, 0, 4, 0, 1, 0, 4, 0, 2, 0, 4, 0, 3, 0, 4, 0];

    let mut offset = 0usize;
    while indices.len() - offset >= CSV_PATTERN.len() {
        if indices[offset..offset + CSV_PATTERN.len()] == CSV_PATTERN {
            append_dispatched_string_source_to_serial(&mut sources[0], output)?;
            append_dispatched_single_byte_string_source_to_serial(&mut sources[4], output)?;
            append_dispatched_string_source_to_serial(&mut sources[1], output)?;
            append_dispatched_single_byte_string_source_to_serial(&mut sources[4], output)?;
            append_dispatched_string_source_to_serial(&mut sources[2], output)?;
            append_dispatched_single_byte_string_source_to_serial(&mut sources[4], output)?;
            append_dispatched_string_source_to_serial(&mut sources[3], output)?;
            append_dispatched_single_byte_string_source_to_serial(&mut sources[4], output)?;
            offset += CSV_PATTERN.len();
            continue;
        }

        let source = &indices[offset..offset + 2];
        append_dispatched_string_to_serial(
            usize::from(u16::from_le_bytes([source[0], source[1]])),
            sources,
            output,
        )?;
        offset += 2;
    }

    while offset < indices.len() {
        let source = &indices[offset..offset + 2];
        append_dispatched_string_to_serial(
            usize::from(u16::from_le_bytes([source[0], source[1]])),
            sources,
            output,
        )?;
        offset += 2;
    }

    Ok(())
}
