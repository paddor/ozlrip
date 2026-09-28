//! CSV-shaped `dispatch_string` indices: shape detection and the calls into
//! the unchecked row writers, with a checked loop for the 5-source pattern.

use alloc::vec::Vec;

use ozlrip_core::Result;
#[cfg(not(feature = "paranoid"))]
use ozlrip_core::{Error, ErrorKind};

#[cfg(not(feature = "paranoid"))]
use super::fast_csv;
use super::source::{
    DispatchStringSource, append_dispatched_single_byte_string_source_to_serial,
    append_dispatched_string_source_to_serial, append_dispatched_string_to_serial,
};
#[cfg(not(feature = "paranoid"))]
use super::source::{
    chunks_match_16, delimiter_bytes_match_csv_header_rows, delimiter_bytes_match_csv_rows,
    fixed_length_source_remaining, one_byte_strings_remaining, whole_strings_remaining,
};

/// Appends the strings 16-bit `indices` select, through a CSV fast path
/// when one matches. Returns true when a fast path wrote the output; fast
/// paths check source consumption themselves.
pub(super) fn append_u16_dispatched_to_serial(
    indices: &[u8],
    sources: &mut [DispatchStringSource<'_>],
    output: &mut Vec<u8>,
    allow_fast: bool,
) -> Result<bool> {
    #[cfg(feature = "paranoid")]
    let _ = allow_fast;
    #[cfg(not(feature = "paranoid"))]
    if allow_fast
        && sources.len() > 6
        && append_dispatched_string_2byte_csv_wide_header_pattern_fast(indices, sources, output)?
    {
        return Ok(true);
    }
    if sources.len() == 5 {
        #[cfg(not(feature = "paranoid"))]
        if allow_fast && append_dispatched_string_2byte_csv_pattern_fast(indices, sources, output)?
        {
            return Ok(true);
        }
        append_dispatched_string_2byte_csv_pattern(indices, sources, output)?;
        return Ok(false);
    }
    #[cfg(not(feature = "paranoid"))]
    if allow_fast
        && sources.len() == 6
        && append_dispatched_string_2byte_csv_header_pattern_fast(indices, sources, output)?
    {
        return Ok(true);
    }
    for source in indices.as_chunks::<2>().0 {
        append_dispatched_string_to_serial(
            usize::from(u16::from_le_bytes(*source)),
            sources,
            output,
        )?;
    }
    Ok(false)
}

#[cfg(not(feature = "paranoid"))]
fn append_dispatched_string_2byte_csv_wide_header_pattern_fast(
    indices: &[u8],
    sources: &mut [DispatchStringSource<'_>],
    output: &mut Vec<u8>,
) -> Result<bool> {
    let Some(layout) = WideCsvLayout::new(sources.len())? else {
        return Ok(false);
    };
    let Some(rows) = layout.rows(indices) else {
        return Ok(false);
    };
    if !layout.sources_match(sources, rows)? {
        return Ok(false);
    }
    // SAFETY: `sources_match` found `rows` strings in each data source with
    // lengths that sum to its bytes, `rows * data_sources + 1` one-byte
    // delimiters, and a header source whose lengths sum to its bytes.
    unsafe {
        fast_csv::append_wide_header_pattern(
            rows,
            layout.data_sources,
            layout.delimiter_source(),
            layout.header_source(),
            sources,
            output,
        )
    }?;
    Ok(true)
}

/// A CSV shape with a header row and any number of columns: data sources,
/// then the delimiter source, then the header source.
#[cfg(not(feature = "paranoid"))]
struct WideCsvLayout {
    data_sources: usize,
    delimiter_index: u16,
    header_index: u16,
    header_fields: usize,
    header_bytes: usize,
    row_bytes: usize,
}

#[cfg(not(feature = "paranoid"))]
impl WideCsvLayout {
    fn new(source_count: usize) -> Result<Option<Self>> {
        let data_sources = source_count
            .checked_sub(2)
            .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
        if data_sources == 0 {
            return Ok(None);
        }
        // Indices are read as `u16`, and the header source is the largest
        // index the pattern refers to, so it must round-trip through `u16`
        // without wrapping.
        let (Ok(delimiter_index), Ok(header_index)) =
            (u16::try_from(data_sources), u16::try_from(data_sources + 1))
        else {
            return Ok(None);
        };
        let header_fields = data_sources
            .checked_mul(2)
            .and_then(|count| count.checked_sub(1))
            .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
        let header_bytes = header_fields
            .checked_mul(2)
            .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
        let row_fields = data_sources
            .checked_mul(2)
            .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
        let row_bytes = row_fields
            .checked_mul(2)
            .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
        Ok(Some(Self {
            data_sources,
            delimiter_index,
            header_index,
            header_fields,
            header_bytes,
            row_bytes,
        }))
    }

    fn delimiter_source(&self) -> usize {
        self.data_sources
    }

    fn header_source(&self) -> usize {
        self.data_sources + 1
    }

    /// Row count, if `indices` are the header, whole rows and a trailing
    /// delimiter.
    fn rows(&self, indices: &[u8]) -> Option<usize> {
        let trailing_delimiter_bytes = 2usize;
        if indices.len() < self.header_bytes + trailing_delimiter_bytes
            || !(indices.len() - self.header_bytes - trailing_delimiter_bytes)
                .is_multiple_of(self.row_bytes)
        {
            return None;
        }
        if !indices[..self.header_bytes]
            .as_chunks::<2>()
            .0
            .iter()
            .all(|chunk| u16::from_le_bytes(*chunk) == self.header_index)
        {
            return None;
        }
        let rows_end = indices.len() - trailing_delimiter_bytes;
        if u16::from_le_bytes([indices[rows_end], indices[rows_end + 1]]) != self.delimiter_index {
            return None;
        }
        let rows = (rows_end - self.header_bytes) / self.row_bytes;
        let row_indices = &indices[self.header_bytes..rows_end];
        csv_wide_header_row_indices_match(row_indices, rows, self.delimiter_index).then_some(rows)
    }

    /// Whether each data source holds `rows` whole strings, the delimiter
    /// source one byte per delimiter, and the header source whole strings.
    fn sources_match(&self, sources: &[DispatchStringSource<'_>], rows: usize) -> Result<bool> {
        for source in &sources[..self.data_sources] {
            if !whole_strings_remaining(source, rows)? {
                return Ok(false);
            }
        }
        let delimiter_count = rows
            .checked_mul(self.data_sources)
            .and_then(|count| count.checked_add(1))
            .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
        Ok(
            one_byte_strings_remaining(&sources[self.delimiter_source()], delimiter_count)
                && whole_strings_remaining(&sources[self.header_source()], self.header_fields)?,
        )
    }
}

#[cfg(not(feature = "paranoid"))]
/// The delimiter stream is indexed directly after the data sources, so
/// `delimiter_index` doubles as the data-source count.
fn csv_wide_header_row_indices_match(indices: &[u8], rows: usize, delimiter_index: u16) -> bool {
    let mut offset = 0usize;
    for _ in 0..rows {
        for source in 0..delimiter_index {
            if u16::from_le_bytes([indices[offset], indices[offset + 1]]) != delimiter_index {
                return false;
            }
            offset += 2;
            if u16::from_le_bytes([indices[offset], indices[offset + 1]]) != source {
                return false;
            }
            offset += 2;
        }
    }
    true
}

#[cfg(not(feature = "paranoid"))]
fn append_dispatched_string_2byte_csv_pattern_fast(
    indices: &[u8],
    sources: &mut [DispatchStringSource<'_>],
    output: &mut Vec<u8>,
) -> Result<bool> {
    const CSV_PATTERN: [u8; 16] = [0, 0, 4, 0, 1, 0, 4, 0, 2, 0, 4, 0, 3, 0, 4, 0];

    if !indices.len().is_multiple_of(CSV_PATTERN.len()) {
        return Ok(false);
    }
    let rows = indices.len() / CSV_PATTERN.len();
    let fixed_prefix = csv_fixed_prefix(sources, rows);
    if !csv_data_sources_match(sources, rows, fixed_prefix)? {
        return Ok(false);
    }
    let delimiter_count = rows
        .checked_mul(4)
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
    if !one_byte_strings_remaining(&sources[4], delimiter_count)
        || !chunks_match_16(indices, CSV_PATTERN)
    {
        return Ok(false);
    }

    if fixed_prefix && delimiter_bytes_match_csv_rows(&sources[4], rows) {
        // SAFETY: the checks above found `rows` strings in sources 0 to 3
        // with lengths that sum to their bytes, 10- and 3-byte strings in
        // sources 0 and 1, and `,,,\n` repeated as the delimiters.
        unsafe {
            fast_csv::append_2byte_csv_fixed_prefix_comma_pattern_rows(rows, sources, output)
        }?;
        return Ok(true);
    }
    if fixed_prefix {
        // SAFETY: the checks above found `rows` strings in sources 0 to 3
        // with lengths that sum to their bytes, 10- and 3-byte strings in
        // sources 0 and 1, and `rows * 4` one-byte delimiters.
        unsafe { fast_csv::append_2byte_csv_fixed_prefix_pattern_rows(rows, sources, output) }?;
        return Ok(true);
    }

    // SAFETY: the checks above found `rows` strings in sources 0 to 3 with
    // lengths that sum to their bytes, and `rows * 4` one-byte delimiters.
    unsafe { fast_csv::append_2byte_csv_pattern_rows(rows, sources, output) }?;
    Ok(true)
}

/// Whether sources 0 and 1 of a four-column CSV hold `rows` 10- and 3-byte
/// strings, as timestamps split into date and time do.
#[cfg(not(feature = "paranoid"))]
fn csv_fixed_prefix(sources: &[DispatchStringSource<'_>], rows: usize) -> bool {
    fixed_length_source_remaining(&sources[0], rows, 10)
        && fixed_length_source_remaining(&sources[1], rows, 3)
}

/// Whether the four data sources of a CSV hold `rows` whole strings each.
/// With `fixed_prefix`, sources 0 and 1 were already checked.
#[cfg(not(feature = "paranoid"))]
fn csv_data_sources_match(
    sources: &[DispatchStringSource<'_>],
    rows: usize,
    fixed_prefix: bool,
) -> Result<bool> {
    let variable_sources = if fixed_prefix {
        &sources[2..4]
    } else {
        &sources[..4]
    };
    for source in variable_sources {
        if !whole_strings_remaining(source, rows)? {
            return Ok(false);
        }
    }
    Ok(true)
}

#[cfg(not(feature = "paranoid"))]
const CSV_HEADER_FIELDS: usize = 7;

#[cfg(not(feature = "paranoid"))]
fn append_dispatched_string_2byte_csv_header_pattern_fast(
    indices: &[u8],
    sources: &mut [DispatchStringSource<'_>],
    output: &mut Vec<u8>,
) -> Result<bool> {
    let Some(rows) = csv_header_rows(indices)? else {
        return Ok(false);
    };
    let fixed_prefix = csv_fixed_prefix(sources, rows);
    if !csv_data_sources_match(sources, rows, fixed_prefix)? {
        return Ok(false);
    }
    let delimiter_count = rows
        .checked_mul(4)
        .and_then(|count| count.checked_add(1))
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
    if !one_byte_strings_remaining(&sources[4], delimiter_count)
        || !whole_strings_remaining(&sources[5], CSV_HEADER_FIELDS)?
    {
        return Ok(false);
    }

    for _ in 0..CSV_HEADER_FIELDS {
        append_dispatched_string_to_serial(5, sources, output)?;
    }
    if fixed_prefix && delimiter_bytes_match_csv_header_rows(&sources[4], rows) {
        // SAFETY: the checks above found `rows` strings in sources 0 to 3
        // with lengths that sum to their bytes, 10- and 3-byte strings in
        // sources 0 and 1, and `\n` then `,,,\n` repeated as the delimiters.
        unsafe {
            fast_csv::append_2byte_csv_fixed_prefix_comma_header_pattern_rows(rows, sources, output)
        }?;
        return Ok(true);
    }
    if fixed_prefix {
        // SAFETY: the checks above found `rows` strings in sources 0 to 3
        // with lengths that sum to their bytes, 10- and 3-byte strings in
        // sources 0 and 1, and `rows * 4 + 1` one-byte delimiters.
        unsafe {
            fast_csv::append_2byte_csv_fixed_prefix_header_pattern_rows(rows, sources, output)
        }?;
        return Ok(true);
    }
    // SAFETY: the checks above found `rows` strings in sources 0 to 3 with
    // lengths that sum to their bytes, and `rows * 4 + 1` one-byte delimiters.
    unsafe { fast_csv::append_2byte_csv_header_pattern_rows(rows, sources, output) }?;
    Ok(true)
}

/// Row count, if `indices` are a four-column CSV with a header row: seven
/// header strings, the rows, and a trailing delimiter.
#[cfg(not(feature = "paranoid"))]
fn csv_header_rows(indices: &[u8]) -> Result<Option<usize>> {
    const HEADER_SOURCE: u16 = 5;
    const ROW_PATTERN: [u8; 16] = [4, 0, 0, 0, 4, 0, 1, 0, 4, 0, 2, 0, 4, 0, 3, 0];
    const TRAILING_DELIMITER: [u8; 2] = [4, 0];

    let header_bytes = CSV_HEADER_FIELDS
        .checked_mul(2)
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
    if indices.len() < header_bytes + TRAILING_DELIMITER.len()
        || !(indices.len() - header_bytes - TRAILING_DELIMITER.len())
            .is_multiple_of(ROW_PATTERN.len())
    {
        return Ok(None);
    }
    if !indices[..header_bytes]
        .as_chunks::<2>()
        .0
        .iter()
        .all(|chunk| u16::from_le_bytes(*chunk) == HEADER_SOURCE)
    {
        return Ok(None);
    }
    let row_bytes_end = indices.len() - TRAILING_DELIMITER.len();
    if indices[row_bytes_end..] != TRAILING_DELIMITER
        || !chunks_match_16(&indices[header_bytes..row_bytes_end], ROW_PATTERN)
    {
        return Ok(None);
    }
    Ok(Some((row_bytes_end - header_bytes) / ROW_PATTERN.len()))
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
