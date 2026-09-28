use alloc::vec::Vec;

use ozlrip_core::{Error, ErrorKind, Limits, Result};

use super::header::require_empty_header;
use super::output::{alloc_output, check_output_len};

use super::dispatch_source::DispatchStringSource;
#[cfg(not(feature = "paranoid"))]
use super::dispatch_source::{
    chunks_match_16, delimiter_bytes_match_csv_header_rows, delimiter_bytes_match_csv_rows,
    fixed_length_source_remaining, one_byte_strings_remaining, whole_strings_remaining,
};
#[cfg(not(feature = "paranoid"))]
use super::fast_csv;
use super::{
    fast_dispatch,
    numeric::{
        checked_sum_u32, numeric_element_count, read_usize_numeric_element, require_numeric_width,
        validate_numeric_stream_width,
    },
    streams::{OwnedStream, StreamInput},
};

pub(super) fn decode_dispatch_string_node(
    inputs: &[StreamInput<'_>],
    variable_inputs: u32,
    header: &[u8],
    format_version: u32,
    limits: Limits,
) -> Result<OwnedStream> {
    require_empty_header(header, "dispatch_string headers are unsupported")?;
    let (indices, string_inputs, index_count) =
        dispatch_shape(inputs, variable_inputs, format_version)?;
    let (mut sources, total_bytes) = collect_sources(string_inputs, index_count, true)?;
    let mut output = alloc_output(total_bytes, limits, "dispatch output allocation failed")?;
    let mut output_lengths = Vec::new();
    output_lengths.try_reserve_exact(index_count).map_err(|_| {
        Error::new(ErrorKind::AllocationFailed).with_detail("dispatch length allocation failed")
    })?;
    match indices.element_width {
        1 => {
            for &source in indices.bytes {
                append_dispatched_string(
                    usize::from(source),
                    &mut sources,
                    &mut output,
                    &mut output_lengths,
                )?;
            }
        }
        2 => {
            for source in indices.bytes.as_chunks::<2>().0 {
                append_dispatched_string(
                    usize::from(u16::from_le_bytes(*source)),
                    &mut sources,
                    &mut output,
                    &mut output_lengths,
                )?;
            }
        }
        _ => unreachable!("require_numeric_width accepted only the expected dispatch width"),
    }
    ensure_sources_consumed(&sources)?;
    Ok(OwnedStream::strings(output, output_lengths))
}

/// Splits a dispatch_string node's inputs into its index stream and string
/// sources, and returns the index count.
fn dispatch_shape<'a, 'b>(
    inputs: &'a [StreamInput<'b>],
    variable_inputs: u32,
    format_version: u32,
) -> Result<(&'a StreamInput<'b>, &'a [StreamInput<'b>], usize)> {
    let variable_inputs = usize::try_from(variable_inputs)
        .map_err(|_| Error::new(ErrorKind::LimitExceeded).with_detail("input count too large"))?;
    if inputs.len()
        != variable_inputs
            .checked_add(1)
            .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?
    {
        return Err(Error::new(ErrorKind::InvalidGraph)
            .with_detail("dispatch_string input count does not match node shape"));
    }
    let (indices, string_inputs) = inputs.split_first().ok_or_else(|| {
        Error::new(ErrorKind::InvalidGraph).with_detail("dispatch_string index stream is missing")
    })?;
    let expected_index_width = if format_version < 21 { 1 } else { 2 };
    require_numeric_width(indices, expected_index_width, "dispatch_string indices")?;
    let index_count = numeric_element_count(indices.bytes, indices.element_width)?;
    if index_count != 0 && string_inputs.is_empty() {
        return Err(Error::new(ErrorKind::Malformed)
            .with_detail("dispatch_string indices require string inputs"));
    }
    Ok((indices, string_inputs, index_count))
}

/// One source per string input, and their total content size. With
/// `verify_sums`, each input's lengths must add up to its content;
/// direct-append inputs come from nodes that already checked that.
fn collect_sources<'a>(
    string_inputs: &[StreamInput<'a>],
    index_count: usize,
    verify_sums: bool,
) -> Result<(Vec<DispatchStringSource<'a>>, usize)> {
    let mut sources = Vec::new();
    sources
        .try_reserve_exact(string_inputs.len())
        .map_err(|_| {
            Error::new(ErrorKind::AllocationFailed).with_detail("dispatch allocation failed")
        })?;
    let mut total_string_count = 0usize;
    let mut total_bytes = 0usize;
    for input in string_inputs {
        if input.element_width != 1 {
            return Err(Error::new(ErrorKind::InvalidType)
                .with_detail("dispatch_string inputs must be byte strings"));
        }
        let lengths = input.string_lengths.ok_or_else(|| {
            Error::new(ErrorKind::InvalidType)
                .with_detail("dispatch_string input is missing string lengths")
        })?;
        if verify_sums && checked_sum_u32(lengths)? != input.bytes.len() {
            return Err(Error::new(ErrorKind::Malformed)
                .with_detail("dispatch_string input lengths do not sum to content size"));
        }
        total_string_count = total_string_count
            .checked_add(lengths.len())
            .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
        total_bytes = total_bytes
            .checked_add(input.bytes.len())
            .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
        sources.push(DispatchStringSource {
            bytes: input.bytes,
            lengths,
            position: 0,
            byte_position: 0,
        });
    }
    if index_count != total_string_count {
        return Err(Error::new(ErrorKind::Malformed)
            .with_detail("dispatch_string index count does not match string count"));
    }
    Ok((sources, total_bytes))
}

fn ensure_sources_consumed(sources: &[DispatchStringSource<'_>]) -> Result<()> {
    for source in sources {
        if source.position != source.lengths.len() || source.byte_position != source.bytes.len() {
            return Err(Error::new(ErrorKind::Malformed)
                .with_detail("dispatch_string did not consume every source string"));
        }
    }
    Ok(())
}

#[expect(
    clippy::inline_always,
    reason = "profiled CSV dispatch hot path benefits from inlining this leaf"
)]
#[inline(always)]
fn append_dispatched_string(
    source: usize,
    sources: &mut [DispatchStringSource<'_>],
    output: &mut Vec<u8>,
    output_lengths: &mut Vec<u32>,
) -> Result<()> {
    let source = sources.get_mut(source).ok_or_else(|| {
        Error::new(ErrorKind::Malformed).with_detail("dispatch_string source index is invalid")
    })?;
    let length = *source.lengths.get(source.position).ok_or_else(|| {
        Error::new(ErrorKind::Malformed).with_detail("dispatch_string source is exhausted")
    })?;
    let length_usize = usize::try_from(length)
        .map_err(|_| Error::new(ErrorKind::LimitExceeded).with_detail("string length too large"))?;
    let offset = source.byte_position;
    let end = offset
        .checked_add(length_usize)
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
    let bytes = source.bytes.get(offset..end).ok_or_else(|| {
        Error::new(ErrorKind::Malformed).with_detail("dispatch_string range is invalid")
    })?;
    output.extend_from_slice(bytes);
    output_lengths.push(length);
    source.position = source
        .position
        .checked_add(1)
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
    source.byte_position = end;
    Ok(())
}

pub(super) fn decode_dispatch_string_node_to_serial_output(
    inputs: &[StreamInput<'_>],
    variable_inputs: u32,
    header: &[u8],
    format_version: u32,
    limits: Limits,
    output: &mut Vec<u8>,
) -> Result<()> {
    decode_dispatch_string_to_serial(
        inputs,
        variable_inputs,
        header,
        format_version,
        limits,
        output,
        true,
    )
}

/// `allow_fast: false` decodes CSV shapes through the generic loop, so tests
/// can compare it with the fast paths.
pub(super) fn decode_dispatch_string_to_serial(
    inputs: &[StreamInput<'_>],
    variable_inputs: u32,
    header: &[u8],
    format_version: u32,
    limits: Limits,
    output: &mut Vec<u8>,
    allow_fast: bool,
) -> Result<()> {
    require_empty_header(header, "dispatch_string headers are unsupported")?;
    let (indices, string_inputs, index_count) =
        dispatch_shape(inputs, variable_inputs, format_version)?;
    let (mut sources, total_bytes) = collect_sources(string_inputs, index_count, false)?;
    check_output_len(total_bytes, limits)?;
    output.try_reserve_exact(total_bytes).map_err(|_| {
        Error::new(ErrorKind::AllocationFailed).with_detail("dispatch output allocation failed")
    })?;

    match indices.element_width {
        1 => {
            for &source in indices.bytes {
                append_dispatched_string_to_serial(usize::from(source), &mut sources, output)?;
            }
        }
        2 => {
            if append_u16_dispatched_to_serial(indices.bytes, &mut sources, output, allow_fast)? {
                return Ok(());
            }
        }
        _ => unreachable!("require_numeric_width accepted only the expected dispatch width"),
    }
    ensure_sources_consumed(&sources)
}

/// Appends the strings 16-bit `indices` select, through a CSV fast path
/// when one matches. Returns true when a fast path wrote the output; fast
/// paths check source consumption themselves.
fn append_u16_dispatched_to_serial(
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

#[expect(
    clippy::inline_always,
    reason = "profiled CSV dispatch hot path benefits from inlining this leaf"
)]
#[inline(always)]
fn append_dispatched_string_to_serial(
    source: usize,
    sources: &mut [DispatchStringSource<'_>],
    output: &mut Vec<u8>,
) -> Result<()> {
    let source = sources.get_mut(source).ok_or_else(|| {
        Error::new(ErrorKind::Malformed).with_detail("dispatch_string source index is invalid")
    })?;
    let length = *source.lengths.get(source.position).ok_or_else(|| {
        Error::new(ErrorKind::Malformed).with_detail("dispatch_string source is exhausted")
    })?;
    let length = usize::try_from(length)
        .map_err(|_| Error::new(ErrorKind::LimitExceeded).with_detail("string length too large"))?;
    let offset = source.byte_position;
    let end = offset
        .checked_add(length)
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
    let bytes = source.bytes.get(offset..end).ok_or_else(|| {
        Error::new(ErrorKind::Malformed).with_detail("dispatch_string range is invalid")
    })?;
    output.extend_from_slice(bytes);
    source.position = source
        .position
        .checked_add(1)
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
    source.byte_position = end;
    Ok(())
}

#[expect(
    clippy::inline_always,
    reason = "profiled CSV dispatch hot path benefits from inlining this leaf"
)]
#[inline(always)]
fn append_dispatched_string_source_to_serial(
    source: &mut DispatchStringSource<'_>,
    output: &mut Vec<u8>,
) -> Result<()> {
    let length = *source.lengths.get(source.position).ok_or_else(|| {
        Error::new(ErrorKind::Malformed).with_detail("dispatch_string source is exhausted")
    })?;
    let length = usize::try_from(length)
        .map_err(|_| Error::new(ErrorKind::LimitExceeded).with_detail("string length too large"))?;
    let offset = source.byte_position;
    let end = offset
        .checked_add(length)
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
    let bytes = source.bytes.get(offset..end).ok_or_else(|| {
        Error::new(ErrorKind::Malformed).with_detail("dispatch_string range is invalid")
    })?;
    output.extend_from_slice(bytes);
    source.position = source
        .position
        .checked_add(1)
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
    source.byte_position = end;
    Ok(())
}

#[expect(
    clippy::inline_always,
    reason = "profiled CSV dispatch hot path benefits from inlining this leaf"
)]
#[inline(always)]
fn append_dispatched_single_byte_string_source_to_serial(
    source: &mut DispatchStringSource<'_>,
    output: &mut Vec<u8>,
) -> Result<()> {
    let length = *source.lengths.get(source.position).ok_or_else(|| {
        Error::new(ErrorKind::Malformed).with_detail("dispatch_string source is exhausted")
    })?;
    if length == 1 {
        let byte = *source.bytes.get(source.byte_position).ok_or_else(|| {
            Error::new(ErrorKind::Malformed).with_detail("dispatch_string range is invalid")
        })?;
        output.push(byte);
        source.position = source
            .position
            .checked_add(1)
            .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
        source.byte_position = source
            .byte_position
            .checked_add(1)
            .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
        return Ok(());
    }

    let length = usize::try_from(length)
        .map_err(|_| Error::new(ErrorKind::LimitExceeded).with_detail("string length too large"))?;
    let offset = source.byte_position;
    let end = offset
        .checked_add(length)
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
    let bytes = source.bytes.get(offset..end).ok_or_else(|| {
        Error::new(ErrorKind::Malformed).with_detail("dispatch_string range is invalid")
    })?;
    output.extend_from_slice(bytes);
    source.position = source
        .position
        .checked_add(1)
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
    source.byte_position = end;
    Ok(())
}

pub(super) fn decode_dispatch_n_by_tag_node(
    inputs: &[StreamInput<'_>],
    variable_inputs: u32,
    header: &[u8],
    format_version: u32,
    limits: Limits,
) -> Result<Vec<u8>> {
    require_empty_header(header, "dispatchN_byTag headers are unsupported")?;
    let (tags, segment_sizes, segment_inputs, segment_count) =
        n_by_tag_shape(inputs, variable_inputs, format_version)?;
    let total_output =
        check_n_by_tag_segments(tags, segment_sizes, segment_inputs, segment_count, limits)?;
    let mut output = Vec::new();
    fast_dispatch::decode_dispatch_n_by_tag_to_output(
        tags,
        segment_sizes,
        segment_inputs,
        segment_count,
        total_output,
        &mut output,
    )?;
    if output.len() != total_output {
        return Err(
            Error::new(ErrorKind::Malformed).with_detail("dispatchN_byTag output size mismatch")
        );
    }
    Ok(output)
}

/// Splits a dispatchN_byTag node's inputs into tags, segment sizes and
/// source streams, and returns the segment count.
fn n_by_tag_shape<'a, 'b>(
    inputs: &'a [StreamInput<'b>],
    variable_inputs: u32,
    format_version: u32,
) -> Result<(
    &'a StreamInput<'b>,
    &'a StreamInput<'b>,
    &'a [StreamInput<'b>],
    usize,
)> {
    let variable_inputs = usize::try_from(variable_inputs)
        .map_err(|_| Error::new(ErrorKind::LimitExceeded).with_detail("input count too large"))?;
    if inputs.len()
        != variable_inputs
            .checked_add(2)
            .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?
    {
        return Err(Error::new(ErrorKind::InvalidGraph)
            .with_detail("dispatchN_byTag input count does not match node shape"));
    }
    let [tags, segment_sizes, segment_inputs @ ..] = inputs else {
        return Err(Error::new(ErrorKind::InvalidGraph)
            .with_detail("dispatchN_byTag input count does not match node shape"));
    };
    if segment_inputs.len() != variable_inputs {
        return Err(Error::new(ErrorKind::InvalidGraph)
            .with_detail("dispatchN_byTag variable input count does not match node shape"));
    }
    let expected_tag_width = if format_version < 20 { 1 } else { 2 };
    if tags.element_width > expected_tag_width {
        return Err(Error::new(ErrorKind::Unsupported)
            .with_detail("dispatchN_byTag tag width is unsupported"));
    }
    validate_numeric_stream_width(tags.element_width, "dispatchN_byTag tags")?;
    validate_numeric_stream_width(segment_sizes.element_width, "dispatchN_byTag segment sizes")?;
    let segment_count = numeric_element_count(segment_sizes.bytes, segment_sizes.element_width)?;
    if numeric_element_count(tags.bytes, tags.element_width)? != segment_count {
        return Err(Error::new(ErrorKind::Malformed)
            .with_detail("dispatchN_byTag tag count does not match segment count"));
    }
    if segment_count != 0 && segment_inputs.is_empty() {
        return Err(Error::new(ErrorKind::Malformed)
            .with_detail("dispatchN_byTag segments require source streams"));
    }
    if format_version < 20 && segment_inputs.len() >= 256 {
        return Err(Error::new(ErrorKind::Unsupported)
            .with_detail("dispatchN_byTag source count is unsupported"));
    }
    if format_version >= 20 && segment_inputs.len() >= (1usize << 16) {
        return Err(Error::new(ErrorKind::Unsupported)
            .with_detail("dispatchN_byTag source count is unsupported"));
    }
    Ok((tags, segment_sizes, segment_inputs, segment_count))
}

/// Checks that the segments of each tag add up to its source stream, and
/// returns the total output size.
fn check_n_by_tag_segments(
    tags: &StreamInput<'_>,
    segment_sizes: &StreamInput<'_>,
    segment_inputs: &[StreamInput<'_>],
    segment_count: usize,
    limits: Limits,
) -> Result<usize> {
    let mut source_totals = Vec::new();
    source_totals
        .try_reserve_exact(segment_inputs.len())
        .map_err(|_| {
            Error::new(ErrorKind::AllocationFailed).with_detail("dispatchN_byTag allocation failed")
        })?;
    let mut total_output = 0usize;
    for input in segment_inputs {
        if input.element_width == 0 {
            return Err(Error::new(ErrorKind::InvalidType)
                .with_detail("dispatchN_byTag source width is zero"));
        }
        source_totals.push(0usize);
        total_output = total_output
            .checked_add(input.bytes.len())
            .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
    }
    check_output_len(total_output, limits)?;

    for segment in 0..segment_count {
        let tag = read_usize_numeric_element(tags.bytes, tags.element_width, segment)?;
        let size =
            read_usize_numeric_element(segment_sizes.bytes, segment_sizes.element_width, segment)?;
        let source_total = source_totals.get_mut(tag).ok_or_else(|| {
            Error::new(ErrorKind::Malformed).with_detail("dispatchN_byTag tag is out of range")
        })?;
        *source_total = source_total
            .checked_add(size)
            .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
    }
    for (total, input) in source_totals.iter().zip(segment_inputs) {
        if *total != input.bytes.len() {
            return Err(Error::new(ErrorKind::Malformed)
                .with_detail("dispatchN_byTag segment sizes do not consume source stream"));
        }
    }
    Ok(total_output)
}
