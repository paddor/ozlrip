use alloc::vec::Vec;

use ozlrip_core::{Error, ErrorKind, Limits, Result};

#[cfg(not(feature = "paranoid"))]
use super::fast_csv;
use super::{
    OwnedStream, StreamInput, checked_sum_u32, fast_dispatch, numeric_element_count,
    read_usize_numeric_element, require_numeric_width, validate_numeric_stream_width,
};

pub(super) fn decode_dispatch_string_node(
    inputs: &[StreamInput<'_>],
    variable_inputs: u32,
    header: &[u8],
    format_version: u32,
    limits: Limits,
) -> Result<OwnedStream> {
    if !header.is_empty() {
        return Err(
            Error::new(ErrorKind::Malformed).with_detail("dispatch_string header must be empty")
        );
    }
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
    let mut sources = Vec::new();
    sources
        .try_reserve_exact(string_inputs.len())
        .map_err(|_| {
            Error::new(ErrorKind::LimitExceeded).with_detail("dispatch allocation failed")
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
        let byte_total = checked_sum_u32(lengths)?;
        if byte_total != input.bytes.len() {
            return Err(Error::new(ErrorKind::Malformed)
                .with_detail("dispatch_string input lengths do not sum to content size"));
        }
        total_string_count = total_string_count
            .checked_add(lengths.len())
            .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
        total_bytes = total_bytes
            .checked_add(byte_total)
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
    if total_bytes > limits.max_decoded_bytes || total_bytes > limits.max_buffer_bytes {
        return Err(
            Error::new(ErrorKind::LimitExceeded).with_detail("decoded output limit exceeded")
        );
    }
    let mut output = Vec::new();
    output.try_reserve_exact(total_bytes).map_err(|_| {
        Error::new(ErrorKind::LimitExceeded).with_detail("dispatch output allocation failed")
    })?;
    let mut output_lengths = Vec::new();
    output_lengths.try_reserve_exact(index_count).map_err(|_| {
        Error::new(ErrorKind::LimitExceeded).with_detail("dispatch length allocation failed")
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
            for source in indices.bytes.chunks_exact(2) {
                append_dispatched_string(
                    usize::from(u16::from_le_bytes([source[0], source[1]])),
                    &mut sources,
                    &mut output,
                    &mut output_lengths,
                )?;
            }
        }
        _ => unreachable!("require_numeric_width accepted only the expected dispatch width"),
    }
    for source in sources {
        if source.position != source.lengths.len() || source.byte_position != source.bytes.len() {
            return Err(Error::new(ErrorKind::Malformed)
                .with_detail("dispatch_string did not consume every source string"));
        }
    }
    Ok(OwnedStream {
        bytes: output,
        element_width: 1,
        string_lengths: Some(output_lengths),
        recyclable: false,
    })
}

pub(super) struct DispatchStringSource<'a> {
    pub(super) bytes: &'a [u8],
    pub(super) lengths: &'a [u32],
    pub(super) position: usize,
    pub(super) byte_position: usize,
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
    if !header.is_empty() {
        return Err(
            Error::new(ErrorKind::Malformed).with_detail("dispatch_string header must be empty")
        );
    }
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

    let mut sources = Vec::new();
    sources
        .try_reserve_exact(string_inputs.len())
        .map_err(|_| {
            Error::new(ErrorKind::LimitExceeded).with_detail("dispatch allocation failed")
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
        // Direct-append inputs are internal graph streams. String-producing
        // nodes already validated that their length tables sum to byte length.
        let byte_total = input.bytes.len();
        total_string_count = total_string_count
            .checked_add(lengths.len())
            .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
        total_bytes = total_bytes
            .checked_add(byte_total)
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
    if total_bytes > limits.max_decoded_bytes || total_bytes > limits.max_buffer_bytes {
        return Err(
            Error::new(ErrorKind::LimitExceeded).with_detail("decoded output limit exceeded")
        );
    }
    output.try_reserve_exact(total_bytes).map_err(|_| {
        Error::new(ErrorKind::LimitExceeded).with_detail("dispatch output allocation failed")
    })?;

    match indices.element_width {
        1 => {
            for &source in indices.bytes {
                append_dispatched_string_to_serial(usize::from(source), &mut sources, output)?;
            }
        }
        2 => {
            #[cfg(not(feature = "paranoid"))]
            if sources.len() > 6
                && append_dispatched_string_2byte_csv_wide_header_pattern_fast(
                    indices.bytes,
                    &mut sources,
                    output,
                )?
            {
                return Ok(());
            }
            if sources.len() == 5 {
                #[cfg(not(feature = "paranoid"))]
                if append_dispatched_string_2byte_csv_pattern_fast(
                    indices.bytes,
                    &mut sources,
                    output,
                )? {
                    return Ok(());
                }
                append_dispatched_string_2byte_csv_pattern(indices.bytes, &mut sources, output)?;
            } else if sources.len() == 6 {
                #[cfg(not(feature = "paranoid"))]
                if append_dispatched_string_2byte_csv_header_pattern_fast(
                    indices.bytes,
                    &mut sources,
                    output,
                )? {
                    return Ok(());
                }
                for source in indices.bytes.chunks_exact(2) {
                    append_dispatched_string_to_serial(
                        usize::from(u16::from_le_bytes([source[0], source[1]])),
                        &mut sources,
                        output,
                    )?;
                }
            } else {
                for source in indices.bytes.chunks_exact(2) {
                    append_dispatched_string_to_serial(
                        usize::from(u16::from_le_bytes([source[0], source[1]])),
                        &mut sources,
                        output,
                    )?;
                }
            }
        }
        _ => unreachable!("require_numeric_width accepted only the expected dispatch width"),
    }
    for source in sources {
        if source.position != source.lengths.len() || source.byte_position != source.bytes.len() {
            return Err(Error::new(ErrorKind::Malformed)
                .with_detail("dispatch_string did not consume every source string"));
        }
    }
    Ok(())
}

#[cfg(not(feature = "paranoid"))]
fn append_dispatched_string_2byte_csv_wide_header_pattern_fast(
    indices: &[u8],
    sources: &mut [DispatchStringSource<'_>],
    output: &mut Vec<u8>,
) -> Result<bool> {
    let data_sources = sources
        .len()
        .checked_sub(2)
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
    if data_sources == 0 {
        return Ok(false);
    }
    let delimiter_source = data_sources;
    let header_source = data_sources + 1;
    // Indices are read as `u16`, and `header_source` is the largest index the
    // pattern refers to, so it must round-trip through `u16` without wrapping.
    let (Ok(delimiter_index), Ok(header_index)) = (
        u16::try_from(delimiter_source),
        u16::try_from(header_source),
    ) else {
        return Ok(false);
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
    let trailing_delimiter_bytes = 2usize;

    if indices.len() < header_bytes + trailing_delimiter_bytes
        || !(indices.len() - header_bytes - trailing_delimiter_bytes).is_multiple_of(row_bytes)
    {
        return Ok(false);
    }
    if !indices[..header_bytes]
        .chunks_exact(2)
        .all(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]) == header_index)
    {
        return Ok(false);
    }
    let rows_end = indices.len() - trailing_delimiter_bytes;
    if u16::from_le_bytes([indices[rows_end], indices[rows_end + 1]]) != delimiter_index {
        return Ok(false);
    }
    let rows = (rows_end - header_bytes) / row_bytes;
    let row_indices = &indices[header_bytes..rows_end];
    if !csv_wide_header_row_indices_match(row_indices, rows, delimiter_index) {
        return Ok(false);
    }

    for source in &sources[..data_sources] {
        if source.lengths.len().saturating_sub(source.position) != rows {
            return Ok(false);
        }
        if source.bytes.len().saturating_sub(source.byte_position)
            != remaining_string_bytes(source)?
        {
            return Ok(false);
        }
    }

    let delimiter_count = rows
        .checked_mul(data_sources)
        .and_then(|count| count.checked_add(1))
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
    let delimiter = &sources[delimiter_source];
    if delimiter.lengths.len().saturating_sub(delimiter.position) != delimiter_count
        || delimiter
            .bytes
            .len()
            .saturating_sub(delimiter.byte_position)
            != delimiter_count
        || !delimiter.lengths[delimiter.position..]
            .iter()
            .all(|&length| length == 1)
    {
        return Ok(false);
    }

    let header = &sources[header_source];
    if header.lengths.len().saturating_sub(header.position) != header_fields
        || header.bytes.len().saturating_sub(header.byte_position)
            != remaining_string_bytes(header)?
    {
        return Ok(false);
    }

    fast_csv::append_wide_header_pattern(
        rows,
        data_sources,
        delimiter_source,
        header_source,
        sources,
        output,
    )?;
    Ok(true)
}

#[cfg(not(feature = "paranoid"))]
fn remaining_string_bytes(source: &DispatchStringSource<'_>) -> Result<usize> {
    source.lengths[source.position..]
        .iter()
        .try_fold(0usize, |sum, &length| {
            sum.checked_add(length as usize)
                .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))
        })
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
    let fixed_prefix = fixed_length_source_remaining(&sources[0], rows, 10)
        && fixed_length_source_remaining(&sources[1], rows, 3);
    let variable_sources = if fixed_prefix {
        &sources[2..4]
    } else {
        &sources[..4]
    };
    for source in variable_sources {
        if source.lengths.len().saturating_sub(source.position) != rows {
            return Ok(false);
        }
        let remaining_len =
            source.lengths[source.position..]
                .iter()
                .try_fold(0usize, |sum, &length| {
                    sum.checked_add(length as usize)
                        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))
                })?;
        if source.bytes.len().saturating_sub(source.byte_position) != remaining_len {
            return Ok(false);
        }
    }
    let delimiter_count = rows
        .checked_mul(4)
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
    if sources[4].lengths.len().saturating_sub(sources[4].position) != delimiter_count
        || !sources[4].lengths[sources[4].position..]
            .iter()
            .all(|&length| length == 1)
    {
        return Ok(false);
    }
    if sources[4]
        .bytes
        .len()
        .saturating_sub(sources[4].byte_position)
        != delimiter_count
    {
        return Ok(false);
    }

    if !chunks_match_16(indices, CSV_PATTERN) {
        return Ok(false);
    }

    if fixed_prefix && delimiter_bytes_match_csv_rows(&sources[4], rows) {
        fast_csv::append_2byte_csv_fixed_prefix_comma_pattern_rows(rows, sources, output)?;
        return Ok(true);
    }
    if fixed_prefix {
        fast_csv::append_2byte_csv_fixed_prefix_pattern_rows(rows, sources, output)?;
        return Ok(true);
    }

    fast_csv::append_2byte_csv_pattern_rows(rows, sources, output)?;
    Ok(true)
}

#[cfg(not(feature = "paranoid"))]
fn append_dispatched_string_2byte_csv_header_pattern_fast(
    indices: &[u8],
    sources: &mut [DispatchStringSource<'_>],
    output: &mut Vec<u8>,
) -> Result<bool> {
    const HEADER_SOURCE: u16 = 5;
    const HEADER_FIELDS: usize = 7;
    const ROW_PATTERN: [u8; 16] = [4, 0, 0, 0, 4, 0, 1, 0, 4, 0, 2, 0, 4, 0, 3, 0];
    const TRAILING_DELIMITER: [u8; 2] = [4, 0];

    let header_bytes = HEADER_FIELDS
        .checked_mul(2)
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
    if indices.len() < header_bytes + TRAILING_DELIMITER.len()
        || !(indices.len() - header_bytes - TRAILING_DELIMITER.len())
            .is_multiple_of(ROW_PATTERN.len())
    {
        return Ok(false);
    }
    if !indices[..header_bytes]
        .chunks_exact(2)
        .all(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]) == HEADER_SOURCE)
    {
        return Ok(false);
    }
    let row_bytes_end = indices.len() - TRAILING_DELIMITER.len();
    if indices[row_bytes_end..] != TRAILING_DELIMITER {
        return Ok(false);
    }
    if !chunks_match_16(&indices[header_bytes..row_bytes_end], ROW_PATTERN) {
        return Ok(false);
    }

    let rows = (row_bytes_end - header_bytes) / ROW_PATTERN.len();
    let fixed_prefix = fixed_length_source_remaining(&sources[0], rows, 10)
        && fixed_length_source_remaining(&sources[1], rows, 3);
    let variable_sources = if fixed_prefix {
        &sources[2..4]
    } else {
        &sources[..4]
    };
    for source in variable_sources {
        if source.lengths.len().saturating_sub(source.position) != rows {
            return Ok(false);
        }
        let remaining_len =
            source.lengths[source.position..]
                .iter()
                .try_fold(0usize, |sum, &length| {
                    sum.checked_add(length as usize)
                        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))
                })?;
        if source.bytes.len().saturating_sub(source.byte_position) != remaining_len {
            return Ok(false);
        }
    }

    let delimiter_count = rows
        .checked_mul(4)
        .and_then(|count| count.checked_add(1))
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
    if sources[4].lengths.len().saturating_sub(sources[4].position) != delimiter_count
        || !sources[4].lengths[sources[4].position..]
            .iter()
            .all(|&length| length == 1)
    {
        return Ok(false);
    }
    if sources[4]
        .bytes
        .len()
        .saturating_sub(sources[4].byte_position)
        != delimiter_count
    {
        return Ok(false);
    }

    if sources[5].lengths.len().saturating_sub(sources[5].position) != HEADER_FIELDS {
        return Ok(false);
    }
    let header_len =
        sources[5].lengths[sources[5].position..]
            .iter()
            .try_fold(0usize, |sum, &length| {
                sum.checked_add(length as usize)
                    .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))
            })?;
    if sources[5]
        .bytes
        .len()
        .saturating_sub(sources[5].byte_position)
        != header_len
    {
        return Ok(false);
    }

    for _ in 0..HEADER_FIELDS {
        append_dispatched_string_to_serial(5, sources, output)?;
    }
    if fixed_prefix && delimiter_bytes_match_csv_header_rows(&sources[4], rows) {
        fast_csv::append_2byte_csv_fixed_prefix_comma_header_pattern_rows(rows, sources, output)?;
        return Ok(true);
    }
    if fixed_prefix {
        fast_csv::append_2byte_csv_fixed_prefix_header_pattern_rows(rows, sources, output)?;
        return Ok(true);
    }
    fast_csv::append_2byte_csv_header_pattern_rows(rows, sources, output)?;
    Ok(true)
}

#[cfg(not(feature = "paranoid"))]
fn fixed_length_source_remaining(
    source: &DispatchStringSource<'_>,
    count: usize,
    length: usize,
) -> bool {
    let Some(byte_count) = count.checked_mul(length) else {
        return false;
    };
    source.lengths.len().saturating_sub(source.position) == count
        && source.bytes.len().saturating_sub(source.byte_position) == byte_count
        && source.lengths[source.position..]
            .iter()
            .all(|&candidate| candidate as usize == length)
}

#[cfg(not(feature = "paranoid"))]
fn delimiter_bytes_match_csv_rows(source: &DispatchStringSource<'_>, rows: usize) -> bool {
    let Some(byte_count) = rows.checked_mul(4) else {
        return false;
    };
    let remaining = &source.bytes[source.byte_position..];
    remaining.len() == byte_count && chunks_match_4(remaining, *b",,,\n")
}

#[cfg(not(feature = "paranoid"))]
fn delimiter_bytes_match_csv_header_rows(source: &DispatchStringSource<'_>, rows: usize) -> bool {
    let Some(row_delimiter_bytes) = rows.checked_mul(4) else {
        return false;
    };
    let Some(byte_count) = row_delimiter_bytes.checked_add(1) else {
        return false;
    };
    let remaining = &source.bytes[source.byte_position..];
    remaining.len() == byte_count
        && remaining.first() == Some(&b'\n')
        && chunks_match_4(&remaining[1..], *b",,,\n")
}

#[cfg(not(feature = "paranoid"))]
fn chunks_match_16(bytes: &[u8], pattern: [u8; 16]) -> bool {
    debug_assert!(bytes.len().is_multiple_of(16));
    let expected = u128::from_le_bytes(pattern);
    let mut offset = 0usize;
    while offset < bytes.len() {
        let actual = unsafe {
            // SAFETY: caller gives 16-byte chunks; loop offset stays within
            // `bytes` and read is explicitly unaligned.
            bytes.as_ptr().add(offset).cast::<u128>().read_unaligned()
        };
        if u128::from_le(actual) != expected {
            return false;
        }
        offset += 16;
    }
    true
}

#[cfg(not(feature = "paranoid"))]
fn chunks_match_4(bytes: &[u8], pattern: [u8; 4]) -> bool {
    debug_assert!(bytes.len().is_multiple_of(4));
    let expected = u32::from_le_bytes(pattern);
    let mut offset = 0usize;
    while offset < bytes.len() {
        let actual = unsafe {
            // SAFETY: caller gives 4-byte chunks; loop offset stays within
            // `bytes` and read is explicitly unaligned.
            bytes.as_ptr().add(offset).cast::<u32>().read_unaligned()
        };
        if u32::from_le(actual) != expected {
            return false;
        }
        offset += 4;
    }
    true
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
    if !header.is_empty() {
        return Err(
            Error::new(ErrorKind::Malformed).with_detail("dispatchN_byTag header must be empty")
        );
    }
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

    let mut source_totals = Vec::new();
    source_totals
        .try_reserve_exact(segment_inputs.len())
        .map_err(|_| {
            Error::new(ErrorKind::LimitExceeded).with_detail("dispatchN_byTag allocation failed")
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
    if total_output > limits.max_decoded_bytes || total_output > limits.max_buffer_bytes {
        return Err(
            Error::new(ErrorKind::LimitExceeded).with_detail("decoded output limit exceeded")
        );
    }

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
