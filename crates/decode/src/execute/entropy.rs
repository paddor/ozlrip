use alloc::{format, vec, vec::Vec};

use ozlrip_core::{Error, ErrorKind, Limits, Result};
use zrip_core::{
    bitstream::{reader::BitReader, reader_reverse::ReverseBitReader},
    fse::{
        FseDecodeEntry,
        table_builder::{build_decode_table, parse_fse_table_description},
    },
    huffman::{HuffmanDecodeEntry, decode},
};

use super::{OwnedStream, StreamInput, numeric_element_count, require_numeric_width};

pub(super) fn decode_fse_ncount_node(
    source: StreamInput<'_>,
    header: &[u8],
    limits: Limits,
) -> Result<OwnedStream> {
    if !header.is_empty() {
        return Err(
            Error::new(ErrorKind::Unsupported).with_detail("fse_ncount headers are unsupported")
        );
    }
    if source.element_width != 1 {
        return Err(
            Error::new(ErrorKind::InvalidType).with_detail("fse_ncount input must be serial")
        );
    }

    let mut reader = BitReader::new(source.bytes);
    let (mut distribution, _accuracy_log) = parse_fse_table_description(&mut reader, u8::MAX)
        .map_err(|err| {
            Error::new(ErrorKind::Malformed).with_detail(format!("invalid fse_ncount: {err}"))
        })?;
    if reader.bytes_consumed() != source.bytes.len() {
        return Err(
            Error::new(ErrorKind::Malformed).with_detail("fse_ncount input has trailing bytes")
        );
    }
    while distribution.last().copied() == Some(0) {
        distribution.pop();
    }

    let output_len = distribution
        .len()
        .checked_mul(2)
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
    if output_len > limits.max_decoded_bytes || output_len > limits.max_buffer_bytes {
        return Err(
            Error::new(ErrorKind::LimitExceeded).with_detail("decoded output limit exceeded")
        );
    }

    let mut output = Vec::new();
    output.try_reserve_exact(output_len).map_err(|_| {
        Error::new(ErrorKind::LimitExceeded).with_detail("fse_ncount allocation failed")
    })?;
    for count in distribution {
        output.extend_from_slice(&count.to_le_bytes());
    }
    Ok(OwnedStream::typed(output, 2))
}

pub(super) fn decode_fse_v2_node(
    inputs: &[StreamInput<'_>],
    header: &[u8],
    limits: Limits,
) -> Result<Vec<u8>> {
    let [norm, bits] = inputs else {
        return Err(Error::new(ErrorKind::InvalidGraph)
            .with_detail("fse_v2 input count does not match node shape"));
    };
    require_numeric_width(norm, 2, "fse_v2 normalized counts")?;
    if bits.element_width != 1 {
        return Err(Error::new(ErrorKind::InvalidType).with_detail("fse_v2 bits must be serial"));
    }

    let parsed = parse_fse_v2_header(header)?;
    if parsed.output_len > limits.max_decoded_bytes || parsed.output_len > limits.max_buffer_bytes {
        return Err(
            Error::new(ErrorKind::LimitExceeded).with_detail("decoded output limit exceeded")
        );
    }

    let mut distribution = Vec::new();
    distribution
        .try_reserve_exact(numeric_element_count(norm.bytes, 2)?)
        .map_err(|_| {
            Error::new(ErrorKind::LimitExceeded).with_detail("fse distribution allocation failed")
        })?;
    for count in norm.bytes.chunks_exact(2) {
        distribution.push(i16::from_le_bytes(count.try_into().map_err(|_| {
            Error::new(ErrorKind::Malformed).with_detail("invalid fse count")
        })?));
    }
    let accuracy_log = validate_fse_distribution(&distribution)?;
    let table = build_decode_table(&distribution, accuracy_log).map_err(|err| {
        Error::new(ErrorKind::Malformed).with_detail(format!("invalid fse_v2 table: {err}"))
    })?;
    decode_fse_symbols(
        bits.bytes,
        parsed.output_len,
        parsed.nb_states,
        &table,
        accuracy_log,
    )
}

#[derive(Clone, Copy)]
struct FseV2Header {
    nb_states: usize,
    output_len: usize,
}

fn parse_fse_v2_header(header: &[u8]) -> Result<FseV2Header> {
    if !(2..=9).contains(&header.len()) {
        return Err(Error::new(ErrorKind::Malformed).with_detail("fse_v2 header is malformed"));
    }
    let nb_states = usize::from(header[0]);
    if !matches!(nb_states, 2 | 4) {
        return Err(
            Error::new(ErrorKind::Unsupported).with_detail("fse_v2 state count is unsupported")
        );
    }
    let mut output_len = 0u64;
    for (shift, &byte) in header[1..].iter().enumerate() {
        let bit_shift = shift
            .checked_mul(8)
            .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
        output_len |= u64::from(byte) << bit_shift;
    }
    if output_len < 2 {
        return Err(Error::new(ErrorKind::Malformed)
            .with_detail("fse_v2 output count must be at least two"));
    }
    let output_len = usize::try_from(output_len).map_err(|_| {
        Error::new(ErrorKind::LimitExceeded).with_detail("fse_v2 output size is too large")
    })?;
    Ok(FseV2Header {
        nb_states,
        output_len,
    })
}

fn validate_fse_distribution(distribution: &[i16]) -> Result<u8> {
    if distribution.len() < 2 || distribution.len() > 256 {
        return Err(
            Error::new(ErrorKind::Malformed).with_detail("fse_v2 normalized count size is invalid")
        );
    }
    let mut sum = 0u32;
    for &count in distribution {
        if count < -1 {
            return Err(
                Error::new(ErrorKind::Malformed).with_detail("fse_v2 normalized count is invalid")
            );
        }
        if count == -1 {
            sum = sum
                .checked_add(1)
                .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
        } else {
            sum = sum
                .checked_add(u32::try_from(count).map_err(|_| {
                    Error::new(ErrorKind::Malformed).with_detail("fse_v2 count is invalid")
                })?)
                .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
        }
    }
    if sum == 0 || !sum.is_power_of_two() {
        return Err(
            Error::new(ErrorKind::Malformed).with_detail("fse_v2 normalized count sum is invalid")
        );
    }
    let accuracy_log = u8::try_from(sum.ilog2()).map_err(|_| Error::new(ErrorKind::Malformed))?;
    if !(zrip_core::fse::MIN_TABLE_LOG..=zrip_core::fse::MAX_TABLE_LOG).contains(&accuracy_log) {
        return Err(Error::new(ErrorKind::Malformed).with_detail("fse_v2 table log is unsupported"));
    }
    Ok(accuracy_log)
}

#[derive(Clone, Copy)]
struct OpenZlFseState<'a> {
    table: &'a [FseDecodeEntry],
    state: u32,
}

impl<'a> OpenZlFseState<'a> {
    #[expect(
        clippy::inline_always,
        reason = "profiled FSE v2 loops benefit from inlining state setup"
    )]
    #[inline(always)]
    fn new(
        table: &'a [FseDecodeEntry],
        accuracy_log: u8,
        reader: &mut ReverseBitReader<'_>,
    ) -> Result<Self> {
        let state = reader
            .read_bits(accuracy_log)
            .map_err(|err| Error::new(ErrorKind::Malformed).with_detail(format!("{err}")))?;
        Ok(Self { table, state })
    }

    #[expect(
        clippy::inline_always,
        reason = "profiled FSE v2 loops pay measurable call overhead"
    )]
    #[inline(always)]
    fn symbol(self) -> Result<u8> {
        let index = usize::try_from(self.state).map_err(|_| Error::new(ErrorKind::Malformed))?;
        Ok(self
            .table
            .get(index)
            .ok_or_else(|| Error::new(ErrorKind::Malformed).with_detail("fse state is invalid"))?
            .symbol)
    }

    #[expect(
        clippy::inline_always,
        reason = "disassembly showed standalone update calls in the FSE hot loop"
    )]
    #[inline(always)]
    fn update(&mut self, reader: &mut ReverseBitReader<'_>) -> Result<()> {
        let index = usize::try_from(self.state).map_err(|_| Error::new(ErrorKind::Malformed))?;
        let entry = self
            .table
            .get(index)
            .ok_or_else(|| Error::new(ErrorKind::Malformed).with_detail("fse state is invalid"))?;
        let bits = reader
            .read_bits(entry.num_bits)
            .map_err(|err| Error::new(ErrorKind::Malformed).with_detail(format!("{err}")))?;
        self.state = u32::from(entry.base_line)
            .checked_add(bits)
            .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
        Ok(())
    }
}

fn decode_fse_symbols(
    bits: &[u8],
    output_len: usize,
    nb_states: usize,
    table: &[FseDecodeEntry],
    accuracy_log: u8,
) -> Result<Vec<u8>> {
    let mut reader = ReverseBitReader::new(bits)
        .map_err(|err| Error::new(ErrorKind::Malformed).with_detail(format!("{err}")))?;

    let mut output = Vec::new();
    output.try_reserve_exact(output_len).map_err(|_| {
        Error::new(ErrorKind::LimitExceeded).with_detail("fse output allocation failed")
    })?;
    match nb_states {
        2 => {
            let mut states = [
                OpenZlFseState::new(table, accuracy_log, &mut reader)?,
                OpenZlFseState::new(table, accuracy_log, &mut reader)?,
            ];
            decode_fse_symbols_2(&mut reader, &mut states, output_len, &mut output)?;
        }
        4 => {
            let mut states = [
                OpenZlFseState::new(table, accuracy_log, &mut reader)?,
                OpenZlFseState::new(table, accuracy_log, &mut reader)?,
                OpenZlFseState::new(table, accuracy_log, &mut reader)?,
                OpenZlFseState::new(table, accuracy_log, &mut reader)?,
            ];
            decode_fse_symbols_4(&mut reader, &mut states, output_len, &mut output)?;
        }
        _ => {
            return Err(
                Error::new(ErrorKind::Unsupported).with_detail("fse_v2 state count is unsupported")
            );
        }
    }
    if reader.bits_remaining() != 0 {
        return Err(Error::new(ErrorKind::Malformed).with_detail("fse_v2 input has trailing bits"));
    }
    Ok(output)
}

#[expect(
    clippy::inline_always,
    reason = "profiled FSE v2 fixed-state loop benefits from inlining"
)]
#[inline(always)]
fn decode_fse_symbols_2(
    reader: &mut ReverseBitReader<'_>,
    states: &mut [OpenZlFseState<'_>; 2],
    output_len: usize,
    output: &mut Vec<u8>,
) -> Result<()> {
    let update_len = output_len - 2;
    let mut index = 0usize;
    while index < update_len {
        output.push(states[0].symbol()?);
        states[0].update(reader)?;
        index += 1;
        if index >= update_len {
            break;
        }
        output.push(states[1].symbol()?);
        states[1].update(reader)?;
        index += 1;
    }
    while index < output_len {
        output.push(states[index & 1].symbol()?);
        index += 1;
    }
    Ok(())
}

#[expect(
    clippy::inline_always,
    reason = "profiled FSE v2 fixed-state loop benefits from inlining"
)]
#[inline(always)]
fn decode_fse_symbols_4(
    reader: &mut ReverseBitReader<'_>,
    states: &mut [OpenZlFseState<'_>; 4],
    output_len: usize,
    output: &mut Vec<u8>,
) -> Result<()> {
    let update_len = output_len - 4;
    let mut index = 0usize;
    while index < update_len {
        output.push(states[0].symbol()?);
        states[0].update(reader)?;
        index += 1;
        if index >= update_len {
            break;
        }
        output.push(states[1].symbol()?);
        states[1].update(reader)?;
        index += 1;
        if index >= update_len {
            break;
        }
        output.push(states[2].symbol()?);
        states[2].update(reader)?;
        index += 1;
        if index >= update_len {
            break;
        }
        output.push(states[3].symbol()?);
        states[3].update(reader)?;
        index += 1;
    }
    while index < output_len {
        output.push(states[index & 3].symbol()?);
        index += 1;
    }
    Ok(())
}

pub(super) fn decode_huffman_v2_node(
    inputs: &[StreamInput<'_>],
    header: &[u8],
    limits: Limits,
) -> Result<Vec<u8>> {
    let [weights, bits] = inputs else {
        return Err(Error::new(ErrorKind::InvalidGraph)
            .with_detail("huffman_v2 input count does not match node shape"));
    };
    require_numeric_width(weights, 1, "huffman_v2 weights")?;
    if bits.element_width != 1 {
        return Err(
            Error::new(ErrorKind::InvalidType).with_detail("huffman_v2 bits must be serial")
        );
    }
    let parsed = parse_huffman_v2_header(header)?;
    if parsed.output_len > limits.max_decoded_bytes || parsed.output_len > limits.max_buffer_bytes {
        return Err(
            Error::new(ErrorKind::LimitExceeded).with_detail("decoded output limit exceeded")
        );
    }
    let (table, table_log) = build_complete_huffman_decode_table(weights.bytes)?;
    let decoded = if parsed.x4 {
        decode::decode_4_streams(&table, table_log, bits.bytes, parsed.output_len)
    } else {
        decode::decode_single_stream(&table, table_log, bits.bytes, parsed.output_len)
    }
    .map_err(|err| Error::new(ErrorKind::Malformed).with_detail(format!("{err}")))?;
    Ok(decoded)
}

pub(super) fn decode_huffman_struct_v2_node(
    inputs: &[StreamInput<'_>],
    header: &[u8],
    limits: Limits,
) -> Result<OwnedStream> {
    let [weights, bits] = inputs else {
        return Err(Error::new(ErrorKind::InvalidGraph)
            .with_detail("huffman_struct_v2 input count does not match node shape"));
    };
    require_numeric_width(weights, 1, "huffman_struct_v2 weights")?;
    if bits.element_width != 1 {
        return Err(
            Error::new(ErrorKind::InvalidType).with_detail("huffman_struct_v2 bits must be serial")
        );
    }

    let parsed = parse_huffman_struct_v2_header(header)?;
    let output_bytes = parsed
        .output_len
        .checked_mul(2)
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
    if output_bytes > limits.max_decoded_bytes || output_bytes > limits.max_buffer_bytes {
        return Err(
            Error::new(ErrorKind::LimitExceeded).with_detail("decoded output limit exceeded")
        );
    }

    let (table, table_log) = build_large_huffman_decode_table(weights.bytes)?;
    let mut output = Vec::new();
    output.try_reserve_exact(output_bytes).map_err(|_| {
        Error::new(ErrorKind::LimitExceeded).with_detail("huffman_struct_v2 allocation failed")
    })?;
    if parsed.x4 {
        decode_large_huffman_streams_x4(
            &table,
            table_log,
            bits.bytes,
            parsed.output_len,
            &mut output,
        )?;
    } else {
        decode_large_huffman_stream_with_size_prefix(
            &table,
            table_log,
            bits.bytes,
            parsed.output_len,
            &mut output,
        )?;
    }
    Ok(OwnedStream::typed(output, 2))
}

#[derive(Clone, Copy)]
struct HuffmanV2Header {
    x4: bool,
    output_len: usize,
}

fn parse_huffman_v2_header(header: &[u8]) -> Result<HuffmanV2Header> {
    if !(2..=9).contains(&header.len()) {
        return Err(Error::new(ErrorKind::Malformed).with_detail("huffman_v2 header is malformed"));
    }
    let x4 = (header[0] & 1) != 0;
    let mut output_len = 0u64;
    for (shift, &byte) in header[1..].iter().enumerate() {
        let bit_shift = shift
            .checked_mul(8)
            .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
        output_len |= u64::from(byte) << bit_shift;
    }
    if output_len < 2 {
        return Err(Error::new(ErrorKind::Malformed)
            .with_detail("huffman_v2 output count must be at least two"));
    }
    let output_len = usize::try_from(output_len).map_err(|_| {
        Error::new(ErrorKind::LimitExceeded).with_detail("huffman_v2 output size is too large")
    })?;
    Ok(HuffmanV2Header { x4, output_len })
}

fn parse_huffman_struct_v2_header(header: &[u8]) -> Result<HuffmanV2Header> {
    if !(2..=9).contains(&header.len()) {
        return Err(
            Error::new(ErrorKind::Malformed).with_detail("huffman_struct_v2 header is malformed")
        );
    }
    let x4 = (header[0] & 1) != 0;
    let mut output_len = 0u64;
    for (shift, &byte) in header[1..].iter().enumerate() {
        let bit_shift = shift
            .checked_mul(8)
            .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
        output_len |= u64::from(byte) << bit_shift;
    }
    if output_len < 2 {
        return Err(Error::new(ErrorKind::Malformed)
            .with_detail("huffman_struct_v2 output count must be at least two"));
    }
    let output_len = usize::try_from(output_len).map_err(|_| {
        Error::new(ErrorKind::LimitExceeded)
            .with_detail("huffman_struct_v2 output size is too large")
    })?;
    Ok(HuffmanV2Header { x4, output_len })
}

fn build_complete_huffman_decode_table(weights: &[u8]) -> Result<(Vec<HuffmanDecodeEntry>, u8)> {
    if weights.len() < 2 || weights.len() > 256 {
        return Err(
            Error::new(ErrorKind::Malformed).with_detail("huffman_v2 weight count is invalid")
        );
    }
    let mut sum = 0u32;
    let mut non_zero = 0usize;
    for &weight in weights {
        if weight > 12 {
            return Err(
                Error::new(ErrorKind::Malformed).with_detail("huffman_v2 weight is invalid")
            );
        }
        if weight != 0 {
            non_zero = non_zero
                .checked_add(1)
                .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
            sum = sum
                .checked_add(1u32 << (u32::from(weight) - 1))
                .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
        }
    }
    if non_zero < 2 || sum == 0 || !sum.is_power_of_two() {
        return Err(
            Error::new(ErrorKind::Malformed).with_detail("huffman_v2 weights are not normalized")
        );
    }
    let table_log = u8::try_from(sum.ilog2()).map_err(|_| Error::new(ErrorKind::Malformed))?;
    if table_log > 12 {
        return Err(Error::new(ErrorKind::Malformed).with_detail("huffman_v2 table is too large"));
    }
    let table_size = 1usize
        .checked_shl(u32::from(table_log))
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
    let mut table = vec![HuffmanDecodeEntry::default(); table_size];
    let max_weight = table_log
        .checked_add(1)
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
    let mut rank_count = vec![0u32; usize::from(max_weight) + 1];
    for &weight in weights {
        if weight != 0 {
            let count = rank_count.get_mut(usize::from(weight)).ok_or_else(|| {
                Error::new(ErrorKind::Malformed).with_detail("huffman_v2 weight is out of range")
            })?;
            *count = count
                .checked_add(1)
                .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
        }
    }

    let mut rank_start = vec![0u32; usize::from(max_weight) + 1];
    let mut cumulative = 0u32;
    for weight in 1..=max_weight {
        rank_start[usize::from(weight)] = cumulative;
        cumulative = cumulative
            .checked_add(
                rank_count[usize::from(weight)]
                    .checked_mul(1u32 << (u32::from(weight) - 1))
                    .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?,
            )
            .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
    }

    for (symbol, &weight) in weights.iter().enumerate() {
        if weight == 0 {
            continue;
        }
        let num_bits = max_weight - weight;
        let entries = 1usize
            .checked_shl(u32::from(weight) - 1)
            .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
        let start = usize::try_from(rank_start[usize::from(weight)])
            .map_err(|_| Error::new(ErrorKind::LimitExceeded))?;
        let end = start
            .checked_add(entries)
            .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
        if end > table.len() {
            return Err(
                Error::new(ErrorKind::Malformed).with_detail("huffman_v2 decode table overflows")
            );
        }
        rank_start[usize::from(weight)] =
            u32::try_from(end).map_err(|_| Error::new(ErrorKind::LimitExceeded))?;
        let symbol = u8::try_from(symbol).map_err(|_| Error::new(ErrorKind::Malformed))?;
        table[start..end].fill(HuffmanDecodeEntry { symbol, num_bits });
    }
    Ok((table, table_log))
}

const LARGE_HUFFMAN_MAX_TABLE_LOG: u8 = 20;

#[derive(Clone, Copy, Default)]
struct LargeHuffmanDecodeEntry {
    symbol: u16,
    num_bits: u8,
}

fn build_large_huffman_decode_table(weights: &[u8]) -> Result<(Vec<LargeHuffmanDecodeEntry>, u8)> {
    if weights.len() < 2 || weights.len() > 65_536 {
        return Err(Error::new(ErrorKind::Malformed)
            .with_detail("huffman_struct_v2 weight count is invalid"));
    }

    let mut sum = 0u64;
    let mut non_zero = 0usize;
    for &weight in weights {
        if weight > LARGE_HUFFMAN_MAX_TABLE_LOG {
            return Err(
                Error::new(ErrorKind::Malformed).with_detail("huffman_struct_v2 weight is invalid")
            );
        }
        if weight != 0 {
            non_zero = non_zero
                .checked_add(1)
                .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
            sum = sum
                .checked_add(1u64 << (u32::from(weight) - 1))
                .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
        }
    }
    if non_zero < 2 || sum == 0 || !sum.is_power_of_two() {
        return Err(Error::new(ErrorKind::Malformed)
            .with_detail("huffman_struct_v2 weights are not normalized"));
    }

    let table_log = u8::try_from(sum.ilog2()).map_err(|_| Error::new(ErrorKind::Malformed))?;
    if table_log > LARGE_HUFFMAN_MAX_TABLE_LOG {
        return Err(
            Error::new(ErrorKind::Malformed).with_detail("huffman_struct_v2 table is too large")
        );
    }
    if weights.iter().any(|&weight| weight > table_log) {
        return Err(Error::new(ErrorKind::Malformed)
            .with_detail("huffman_struct_v2 weights are not normalized"));
    }

    let table_size = 1usize
        .checked_shl(u32::from(table_log))
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
    let mut table = Vec::new();
    table.try_reserve_exact(table_size).map_err(|_| {
        Error::new(ErrorKind::LimitExceeded).with_detail("huffman_struct_v2 table is too large")
    })?;
    table.resize(table_size, LargeHuffmanDecodeEntry::default());

    let max_weight = table_log
        .checked_add(1)
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
    let mut rank_count = vec![0u32; usize::from(max_weight) + 1];
    for &weight in weights {
        if weight != 0 {
            let count = rank_count.get_mut(usize::from(weight)).ok_or_else(|| {
                Error::new(ErrorKind::Malformed)
                    .with_detail("huffman_struct_v2 weight is out of range")
            })?;
            *count = count
                .checked_add(1)
                .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
        }
    }

    let mut rank_start = vec![0u32; usize::from(max_weight) + 1];
    let mut cumulative = 0u32;
    for weight in 1..=table_log {
        rank_start[usize::from(weight)] = cumulative;
        cumulative = cumulative
            .checked_add(
                rank_count[usize::from(weight)]
                    .checked_mul(1u32 << (u32::from(weight) - 1))
                    .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?,
            )
            .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
    }

    for (symbol, &weight) in weights.iter().enumerate() {
        if weight == 0 {
            continue;
        }
        let num_bits = max_weight - weight;
        let entries = 1usize
            .checked_shl(u32::from(weight) - 1)
            .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
        let start = usize::try_from(rank_start[usize::from(weight)])
            .map_err(|_| Error::new(ErrorKind::LimitExceeded))?;
        let end = start
            .checked_add(entries)
            .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
        if end > table.len() {
            return Err(Error::new(ErrorKind::Malformed)
                .with_detail("huffman_struct_v2 decode table overflows"));
        }
        rank_start[usize::from(weight)] =
            u32::try_from(end).map_err(|_| Error::new(ErrorKind::LimitExceeded))?;
        let symbol = u16::try_from(symbol).map_err(|_| Error::new(ErrorKind::Malformed))?;
        table[start..end].fill(LargeHuffmanDecodeEntry { symbol, num_bits });
    }
    Ok((table, table_log))
}

fn decode_large_huffman_stream_with_size_prefix(
    table: &[LargeHuffmanDecodeEntry],
    table_log: u8,
    bits: &[u8],
    expected_output_len: usize,
    output: &mut Vec<u8>,
) -> Result<()> {
    if bits.len() < 8 {
        return Err(Error::new(ErrorKind::Malformed)
            .with_detail("huffman_struct_v2 bitstream is malformed"));
    }
    let output_len = u32::from_le_bytes(
        bits[0..4]
            .try_into()
            .map_err(|_| Error::new(ErrorKind::Malformed))?,
    ) as usize;
    let source_len = u32::from_le_bytes(
        bits[4..8]
            .try_into()
            .map_err(|_| Error::new(ErrorKind::Malformed))?,
    ) as usize;
    let source_end = 8usize
        .checked_add(source_len)
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
    if output_len != expected_output_len || source_end != bits.len() {
        return Err(Error::new(ErrorKind::Malformed)
            .with_detail("huffman_struct_v2 bitstream size is invalid"));
    }
    decode_large_huffman_stream(table, table_log, &bits[8..source_end], output_len, output)
}

fn decode_large_huffman_streams_x4(
    table: &[LargeHuffmanDecodeEntry],
    table_log: u8,
    bits: &[u8],
    expected_output_len: usize,
    output: &mut Vec<u8>,
) -> Result<()> {
    let mut cursor = 0usize;
    let mut decoded = 0usize;
    for _ in 0..4 {
        if bits.len().saturating_sub(cursor) < 8 {
            return Err(Error::new(ErrorKind::Malformed)
                .with_detail("huffman_struct_v2 x4 bitstream is malformed"));
        }
        let output_len = u32::from_le_bytes(
            bits[cursor..cursor + 4]
                .try_into()
                .map_err(|_| Error::new(ErrorKind::Malformed))?,
        ) as usize;
        let source_len = u32::from_le_bytes(
            bits[cursor + 4..cursor + 8]
                .try_into()
                .map_err(|_| Error::new(ErrorKind::Malformed))?,
        ) as usize;
        cursor = cursor
            .checked_add(8)
            .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
        let source_end = cursor
            .checked_add(source_len)
            .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
        if source_end > bits.len() {
            return Err(Error::new(ErrorKind::Malformed)
                .with_detail("huffman_struct_v2 x4 source size is invalid"));
        }
        decoded = decoded
            .checked_add(output_len)
            .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
        if decoded > expected_output_len {
            return Err(Error::new(ErrorKind::Malformed)
                .with_detail("huffman_struct_v2 x4 output size is invalid"));
        }
        decode_large_huffman_stream(
            table,
            table_log,
            &bits[cursor..source_end],
            output_len,
            output,
        )?;
        cursor = source_end;
    }
    if decoded != expected_output_len || cursor != bits.len() {
        return Err(Error::new(ErrorKind::Malformed)
            .with_detail("huffman_struct_v2 x4 bitstream size is invalid"));
    }
    Ok(())
}

fn decode_large_huffman_stream(
    table: &[LargeHuffmanDecodeEntry],
    table_log: u8,
    bits: &[u8],
    output_len: usize,
    output: &mut Vec<u8>,
) -> Result<()> {
    if table_log == 0 || table_log > LARGE_HUFFMAN_MAX_TABLE_LOG {
        return Err(
            Error::new(ErrorKind::Malformed).with_detail("huffman_struct_v2 table is invalid")
        );
    }
    let table_size = 1usize
        .checked_shl(u32::from(table_log))
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
    if table.len() < table_size {
        return Err(
            Error::new(ErrorKind::Malformed).with_detail("huffman_struct_v2 table is invalid")
        );
    }

    let mut reader = ReverseBitReader::new(bits)
        .map_err(|err| Error::new(ErrorKind::Malformed).with_detail(format!("{err}")))?;
    let tl = table_log as usize;
    for _ in 0..output_len {
        reader.refill();
        let remaining = reader.bits_remaining();
        if remaining == 0 {
            return Err(Error::new(ErrorKind::Malformed)
                .with_detail("huffman_struct_v2 bitstream ended early"));
        }
        let bits = if remaining >= tl {
            reader.peek_bits(table_log)
        } else {
            reader.peek_bits(remaining as u8) << (tl - remaining)
        };
        let entry = table
            .get(bits as usize)
            .ok_or_else(|| Error::new(ErrorKind::Malformed))?;
        if entry.num_bits as usize > remaining {
            return Err(Error::new(ErrorKind::Malformed)
                .with_detail("huffman_struct_v2 bitstream ended inside symbol"));
        }
        output.extend_from_slice(&entry.symbol.to_le_bytes());
        reader.consume_bits(entry.num_bits);
    }

    if reader.bits_remaining() != 0 {
        return Err(Error::new(ErrorKind::Malformed)
            .with_detail("huffman_struct_v2 bitstream has trailing bits"));
    }
    Ok(())
}
