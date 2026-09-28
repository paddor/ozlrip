//! Huffman nodes: `huffman_v2` for bytes and `huffman_struct_v2` for
//! 16-bit symbols, with their decode tables and stream decoders.

use alloc::vec::Vec;
use alloc::{format, vec};

use ozlrip_core::{Error, ErrorKind, Limits, Result};
use zrip_core::bitstream::reader_reverse::ReverseBitReader;
use zrip_core::huffman::{DECODE_TABLE_SIZE, HuffmanDecodeEntry, decode};

use crate::execute::elements::require_numeric_width;
use crate::execute::output::check_output_len;
use crate::execute::streams::{OwnedStream, StreamInput};

pub(in crate::execute) fn decode_huffman_v2_node(
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
    check_output_len(parsed.output_len, limits)?;
    let (table, table_log) = build_complete_huffman_decode_table(weights.bytes, "huffman_v2")?;
    let decoded = if parsed.x4 {
        decode::decode_4_streams(&table, table_log, bits.bytes, parsed.output_len)
    } else {
        decode::decode_single_stream(&table, table_log, bits.bytes, parsed.output_len)
    }
    .map_err(|err| Error::new(ErrorKind::Malformed).with_detail(format!("{err}")))?;
    Ok(decoded)
}

pub(in crate::execute) fn decode_huffman_struct_v2_node(
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
    check_output_len(output_bytes, limits)?;

    let (table, table_log) = build_large_huffman_decode_table(weights.bytes, "huffman_struct_v2")?;
    let mut output = Vec::new();
    output.try_reserve_exact(output_bytes).map_err(|_| {
        Error::new(ErrorKind::AllocationFailed).with_detail("huffman_struct_v2 allocation failed")
    })?;
    if parsed.x4 {
        decode_large_huffman_streams_x4(
            &table,
            table_log,
            bits.bytes,
            parsed.output_len,
            &mut output,
            "huffman_struct_v2",
        )?;
    } else {
        decode_large_huffman_stream_with_size_prefix(
            &table,
            table_log,
            bits.bytes,
            parsed.output_len,
            &mut output,
            "huffman_struct_v2",
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

pub(super) fn build_complete_huffman_decode_table(
    weights: &[u8],
    name: &str,
) -> Result<(Vec<HuffmanDecodeEntry>, u8)> {
    if weights.len() < 2 || weights.len() > 256 {
        return Err(
            Error::new(ErrorKind::Malformed).with_detail(format!("{name} weight count is invalid"))
        );
    }
    let table_log = huffman_table_log(weights, 12, name)?;
    if table_log > 12 {
        return Err(
            Error::new(ErrorKind::Malformed).with_detail(format!("{name} table is too large"))
        );
    }
    // The format allows 12, but upstream encoders cap Huffman v2 and the
    // deprecated Huffman codecs at 11, and zrip decodes at most 11.
    if table_log > zrip_core::huffman::MAX_TABLE_LOG {
        return Err(Error::new(ErrorKind::Unsupported)
            .with_detail(format!("{name} table log 12 is unsupported")));
    }
    let table_size = 1usize
        .checked_shl(u32::from(table_log))
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
    // zrip's x4 decoder needs a full-size table; entries past `table_size`
    // stay unused.
    let mut table = vec![HuffmanDecodeEntry::default(); table_size.max(DECODE_TABLE_SIZE)];
    let max_weight = table_log
        .checked_add(1)
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
    let rank_count = huffman_rank_counts(weights, max_weight, name)?;
    let rank_start = huffman_rank_starts(&rank_count, max_weight)?;
    let ranks = HuffmanRanks {
        weights,
        max_weight,
        rank_start,
        name,
    };
    ranks.fill(&mut table, table_size, |symbol, num_bits| {
        let symbol = u8::try_from(symbol).map_err(|_| Error::new(ErrorKind::Malformed))?;
        Ok(HuffmanDecodeEntry { symbol, num_bits })
    })?;
    Ok((table, table_log))
}

/// Table log of Huffman weights: each nonzero weight `w` takes `2^(w-1)`
/// entries, and the entries of at least two symbols must add up to a power
/// of two.
fn huffman_table_log(weights: &[u8], max_weight: u8, name: &str) -> Result<u8> {
    let mut sum = 0u64;
    let mut non_zero = 0usize;
    for &weight in weights {
        if weight > max_weight {
            return Err(
                Error::new(ErrorKind::Malformed).with_detail(format!("{name} weight is invalid"))
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
            .with_detail(format!("{name} weights are not normalized")));
    }
    u8::try_from(sum.ilog2()).map_err(|_| Error::new(ErrorKind::Malformed))
}

/// Number of symbols with each weight, indexed by weight up to
/// `max_weight`.
fn huffman_rank_counts(weights: &[u8], max_weight: u8, name: &str) -> Result<Vec<u32>> {
    let mut rank_count = vec![0u32; usize::from(max_weight) + 1];
    for &weight in weights {
        if weight != 0 {
            let count = rank_count.get_mut(usize::from(weight)).ok_or_else(|| {
                Error::new(ErrorKind::Malformed)
                    .with_detail(format!("{name} weight is out of range"))
            })?;
            *count = count
                .checked_add(1)
                .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
        }
    }
    Ok(rank_count)
}

/// First table entry of each weight from 1 to `last_weight`, lighter
/// weights first.
fn huffman_rank_starts(rank_count: &[u32], last_weight: u8) -> Result<Vec<u32>> {
    let mut rank_start = vec![0u32; rank_count.len()];
    let mut cumulative = 0u32;
    for weight in 1..=last_weight {
        rank_start[usize::from(weight)] = cumulative;
        cumulative = cumulative
            .checked_add(
                rank_count[usize::from(weight)]
                    .checked_mul(1u32 << (u32::from(weight) - 1))
                    .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?,
            )
            .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
    }
    Ok(rank_start)
}

/// Huffman weights and the first free table entry of each weight.
struct HuffmanRanks<'a> {
    weights: &'a [u8],
    max_weight: u8,
    rank_start: Vec<u32>,
    name: &'a str,
}

impl HuffmanRanks<'_> {
    /// Fills each symbol's entries in `table[..limit]`, built by `entry`
    /// from the symbol and its code length.
    fn fill<E: Copy>(
        mut self,
        table: &mut [E],
        limit: usize,
        entry: impl Fn(usize, u8) -> Result<E>,
    ) -> Result<()> {
        for (symbol, &weight) in self.weights.iter().enumerate() {
            if weight == 0 {
                continue;
            }
            let num_bits = self.max_weight - weight;
            let entries = 1usize
                .checked_shl(u32::from(weight) - 1)
                .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
            let start = usize::try_from(self.rank_start[usize::from(weight)])
                .map_err(|_| Error::new(ErrorKind::LimitExceeded))?;
            let end = start
                .checked_add(entries)
                .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
            if end > limit {
                return Err(Error::new(ErrorKind::Malformed)
                    .with_detail(format!("{} decode table overflows", self.name)));
            }
            self.rank_start[usize::from(weight)] =
                u32::try_from(end).map_err(|_| Error::new(ErrorKind::LimitExceeded))?;
            table[start..end].fill(entry(symbol, num_bits)?);
        }
        Ok(())
    }
}

pub(super) const LARGE_HUFFMAN_MAX_TABLE_LOG: u8 = 20;

#[derive(Clone, Copy, Default)]
pub(super) struct LargeHuffmanDecodeEntry {
    symbol: u16,
    num_bits: u8,
}

pub(super) fn build_large_huffman_decode_table(
    weights: &[u8],
    name: &str,
) -> Result<(Vec<LargeHuffmanDecodeEntry>, u8)> {
    if weights.len() < 2 || weights.len() > 65_536 {
        return Err(
            Error::new(ErrorKind::Malformed).with_detail(format!("{name} weight count is invalid"))
        );
    }
    let table_log = huffman_table_log(weights, LARGE_HUFFMAN_MAX_TABLE_LOG, name)?;
    if table_log > LARGE_HUFFMAN_MAX_TABLE_LOG {
        return Err(
            Error::new(ErrorKind::Malformed).with_detail(format!("{name} table is too large"))
        );
    }
    if weights.iter().any(|&weight| weight > table_log) {
        return Err(Error::new(ErrorKind::Malformed)
            .with_detail(format!("{name} weights are not normalized")));
    }

    let table_size = 1usize
        .checked_shl(u32::from(table_log))
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
    let mut table = Vec::new();
    table.try_reserve_exact(table_size).map_err(|_| {
        Error::new(ErrorKind::AllocationFailed).with_detail(format!("{name} table is too large"))
    })?;
    table.resize(table_size, LargeHuffmanDecodeEntry::default());

    let max_weight = table_log
        .checked_add(1)
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
    let rank_count = huffman_rank_counts(weights, max_weight, name)?;
    let rank_start = huffman_rank_starts(&rank_count, table_log)?;
    let ranks = HuffmanRanks {
        weights,
        max_weight,
        rank_start,
        name,
    };
    ranks.fill(&mut table, table_size, |symbol, num_bits| {
        let symbol = u16::try_from(symbol).map_err(|_| Error::new(ErrorKind::Malformed))?;
        Ok(LargeHuffmanDecodeEntry { symbol, num_bits })
    })?;
    Ok((table, table_log))
}

pub(super) fn decode_large_huffman_stream_with_size_prefix(
    table: &[LargeHuffmanDecodeEntry],
    table_log: u8,
    bits: &[u8],
    expected_output_len: usize,
    output: &mut Vec<u8>,
    name: &str,
) -> Result<()> {
    if bits.len() < 8 {
        return Err(
            Error::new(ErrorKind::Malformed).with_detail(format!("{name} bitstream is malformed"))
        );
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
            .with_detail(format!("{name} bitstream size is invalid")));
    }
    decode_large_huffman_stream(
        table,
        table_log,
        &bits[8..source_end],
        output_len,
        output,
        name,
    )
}

pub(super) fn decode_large_huffman_streams_x4(
    table: &[LargeHuffmanDecodeEntry],
    table_log: u8,
    bits: &[u8],
    expected_output_len: usize,
    output: &mut Vec<u8>,
    name: &str,
) -> Result<()> {
    let mut cursor = 0usize;
    let mut decoded = 0usize;
    for _ in 0..4 {
        if bits.len().saturating_sub(cursor) < 8 {
            return Err(Error::new(ErrorKind::Malformed)
                .with_detail(format!("{name} x4 bitstream is malformed")));
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
                .with_detail(format!("{name} x4 source size is invalid")));
        }
        decoded = decoded
            .checked_add(output_len)
            .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
        if decoded > expected_output_len {
            return Err(Error::new(ErrorKind::Malformed)
                .with_detail(format!("{name} x4 output size is invalid")));
        }
        decode_large_huffman_stream(
            table,
            table_log,
            &bits[cursor..source_end],
            output_len,
            output,
            name,
        )?;
        cursor = source_end;
    }
    if decoded != expected_output_len || cursor != bits.len() {
        return Err(Error::new(ErrorKind::Malformed)
            .with_detail(format!("{name} x4 bitstream size is invalid")));
    }
    Ok(())
}

fn decode_large_huffman_stream(
    table: &[LargeHuffmanDecodeEntry],
    table_log: u8,
    bits: &[u8],
    output_len: usize,
    output: &mut Vec<u8>,
    name: &str,
) -> Result<()> {
    if table_log == 0 || table_log > LARGE_HUFFMAN_MAX_TABLE_LOG {
        return Err(
            Error::new(ErrorKind::Malformed).with_detail(format!("{name} table is invalid"))
        );
    }
    let table_size = 1usize
        .checked_shl(u32::from(table_log))
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
    if table.len() < table_size {
        return Err(
            Error::new(ErrorKind::Malformed).with_detail(format!("{name} table is invalid"))
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
                .with_detail(format!("{name} bitstream ended early")));
        }
        let bits = if remaining >= tl {
            reader.peek_bits(table_log)
        } else {
            let remaining = u8::try_from(remaining).map_err(|_| {
                Error::new(ErrorKind::Malformed)
                    .with_detail(format!("{name} bitstream is malformed"))
            })?;
            reader.peek_bits(remaining) << (tl - usize::from(remaining))
        };
        let entry = table
            .get(bits as usize)
            .ok_or_else(|| Error::new(ErrorKind::Malformed))?;
        if entry.num_bits as usize > remaining {
            return Err(Error::new(ErrorKind::Malformed)
                .with_detail(format!("{name} bitstream ended inside symbol")));
        }
        output.extend_from_slice(&entry.symbol.to_le_bytes());
        reader.consume_bits(entry.num_bits);
    }

    if reader.bits_remaining() != 0 {
        return Err(Error::new(ErrorKind::Malformed)
            .with_detail(format!("{name} bitstream has trailing bits")));
    }
    Ok(())
}
