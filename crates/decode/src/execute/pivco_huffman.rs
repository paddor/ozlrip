use alloc::{vec, vec::Vec};
use core::cmp;

use ozlrip_core::{Error, ErrorKind, Limits, Result};

use super::{StreamInput, read_var_u64};

const MAX_SYMBOLS: usize = 256;
const MAX_TABLE_LOG: usize = 12;
const MAX_WEIGHT: usize = MAX_TABLE_LOG + 1;
const MAX_BLOCK_SIZE: usize = 1 << 28;

pub(super) fn decode_node(
    inputs: &[StreamInput<'_>],
    header: &[u8],
    limits: Limits,
) -> Result<Vec<u8>> {
    let [weights, bitstream] = inputs else {
        return Err(Error::new(ErrorKind::InvalidGraph)
            .with_detail("pivco_huffman input count does not match node shape"));
    };
    if weights.element_width != 1 || weights.string_lengths.is_some() {
        return Err(Error::new(ErrorKind::InvalidType)
            .with_detail("pivco_huffman weights stream must be byte numeric"));
    }
    if bitstream.element_width != 1 || bitstream.string_lengths.is_some() {
        return Err(Error::new(ErrorKind::InvalidType)
            .with_detail("pivco_huffman bitstream must be serial bytes"));
    }

    let header = parse_header(header)?;
    if header.decoded_size > limits.max_decoded_bytes
        || header.decoded_size > limits.max_buffer_bytes
    {
        return Err(
            Error::new(ErrorKind::LimitExceeded).with_detail("decoded output limit exceeded")
        );
    }

    if header.decoded_size == 0 {
        if !weights.bytes.is_empty() || !bitstream.bytes.is_empty() {
            return Err(Error::new(ErrorKind::Malformed)
                .with_detail("empty pivco_huffman output must have empty inputs"));
        }
        return Ok(Vec::new());
    }
    if weights.bytes.is_empty() {
        return Err(Error::new(ErrorKind::Malformed)
            .with_detail("non-empty pivco_huffman output requires weights"));
    }

    let tree = Tree::from_weights(weights.bytes)?;
    let mut reader = PivCoBitReader::new(bitstream.bytes);
    let mut output = Vec::new();
    output.try_reserve_exact(header.decoded_size).map_err(|_| {
        Error::new(ErrorKind::LimitExceeded).with_detail("pivco_huffman allocation failed")
    })?;

    let mut remaining = header.decoded_size;
    while remaining > 0 {
        let block_len = cmp::min(header.block_size, remaining);
        let decoded = decode_tree_node(&tree, &mut reader, 0, 0, tree.num_ranks, block_len)?;
        append_result(&mut output, decoded, block_len)?;
        remaining -= block_len;
    }

    if reader.consumed_bytes()? != bitstream.bytes.len() {
        return Err(Error::new(ErrorKind::Malformed)
            .with_detail("pivco_huffman bitstream was not consumed exactly"));
    }
    debug_assert_eq!(output.len(), header.decoded_size);
    Ok(output)
}

struct Header {
    decoded_size: usize,
    block_size: usize,
}

fn parse_header(header: &[u8]) -> Result<Header> {
    let mut offset = 0usize;
    let decoded_size = usize::try_from(read_var_u64(header, &mut offset)?).map_err(|_| {
        Error::new(ErrorKind::LimitExceeded).with_detail("pivco_huffman decoded size is too large")
    })?;
    let block_size = if offset == header.len() {
        if decoded_size > MAX_BLOCK_SIZE {
            return Err(Error::new(ErrorKind::Malformed)
                .with_detail("pivco_huffman single block is too large"));
        }
        decoded_size
    } else {
        let block_size = usize::try_from(read_var_u64(header, &mut offset)?).map_err(|_| {
            Error::new(ErrorKind::LimitExceeded)
                .with_detail("pivco_huffman block size is too large")
        })?;
        if block_size == 0 || block_size > MAX_BLOCK_SIZE {
            return Err(
                Error::new(ErrorKind::Malformed).with_detail("pivco_huffman block size is invalid")
            );
        }
        block_size
    };
    Ok(Header {
        decoded_size,
        block_size,
    })
}

#[derive(Clone)]
struct Leaf {
    symbols: Vec<u8>,
}

struct Tree {
    rank_to_symbol: Vec<u8>,
    rank_to_flat_depth: Vec<u8>,
    rank_to_codeword: Vec<u16>,
    num_levels: usize,
    num_ranks: usize,
}

impl Tree {
    fn from_weights(weights: &[u8]) -> Result<Self> {
        if weights.len() > MAX_SYMBOLS {
            return Err(
                Error::new(ErrorKind::Malformed).with_detail("pivco_huffman has too many weights")
            );
        }
        let table_log = compute_table_log(weights)?;
        let mut buckets = weight_buckets(weights)?;
        optimize_leaves(&mut buckets, table_log)?;

        let min_weight = (1..=MAX_WEIGHT)
            .find(|&weight| !buckets[weight].is_empty())
            .ok_or_else(|| {
                Error::new(ErrorKind::Malformed)
                    .with_detail("pivco_huffman weights contain no symbols")
            })?;
        if min_weight > table_log + 1 {
            return Err(
                Error::new(ErrorKind::Malformed).with_detail("pivco_huffman tree depth is invalid")
            );
        }
        let num_levels = table_log + 2 - min_weight;
        let mut tree = Self {
            rank_to_symbol: Vec::new(),
            rank_to_flat_depth: Vec::new(),
            rank_to_codeword: Vec::new(),
            num_levels,
            num_ranks: 0,
        };
        tree.assign_ranks_and_codewords(&buckets, table_log)?;
        if tree.num_ranks == 0 {
            return Err(
                Error::new(ErrorKind::Malformed).with_detail("pivco_huffman tree has no ranks")
            );
        }
        Ok(tree)
    }

    fn assign_ranks_and_codewords(
        &mut self,
        buckets: &[Vec<Leaf>],
        table_log: usize,
    ) -> Result<()> {
        self.rank_to_symbol
            .try_reserve_exact(MAX_SYMBOLS)
            .map_err(|_| {
                Error::new(ErrorKind::LimitExceeded)
                    .with_detail("pivco_huffman tree allocation failed")
            })?;
        self.rank_to_flat_depth
            .try_reserve_exact(MAX_SYMBOLS)
            .map_err(|_| {
                Error::new(ErrorKind::LimitExceeded)
                    .with_detail("pivco_huffman tree allocation failed")
            })?;
        self.rank_to_codeword
            .try_reserve_exact(MAX_SYMBOLS)
            .map_err(|_| {
                Error::new(ErrorKind::LimitExceeded)
                    .with_detail("pivco_huffman tree allocation failed")
            })?;

        let mut codeword = 0u32;
        for level in 0..self.num_levels {
            let weight = table_log + 1 - level;
            let leaves = buckets.get(weight).ok_or_else(|| {
                Error::new(ErrorKind::Malformed).with_detail("pivco_huffman weight is invalid")
            })?;
            for leaf in leaves {
                let flat_depth = flat_depth(leaf.symbols.len())?;
                let total_bits = level.checked_add(flat_depth).ok_or_else(|| {
                    Error::new(ErrorKind::IntegerOverflow)
                        .with_detail("pivco_huffman codeword length overflowed")
                })?;
                if total_bits > 16 {
                    return Err(Error::new(ErrorKind::Malformed)
                        .with_detail("pivco_huffman codeword is too wide"));
                }
                for (flat_index, &symbol) in leaf.symbols.iter().enumerate() {
                    let flat_index = u32::try_from(flat_index)
                        .map_err(|_| Error::new(ErrorKind::IntegerOverflow))?;
                    let bits = (codeword
                        .checked_shl(u32::try_from(flat_depth).map_err(|_| {
                            Error::new(ErrorKind::IntegerOverflow)
                                .with_detail("pivco_huffman flat depth overflowed")
                        })?)
                        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?)
                    .checked_add(flat_index)
                    .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
                    let code = if total_bits == 0 {
                        0
                    } else {
                        u16::try_from(bits << (16 - total_bits))
                            .map_err(|_| Error::new(ErrorKind::IntegerOverflow))?
                    };
                    self.rank_to_symbol.push(symbol);
                    self.rank_to_flat_depth
                        .push(u8::try_from(flat_depth).map_err(|_| {
                            Error::new(ErrorKind::IntegerOverflow)
                                .with_detail("pivco_huffman flat depth is too large")
                        })?);
                    self.rank_to_codeword.push(code);
                }
                codeword = codeword
                    .checked_add(1)
                    .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
            }
            if level + 1 < self.num_levels {
                codeword = codeword
                    .checked_shl(1)
                    .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
            }
        }

        let expected_codewords = 1u32
            .checked_shl(u32::try_from(self.num_levels - 1).map_err(|_| {
                Error::new(ErrorKind::IntegerOverflow)
                    .with_detail("pivco_huffman tree level overflowed")
            })?)
            .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
        if codeword != expected_codewords || self.rank_to_symbol.len() > MAX_SYMBOLS {
            return Err(Error::new(ErrorKind::Malformed)
                .with_detail("pivco_huffman weights do not form a complete tree"));
        }
        self.num_ranks = self.rank_to_symbol.len();
        Ok(())
    }

    fn range_is_leaf(&self, first_rank: usize, rank_end: usize) -> bool {
        let Some(&depth) = self.rank_to_flat_depth.get(first_rank) else {
            return false;
        };
        let Some(width) = 1usize.checked_shl(u32::from(depth)) else {
            return false;
        };
        width == rank_end.saturating_sub(first_rank)
    }

    fn range_is_constant_leaf(&self, first_rank: usize, rank_end: usize) -> bool {
        self.range_is_leaf(first_rank, rank_end) && self.rank_to_flat_depth[first_rank] == 0
    }

    fn split_rank(&self, level: usize, first_rank: usize, rank_end: usize) -> Result<usize> {
        if level >= self.num_levels || first_rank + 1 >= rank_end || rank_end > self.num_ranks {
            return Err(Error::new(ErrorKind::Malformed)
                .with_detail("pivco_huffman tree range cannot split"));
        }
        let mask = 0x8000u16
            .checked_shr(u32::try_from(level).map_err(|_| {
                Error::new(ErrorKind::IntegerOverflow)
                    .with_detail("pivco_huffman split level overflowed")
            })?)
            .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
        if (self.rank_to_codeword[first_rank] & mask) != 0 {
            return Err(
                Error::new(ErrorKind::Malformed).with_detail("pivco_huffman tree split is invalid")
            );
        }
        let mut split_rank = first_rank + 1;
        while split_rank < rank_end && (self.rank_to_codeword[split_rank] & mask) == 0 {
            split_rank += 1;
        }
        if split_rank >= rank_end {
            return Err(
                Error::new(ErrorKind::Malformed).with_detail("pivco_huffman tree split is invalid")
            );
        }
        Ok(split_rank)
    }
}

fn compute_table_log(weights: &[u8]) -> Result<usize> {
    if weights.is_empty() || weights.len() > MAX_SYMBOLS {
        return Err(
            Error::new(ErrorKind::Malformed).with_detail("pivco_huffman weights size is invalid")
        );
    }
    let mut sum = 0u32;
    for &weight in weights {
        if usize::from(weight) > MAX_TABLE_LOG {
            return Err(
                Error::new(ErrorKind::Malformed).with_detail("pivco_huffman weight is too large")
            );
        }
        sum = sum
            .checked_add((1u32 << u32::from(weight)) >> 1)
            .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
    }
    if sum == 0 || !sum.is_power_of_two() {
        return Err(
            Error::new(ErrorKind::Malformed).with_detail("pivco_huffman weights are incomplete")
        );
    }
    let table_log = u32::BITS as usize - 1 - sum.leading_zeros() as usize;
    if table_log > MAX_TABLE_LOG {
        return Err(
            Error::new(ErrorKind::Malformed).with_detail("pivco_huffman table log is too large")
        );
    }
    Ok(table_log)
}

fn weight_buckets(weights: &[u8]) -> Result<Vec<Vec<Leaf>>> {
    let mut buckets = Vec::new();
    buckets.try_reserve_exact(MAX_WEIGHT + 1).map_err(|_| {
        Error::new(ErrorKind::LimitExceeded).with_detail("pivco_huffman tree allocation failed")
    })?;
    for _ in 0..=MAX_WEIGHT {
        buckets.push(Vec::new());
    }
    for (symbol, &weight) in weights.iter().enumerate() {
        if weight == 0 {
            continue;
        }
        let weight = usize::from(weight);
        if weight > MAX_WEIGHT {
            return Err(
                Error::new(ErrorKind::Malformed).with_detail("pivco_huffman weight is invalid")
            );
        }
        buckets[weight].push(Leaf {
            symbols: vec![u8::try_from(symbol).map_err(|_| {
                Error::new(ErrorKind::IntegerOverflow)
                    .with_detail("pivco_huffman symbol index overflowed")
            })?],
        });
    }
    Ok(buckets)
}

fn optimize_leaves(buckets: &mut [Vec<Leaf>], table_log: usize) -> Result<()> {
    for weight in (1..=table_log).rev() {
        while buckets[weight].len() > 2 {
            let count = buckets[weight].len();
            let flat_bits = floor_log2(count);
            let flat_count = 1usize
                .checked_shl(u32::try_from(flat_bits).map_err(|_| {
                    Error::new(ErrorKind::IntegerOverflow)
                        .with_detail("pivco_huffman flat leaf size overflowed")
                })?)
                .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
            let flat_offset = count - flat_count;
            let flat_weight = weight
                .checked_add(flat_bits)
                .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
            if flat_weight > MAX_WEIGHT {
                return Err(Error::new(ErrorKind::Malformed)
                    .with_detail("pivco_huffman flat leaf weight is invalid"));
            }

            let peeled = buckets[weight].split_off(flat_offset);
            let mut symbols = Vec::new();
            symbols.try_reserve_exact(flat_count).map_err(|_| {
                Error::new(ErrorKind::LimitExceeded)
                    .with_detail("pivco_huffman tree allocation failed")
            })?;
            for leaf in peeled {
                let [symbol] = leaf.symbols.as_slice() else {
                    return Err(Error::new(ErrorKind::Malformed)
                        .with_detail("pivco_huffman flat leaf source is invalid"));
                };
                symbols.push(*symbol);
            }
            buckets[flat_weight].push(Leaf { symbols });
        }
    }
    Ok(())
}

fn flat_depth(symbols: usize) -> Result<usize> {
    if symbols == 0 || !symbols.is_power_of_two() {
        return Err(
            Error::new(ErrorKind::Malformed).with_detail("pivco_huffman leaf size is invalid")
        );
    }
    Ok(floor_log2(symbols))
}

fn floor_log2(value: usize) -> usize {
    usize::BITS as usize - 1 - value.leading_zeros() as usize
}

enum DecodeResult {
    Constant(u8),
    Bytes(Vec<u8>),
}

fn decode_tree_node(
    tree: &Tree,
    reader: &mut PivCoBitReader<'_>,
    level: usize,
    first_rank: usize,
    rank_end: usize,
    count: usize,
) -> Result<DecodeResult> {
    if tree.range_is_leaf(first_rank, rank_end) {
        return decode_leaf(tree, reader, first_rank, count);
    }
    if level >= tree.num_levels {
        return Err(Error::new(ErrorKind::Malformed)
            .with_detail("pivco_huffman tree range exceeds tree depth"));
    }

    let split_rank = tree.split_rank(level, first_rank, rank_end)?;
    let left_is_constant = tree.range_is_constant_leaf(first_rank, split_rank);
    let right_is_constant = tree.range_is_constant_leaf(split_rank, rank_end);
    let bitmap = reader.aligned_bitmap(count)?;

    let num_ones = if left_is_constant && right_is_constant {
        bitmap_ones(bitmap, count)
    } else {
        let encoded = reader.read_int(bits_needed(count + 1))?;
        if encoded > count {
            return Err(Error::new(ErrorKind::Malformed)
                .with_detail("pivco_huffman child count is too large"));
        }
        if encoded != bitmap_ones(bitmap, count) {
            return Err(Error::new(ErrorKind::Malformed)
                .with_detail("pivco_huffman child count does not match bitmap"));
        }
        encoded
    };
    let num_zeros = count - num_ones;

    let left = decode_tree_node(tree, reader, level + 1, first_rank, split_rank, num_zeros)?;
    let right = decode_tree_node(tree, reader, level + 1, split_rank, rank_end, num_ones)?;
    let merged = merge_results(bitmap, count, &left, num_zeros, &right, num_ones)?;
    Ok(DecodeResult::Bytes(merged))
}

fn decode_leaf(
    tree: &Tree,
    reader: &mut PivCoBitReader<'_>,
    first_rank: usize,
    count: usize,
) -> Result<DecodeResult> {
    let depth = usize::from(tree.rank_to_flat_depth[first_rank]);
    if depth == 0 {
        return Ok(DecodeResult::Constant(tree.rank_to_symbol[first_rank]));
    }
    let bitmap_bits = count
        .checked_mul(depth)
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
    let bitmap = reader.aligned_bitmap(bitmap_bits)?;
    let mut output = Vec::new();
    output.try_reserve_exact(count).map_err(|_| {
        Error::new(ErrorKind::LimitExceeded).with_detail("pivco_huffman allocation failed")
    })?;
    for index in 0..count {
        let symbol_index = read_bitmap_int(bitmap, index * depth, depth);
        let symbol = *tree
            .rank_to_symbol
            .get(first_rank + symbol_index)
            .ok_or_else(|| {
                Error::new(ErrorKind::Malformed)
                    .with_detail("pivco_huffman flat symbol index is invalid")
            })?;
        output.push(symbol);
    }
    Ok(DecodeResult::Bytes(output))
}

fn merge_results(
    bitmap: &[u8],
    count: usize,
    left: &DecodeResult,
    left_count: usize,
    right: &DecodeResult,
    right_count: usize,
) -> Result<Vec<u8>> {
    let mut output = Vec::new();
    output.try_reserve_exact(count).map_err(|_| {
        Error::new(ErrorKind::LimitExceeded).with_detail("pivco_huffman allocation failed")
    })?;
    let mut left_index = 0usize;
    let mut right_index = 0usize;
    for index in 0..count {
        if bitmap_bit(bitmap, index) {
            output.push(next_decoded_byte(right, &mut right_index)?);
        } else {
            output.push(next_decoded_byte(left, &mut left_index)?);
        }
    }
    if left_index != left_count || right_index != right_count {
        return Err(
            Error::new(ErrorKind::Malformed).with_detail("pivco_huffman merge count mismatch")
        );
    }
    Ok(output)
}

fn append_result(output: &mut Vec<u8>, result: DecodeResult, count: usize) -> Result<()> {
    match result {
        DecodeResult::Constant(symbol) => output.resize(output.len() + count, symbol),
        DecodeResult::Bytes(bytes) => {
            if bytes.len() != count {
                return Err(Error::new(ErrorKind::Malformed)
                    .with_detail("pivco_huffman decoded block size mismatch"));
            }
            output.extend_from_slice(&bytes);
        }
    }
    Ok(())
}

fn next_decoded_byte(result: &DecodeResult, index: &mut usize) -> Result<u8> {
    match result {
        DecodeResult::Constant(symbol) => {
            *index = index
                .checked_add(1)
                .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
            Ok(*symbol)
        }
        DecodeResult::Bytes(bytes) => {
            let byte = *bytes.get(*index).ok_or_else(|| {
                Error::new(ErrorKind::Malformed)
                    .with_detail("pivco_huffman decoded child is truncated")
            })?;
            *index = index
                .checked_add(1)
                .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
            Ok(byte)
        }
    }
}

struct PivCoBitReader<'a> {
    bytes: &'a [u8],
    bit_pos: usize,
}

impl<'a> PivCoBitReader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, bit_pos: 0 }
    }

    fn aligned_bitmap(&mut self, bits: usize) -> Result<&'a [u8]> {
        self.align_to_byte()?;
        let byte_start = self.bit_pos / 8;
        let byte_len = bits.div_ceil(8);
        let byte_end = byte_start
            .checked_add(byte_len)
            .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
        let bitmap = self.bytes.get(byte_start..byte_end).ok_or_else(|| {
            Error::new(ErrorKind::Truncated).with_detail("pivco_huffman bitstream is truncated")
        })?;
        self.bit_pos = self
            .bit_pos
            .checked_add(bits)
            .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
        Ok(bitmap)
    }

    fn read_int(&mut self, bits: usize) -> Result<usize> {
        if bits > usize::BITS as usize {
            return Err(Error::new(ErrorKind::Malformed)
                .with_detail("pivco_huffman integer bit width is too large"));
        }
        let end = self
            .bit_pos
            .checked_add(bits)
            .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
        if end > self.total_bits()? {
            return Err(Error::new(ErrorKind::Truncated)
                .with_detail("pivco_huffman bitstream is truncated"));
        }

        let mut value = 0usize;
        for bit in 0..bits {
            if self.bit_at(self.bit_pos + bit)? {
                value |= 1usize
                    .checked_shl(u32::try_from(bit).map_err(|_| {
                        Error::new(ErrorKind::IntegerOverflow)
                            .with_detail("pivco_huffman integer shift overflowed")
                    })?)
                    .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
            }
        }
        self.bit_pos = end;
        Ok(value)
    }

    fn consumed_bytes(&self) -> Result<usize> {
        if self.bit_pos > self.total_bits()? {
            return Err(Error::new(ErrorKind::Truncated)
                .with_detail("pivco_huffman bitstream is truncated"));
        }
        Ok(self.bit_pos.div_ceil(8))
    }

    fn align_to_byte(&mut self) -> Result<()> {
        let remainder = self.bit_pos % 8;
        if remainder != 0 {
            self.bit_pos = self
                .bit_pos
                .checked_add(8 - remainder)
                .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
        }
        if self.bit_pos > self.total_bits()? {
            return Err(Error::new(ErrorKind::Truncated)
                .with_detail("pivco_huffman bitstream is truncated"));
        }
        Ok(())
    }

    fn total_bits(&self) -> Result<usize> {
        self.bytes
            .len()
            .checked_mul(8)
            .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))
    }

    fn bit_at(&self, bit: usize) -> Result<bool> {
        let byte = *self.bytes.get(bit / 8).ok_or_else(|| {
            Error::new(ErrorKind::Truncated).with_detail("pivco_huffman bitstream is truncated")
        })?;
        Ok(((byte >> (bit % 8)) & 1) != 0)
    }
}

fn bits_needed(max_value: usize) -> usize {
    if max_value <= 1 {
        0
    } else {
        usize::BITS as usize - (max_value - 1).leading_zeros() as usize
    }
}

fn bitmap_ones(bitmap: &[u8], count: usize) -> usize {
    (0..count)
        .filter(|&index| bitmap_bit(bitmap, index))
        .count()
}

fn bitmap_bit(bitmap: &[u8], index: usize) -> bool {
    ((bitmap[index / 8] >> (index % 8)) & 1) != 0
}

fn read_bitmap_int(bitmap: &[u8], start_bit: usize, bits: usize) -> usize {
    let mut value = 0usize;
    for bit in 0..bits {
        if bitmap_bit(bitmap, start_bit + bit) {
            value |= 1 << bit;
        }
    }
    value
}

#[cfg(test)]
mod tests {
    use super::*;
    use ozlrip_core::ErrorKind;

    fn stream(bytes: &[u8]) -> StreamInput<'_> {
        StreamInput {
            bytes,
            element_width: 1,
            string_lengths: None,
        }
    }

    fn header(decoded_size: usize, block_size: Option<usize>) -> Vec<u8> {
        let mut header = Vec::new();
        push_var_u64(&mut header, u64::try_from(decoded_size).unwrap());
        if let Some(block_size) = block_size {
            push_var_u64(&mut header, u64::try_from(block_size).unwrap());
        }
        header
    }

    fn decode(weights: &[u8], bitstream: &[u8], header: &[u8]) -> Result<Vec<u8>> {
        decode_node(
            &[stream(weights), stream(bitstream)],
            header,
            Limits::default(),
        )
    }

    fn push_var_u64(out: &mut Vec<u8>, mut value: u64) {
        while value >= 0x80 {
            out.push(u8::try_from(value & 0x7f).unwrap() | 0x80);
            value >>= 7;
        }
        out.push(u8::try_from(value).unwrap());
    }

    #[test]
    fn decodes_empty_payload() {
        let output = decode(&[], &[], &header(0, None)).unwrap();

        assert!(output.is_empty());
    }

    #[test]
    fn decodes_constant_tree() {
        let mut weights = vec![0; 66];
        weights[65] = 1;

        let output = decode(&weights, &[], &header(4, None)).unwrap();

        assert_eq!(output, b"AAAA");
    }

    #[test]
    fn decodes_two_constant_children_from_partition_bitmap() {
        let weights = [1, 1];

        let output = decode(&weights, &[0b0000_0010], &header(3, None)).unwrap();

        assert_eq!(output, [0, 1, 0]);
    }

    #[test]
    fn decodes_flat_leaf() {
        let weights = [1, 1, 1, 1];

        let output = decode(&weights, &[0xe4], &header(4, None)).unwrap();

        assert_eq!(output, [0, 1, 2, 3]);
    }

    #[test]
    fn decodes_internal_node_with_count_and_alignment() {
        let weights = [2, 1, 1];

        let output = decode(&weights, &[0x26, 0x02], &header(4, None)).unwrap();

        assert_eq!(output, [0, 1, 2, 0]);
    }

    #[test]
    fn decodes_multiple_blocks() {
        let weights = [1, 1];

        let output = decode(&weights, &[0x02, 0x01], &header(4, Some(2))).unwrap();

        assert_eq!(output, [0, 1, 1, 0]);
    }

    #[test]
    fn rejects_count_that_disagrees_with_bitmap() {
        let weights = [2, 1, 1];

        let err = decode(&weights, &[0x16, 0x02], &header(4, None)).unwrap_err();

        assert_eq!(err.kind(), ErrorKind::Malformed);
    }

    #[test]
    fn rejects_leftover_bitstream_bytes() {
        let mut weights = vec![0; 66];
        weights[65] = 1;

        let err = decode(&weights, &[0], &header(4, None)).unwrap_err();

        assert_eq!(err.kind(), ErrorKind::Malformed);
    }

    #[test]
    fn rejects_incomplete_weights() {
        let weights = [1, 1, 1];

        let err = decode(&weights, &[], &header(3, None)).unwrap_err();

        assert_eq!(err.kind(), ErrorKind::Malformed);
    }

    #[test]
    fn enforces_output_limit() {
        let weights = [1];
        let limits = Limits {
            max_decoded_bytes: 2,
            max_buffer_bytes: 2,
            ..Limits::default()
        };

        let err =
            decode_node(&[stream(&weights), stream(&[])], &header(3, None), limits).unwrap_err();

        assert_eq!(err.kind(), ErrorKind::LimitExceeded);
    }
}
