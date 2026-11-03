//! Huffman blocks of the legacy entropy container: zstd's Huffman format
//! for bytes and upstream's large-alphabet format for 16-bit symbols.

use alloc::format;
use alloc::vec::Vec;

use ozlrip_core::{Error, ErrorKind, Limits, Result};
use zrip_core::huffman::decode;
use zrip_core::huffman::weights::parse_huffman_weights;

use super::huffman::{
    LARGE_HUFFMAN_MAX_TABLE_LOG, build_complete_huffman_decode_table,
    build_large_huffman_decode_table, decode_large_huffman_stream_with_size_prefix,
    decode_large_huffman_streams_x4,
};
use super::legacy::{
    LegacyLimit, LegacyParams, checked_legacy_entropy_output_len, parse_legacy_block,
    read_legacy_compressed_entropy_header,
};
use crate::execute::elements::read_var_u64;

/// A legacy entropy Huffman block: zstd's Huffman literals format for bytes,
/// upstream's large-alphabet format for 16-bit symbols.
pub(in crate::execute) fn decode_legacy_huffman_block(
    source: &[u8],
    offset: &mut usize,
    element_width: usize,
    limits: Limits,
    transform_name: &str,
    max_depth: usize,
) -> Result<Vec<u8>> {
    let header = read_legacy_compressed_entropy_header(source, offset, transform_name)?;
    // No upstream encoder writes this layout. Only the deprecated fastlz
    // encoder allows it, for 16-bit symbols up to 1024, and its tokens reach
    // 2047.
    if header.avx2_huffman {
        return Err(Error::new(ErrorKind::Unsupported).with_detail(format!(
            "{transform_name} AVX2 Huffman layout is unsupported"
        )));
    }
    checked_legacy_entropy_output_len(header.decoded_elements, element_width, limits)?;
    let end = (*offset)
        .checked_add(header.encoded_len)
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
    let encoded = source
        .get(*offset..end)
        .ok_or_else(|| Error::new(ErrorKind::Malformed))?;
    let bytes = match element_width {
        1 => decode_legacy_huffman_bytes(encoded, header.decoded_elements, transform_name)?,
        2 => decode_legacy_huffman_u16(
            encoded,
            header.decoded_elements,
            limits,
            transform_name,
            max_depth,
        )?,
        _ => {
            return Err(Error::new(ErrorKind::Malformed)
                .with_detail(format!("{transform_name} huffman element width is invalid")));
        }
    };
    *offset = end;
    Ok(bytes)
}

/// Decodes upstream `HUF_decompress` input: a copy when it is as large as
/// the output, one repeated byte, or a Huffman tree and four streams.
fn decode_legacy_huffman_bytes(
    encoded: &[u8],
    output_len: usize,
    transform_name: &str,
) -> Result<Vec<u8>> {
    if output_len == 0 || encoded.len() > output_len {
        return Err(Error::new(ErrorKind::Malformed)
            .with_detail(format!("{transform_name} huffman block size is invalid")));
    }
    let alloc_failed = || {
        Error::new(ErrorKind::AllocationFailed)
            .with_detail(format!("{transform_name} allocation failed"))
    };
    if encoded.len() == output_len || encoded.len() == 1 {
        let mut output = Vec::new();
        output
            .try_reserve_exact(output_len)
            .map_err(|_| alloc_failed())?;
        if encoded.len() == output_len {
            output.extend_from_slice(encoded);
        } else {
            output.resize(output_len, encoded[0]);
        }
        return Ok(output);
    }
    let invalid = |err: zrip_core::DecompressError| {
        Error::new(ErrorKind::Malformed)
            .with_detail(format!("{transform_name} huffman block is invalid: {err}"))
    };
    let (weights, consumed) = parse_huffman_weights(encoded).map_err(invalid)?;
    let weights = complete_huffman_weights(&weights, transform_name)?;
    let (table, table_log) = build_complete_huffman_decode_table(&weights, transform_name)?;
    let streams = encoded
        .get(consumed..)
        .ok_or_else(|| Error::new(ErrorKind::Malformed))?;
    decode::decode_4_streams(&table, table_log, streams, output_len).map_err(invalid)
}

/// Adds the implied weight of the last symbol to zstd Huffman weights and
/// checks them as upstream `HUF_readStats` does.
fn complete_huffman_weights(explicit: &[u8], transform_name: &str) -> Result<Vec<u8>> {
    let invalid = || {
        Error::new(ErrorKind::Malformed)
            .with_detail(format!("{transform_name} huffman weights are invalid"))
    };
    let mut total = 0u32;
    let mut rank_one = 0usize;
    for &weight in explicit {
        if weight > HUFFMAN_MAX_TABLE_LOG {
            return Err(invalid());
        }
        if weight == 1 {
            rank_one += 1;
        }
        if weight != 0 {
            total += 1 << (weight - 1);
        }
    }
    if total == 0 {
        return Err(invalid());
    }
    let table_log = total.ilog2() + 1;
    if table_log > u32::from(HUFFMAN_MAX_TABLE_LOG) {
        return Err(invalid());
    }
    let rest = (1u32 << table_log) - total;
    if !rest.is_power_of_two() {
        return Err(invalid());
    }
    let last = u8::try_from(rest.ilog2() + 1).map_err(|_| invalid())?;
    if last == 1 {
        rank_one += 1;
    }
    if rank_one < 2 || rank_one % 2 == 1 {
        return Err(invalid());
    }
    let mut weights = Vec::with_capacity(explicit.len() + 1);
    weights.extend_from_slice(explicit);
    weights.push(last);
    Ok(weights)
}

/// Decodes upstream `ZS_largeHuffmanDecode` input to `output_elements`
/// little-endian 16-bit symbols.
fn decode_legacy_huffman_u16(
    encoded: &[u8],
    output_elements: usize,
    limits: Limits,
    transform_name: &str,
    max_depth: usize,
) -> Result<Vec<u8>> {
    let output_len = output_elements
        .checked_mul(2)
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
    let mut output = Vec::new();
    output.try_reserve_exact(output_len).map_err(|_| {
        Error::new(ErrorKind::AllocationFailed)
            .with_detail(format!("{transform_name} allocation failed"))
    })?;
    let (&prefix, _) = encoded.split_first().ok_or_else(|| {
        Error::new(ErrorKind::Malformed)
            .with_detail(format!("{transform_name} huffman block is empty"))
    })?;
    let block = LargeHuffmanBlock {
        encoded,
        output_elements,
        transform_name,
    };
    match prefix {
        LARGE_HUFFMAN_PREFIX_LITERAL | LARGE_HUFFMAN_PREFIX_CONSTANT => {
            block.decode_uncoded(prefix, &mut output)?;
        }
        LARGE_HUFFMAN_PREFIX_HUFFMAN => block.decode_coded(limits, max_depth, &mut output)?,
        _ => return Err(block.malformed("huffman block prefix is invalid")),
    }
    Ok(output)
}

/// An upstream `ZS_largeHuffmanDecode` block of 16-bit symbols.
struct LargeHuffmanBlock<'a> {
    encoded: &'a [u8],
    output_elements: usize,
    transform_name: &'a str,
}

impl LargeHuffmanBlock<'_> {
    fn malformed(&self, detail: &str) -> Error {
        Error::new(ErrorKind::Malformed).with_detail(format!("{} {detail}", self.transform_name))
    }

    /// A literal or constant block: the symbol count, then the symbols or
    /// the one repeated symbol.
    fn decode_uncoded(&self, prefix: u8, output: &mut Vec<u8>) -> Result<()> {
        let (encoded, output_elements) = (self.encoded, self.output_elements);
        let mut offset = 1usize;
        let count = read_var_u64(encoded, &mut offset)?;
        if usize::try_from(count).ok() != Some(output_elements) {
            return Err(self.malformed("huffman symbol count is invalid"));
        }
        let rest = &encoded[offset..];
        if prefix == LARGE_HUFFMAN_PREFIX_LITERAL {
            if rest.len() != output_elements * 2 {
                return Err(self.malformed("huffman literal size is invalid"));
            }
            output.extend_from_slice(rest);
        } else {
            let [low, high] = *rest else {
                return Err(self.malformed("huffman constant size is invalid"));
            };
            for _ in 0..output_elements {
                output.extend_from_slice(&[low, high]);
            }
        }
        Ok(())
    }

    /// A Huffman-coded block: table log, symbol count, nested weights, then
    /// one or four streams.
    fn decode_coded(&self, limits: Limits, max_depth: usize, output: &mut Vec<u8>) -> Result<()> {
        let (encoded, transform_name) = (self.encoded, self.transform_name);
        let mut offset = 1usize;
        let [table_log, low, high] = *encoded
            .get(offset..offset + 3)
            .ok_or_else(|| self.malformed("huffman table header is truncated"))?
        else {
            unreachable!("the slice holds three bytes");
        };
        offset += 3;
        if table_log == 0 || table_log > LARGE_HUFFMAN_MAX_TABLE_LOG {
            return Err(self.malformed("huffman table log is invalid"));
        }
        let symbols = usize::from(u16::from_le_bytes([low, high])) + 1;
        if max_depth == 0 {
            return Err(Error::new(ErrorKind::LimitExceeded)
                .with_detail(format!("{transform_name} entropy depth exceeds limit")));
        }
        let params = LegacyParams {
            element_width: 1,
            fse_states: LEGACY_ENTROPY_DEFAULT_FSE_STATES,
            limit: LegacyLimit::Output,
            limits,
            transform_name,
        };
        let weights = parse_legacy_block(encoded, &mut offset, params, max_depth - 1)?
            .into_vec(transform_name)?;
        if weights.len() != symbols {
            return Err(self.malformed("huffman weight count is invalid"));
        }
        let (table, derived_log) = build_large_huffman_decode_table(&weights, transform_name)?;
        if derived_log != table_log {
            return Err(self.malformed("huffman weights are not normalized"));
        }
        let x4 = *encoded
            .get(offset)
            .ok_or_else(|| self.malformed("huffman stream layout is missing"))?;
        let bits = &encoded[offset + 1..];
        if x4 != 0 {
            decode_large_huffman_streams_x4(
                &table,
                table_log,
                bits,
                self.output_elements,
                output,
                transform_name,
            )
        } else {
            decode_large_huffman_stream_with_size_prefix(
                &table,
                table_log,
                bits,
                self.output_elements,
                output,
                transform_name,
            )
        }
    }
}

/// Prefixes of upstream's large-alphabet Huffman blocks.
const LARGE_HUFFMAN_PREFIX_HUFFMAN: u8 = 0;

const LARGE_HUFFMAN_PREFIX_LITERAL: u8 = 1;

const LARGE_HUFFMAN_PREFIX_CONSTANT: u8 = 2;

/// Upstream's default FSE state count for nested legacy entropy blocks.
const LEGACY_ENTROPY_DEFAULT_FSE_STATES: usize = 2;

/// Largest zstd Huffman table log upstream `HUF_readStats` accepts.
const HUFFMAN_MAX_TABLE_LOG: u8 = 12;
