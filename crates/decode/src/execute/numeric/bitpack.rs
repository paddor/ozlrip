//! The `bitpack` and `bitunpack` nodes.

use alloc::vec::Vec;

use ozlrip_core::{Error, ErrorKind, Limits, Result};

use super::fast_bitpack;
use crate::execute::elements::{
    numeric_element_count, read_element, validate_numeric_stream_width,
};
use crate::execute::output::check_output_len;
use crate::execute::runtime::DecodeScratch;
use crate::execute::streams::{OwnedStream, StreamInput};

pub(in crate::execute) fn decode_bitpack_serial_chunk(
    stored: &[u8],
    header: &[u8],
    limits: Limits,
    scratch: &mut DecodeScratch,
) -> Result<Vec<u8>> {
    let parsed = parse_bitpack_header(header, stored.len())?;
    if parsed.element_width != 1 {
        return Err(Error::new(ErrorKind::Unsupported)
            .with_detail("only serial byte bitpack output is implemented"));
    }
    decode_bitpack_chunk(stored, parsed, limits, scratch)
}

pub(in crate::execute) fn decode_bitpack_int_chunk(
    stored: &[u8],
    header: &[u8],
    limits: Limits,
    scratch: &mut DecodeScratch,
) -> Result<OwnedStream> {
    let parsed = parse_bitpack_header(header, stored.len())?;
    let element_width = parsed.element_width;
    Ok(OwnedStream {
        bytes: decode_bitpack_chunk(stored, parsed, limits, scratch)?,
        element_width,
        string_lengths: None,
        recyclable: true,
    })
}

fn decode_bitpack_chunk(
    stored: &[u8],
    parsed: BitpackHeader,
    limits: Limits,
    scratch: &mut DecodeScratch,
) -> Result<Vec<u8>> {
    let output_len = parsed
        .elements
        .checked_mul(parsed.element_width)
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
    check_output_len(output_len, limits)?;
    let mut output = scratch.take_byte_buffer(output_len, "bitpack allocation failed")?;
    fast_bitpack::unpack_lsb_bits(
        stored,
        parsed.bits,
        parsed.element_width,
        parsed.elements,
        &mut output,
    )?;
    Ok(output)
}

#[derive(Clone, Copy)]
struct BitpackHeader {
    element_width: usize,
    bits: usize,
    elements: usize,
}

fn parse_bitpack_header(header: &[u8], packed_len: usize) -> Result<BitpackHeader> {
    if header.is_empty() || header.len() > 2 {
        return Err(Error::new(ErrorKind::Malformed).with_detail("bitpack header is malformed"));
    }
    let element_width = 1usize
        .checked_shl(u32::from((header[0] >> 6) & 0x3))
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
    let bits = usize::from(header[0] & 0x3f)
        .checked_add(1)
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
    let max_bits = element_width
        .checked_mul(8)
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
    if bits > max_bits {
        return Err(Error::new(ErrorKind::Malformed).with_detail("bitpack width is too large"));
    }
    let max_elements = packed_len.checked_mul(8).ok_or_else(|| {
        Error::new(ErrorKind::IntegerOverflow).with_detail("bitpack size overflowed")
    })? / bits;
    let extra = header.get(1).copied().map_or(0usize, usize::from);
    if extra > max_elements {
        return Err(Error::new(ErrorKind::Malformed).with_detail("bitpack header is corrupt"));
    }
    Ok(BitpackHeader {
        element_width,
        bits,
        elements: max_elements - extra,
    })
}

pub(in crate::execute) fn decode_bitunpack_node(
    stored: StreamInput<'_>,
    header: &[u8],
    limits: Limits,
) -> Result<Vec<u8>> {
    if header.is_empty() || header.len() > 2 {
        return Err(Error::new(ErrorKind::Malformed).with_detail("bitunpack header is malformed"));
    }
    validate_numeric_stream_width(stored.element_width, "bitunpack input")?;
    let elements = numeric_element_count(stored.bytes, stored.element_width)?;
    let bits = usize::from(header[0]);
    if bits == 0 || bits > 8 * stored.element_width {
        return Err(Error::new(ErrorKind::Malformed).with_detail("bitunpack bit count is invalid"));
    }
    let bit_count = elements.checked_mul(bits).ok_or_else(|| {
        Error::new(ErrorKind::IntegerOverflow).with_detail("bitunpack size overflowed")
    })?;
    let output_len = bit_count.div_ceil(8);
    check_output_len(output_len, limits)?;
    let mut output = Vec::new();
    output.try_reserve_exact(output_len).map_err(|_| {
        Error::new(ErrorKind::AllocationFailed).with_detail("bitunpack allocation failed")
    })?;
    if stored.element_width == 1 {
        pack_byte_values(stored.bytes, bits, &mut output)?;
    } else {
        pack_wide_values(stored.bytes, stored.element_width, bits, &mut output)?;
    }
    debug_assert_eq!(output.len(), output_len);
    if header.len() == 2 {
        let rem_bits = (8 - bit_count % 8) % 8;
        if rem_bits == 0 || output_len == 0 || usize::from(header[1]) >= (1usize << rem_bits) {
            return Err(Error::new(ErrorKind::Malformed)
                .with_detail("bitunpack trailing bits are malformed"));
        }
        let last = output.last_mut().ok_or_else(|| {
            Error::new(ErrorKind::Malformed).with_detail("missing bitunpack output")
        })?;
        *last |= header[1] << (8 - rem_bits);
    }
    Ok(output)
}

fn bitunpack_value_too_wide() -> Error {
    Error::new(ErrorKind::Malformed).with_detail("bitunpack value exceeds bit width")
}

/// Packs byte values of `bits` bits each, low bits first, into `output`.
fn pack_byte_values(values: &[u8], bits: usize, output: &mut Vec<u8>) -> Result<()> {
    if bits < 8 {
        let limit = 1u16 << bits;
        if values.iter().any(|&value| u16::from(value) >= limit) {
            return Err(bitunpack_value_too_wide());
        }
    }
    output.resize((values.len() * bits).div_ceil(8), 0);
    let mut bit_pos = 0usize;
    for &value in values {
        let byte_pos = bit_pos / 8;
        let shift = bit_pos % 8;
        output[byte_pos] |= value << shift;
        if shift + bits > 8 {
            output[byte_pos + 1] |= value >> (8 - shift);
        }
        bit_pos += bits;
    }
    Ok(())
}

/// Packs little-endian values of `width` bytes and `bits` bits each, low bits
/// first, into `output`.
fn pack_wide_values(values: &[u8], width: usize, bits: usize, output: &mut Vec<u8>) -> Result<()> {
    // Fewer than 8 pending bits plus one value of up to 64 bits.
    let mut pending = 0u128;
    let mut pending_bits = 0usize;
    for element in values.chunks_exact(width) {
        let value = read_element(element);
        if bits < 64 && value >> bits != 0 {
            return Err(bitunpack_value_too_wide());
        }
        pending |= u128::from(value) << pending_bits;
        pending_bits += bits;
        while pending_bits >= 8 {
            output.push(pending.to_le_bytes()[0]);
            pending >>= 8;
            pending_bits -= 8;
        }
    }
    if pending_bits > 0 {
        output.push(pending.to_le_bytes()[0]);
    }
    Ok(())
}
