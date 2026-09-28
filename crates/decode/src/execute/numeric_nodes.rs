use alloc::{format, vec::Vec};

use ozlrip_core::{Error, ErrorKind, Limits, Result};

use super::header::require_empty_header;
use super::numeric::{max_numeric_value, push_numeric_element, read_element};
use super::output::{alloc_output, check_output_len};

use super::{
    conversion::{read_conversion_int_size, validate_conversion_numeric_width},
    fast_bitpack, fast_delta, fast_zigzag,
    numeric::{numeric_element_count, read_var_u64, validate_numeric_stream_width},
    runtime::DecodeScratch,
    streams::{OwnedStream, StreamInput},
};

pub(super) fn decode_bitpack_serial_chunk(
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

pub(super) fn decode_bitpack_int_chunk(
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

pub(super) fn decode_constant_serial_chunk(
    stored: &[u8],
    header: &[u8],
    limits: Limits,
    scratch: &mut DecodeScratch,
) -> Result<OwnedStream> {
    let input = StreamInput {
        bytes: stored,
        element_width: 1,
        string_lengths: None,
    };
    decode_constant_typed_chunk(input, header, limits, scratch, "constant_serial")
}

pub(super) fn decode_constant_fixed_chunk(
    stored: StreamInput<'_>,
    header: &[u8],
    limits: Limits,
    scratch: &mut DecodeScratch,
) -> Result<OwnedStream> {
    if stored.string_lengths.is_some() {
        return Err(Error::new(ErrorKind::InvalidType)
            .with_detail("constant_fixed input must not be a string stream"));
    }
    decode_constant_typed_chunk(stored, header, limits, scratch, "constant_fixed")
}

fn decode_constant_typed_chunk(
    stored: StreamInput<'_>,
    header: &[u8],
    limits: Limits,
    scratch: &mut DecodeScratch,
    name: &'static str,
) -> Result<OwnedStream> {
    if stored.element_width == 0 {
        return Err(Error::new(ErrorKind::InvalidType)
            .with_detail(format!("{name} element width must be nonzero")));
    }
    if stored.bytes.len() != stored.element_width {
        return Err(Error::new(ErrorKind::Malformed)
            .with_detail(format!("{name} input must contain one element")));
    }
    let mut offset = 0usize;
    let output_elements = read_var_u64(header, &mut offset)?;
    if offset != header.len() {
        return Err(
            Error::new(ErrorKind::Malformed).with_detail(format!("unexpected {name} header bytes"))
        );
    }
    if output_elements == 0 {
        return Err(Error::new(ErrorKind::Malformed)
            .with_detail(format!("{name} output count must be nonzero")));
    }
    let output_elements = usize::try_from(output_elements).map_err(|_| {
        Error::new(ErrorKind::LimitExceeded).with_detail("output count is too large")
    })?;
    let output_len = output_elements
        .checked_mul(stored.element_width)
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
    check_output_len(output_len, limits)?;
    let mut output = scratch.take_byte_buffer(output_len, "constant allocation failed")?;
    repeat_constant_element(stored.bytes, output_len, &mut output);
    Ok(OwnedStream::pooled(output, stored.element_width))
}

fn repeat_constant_element(element: &[u8], output_len: usize, output: &mut Vec<u8>) {
    if element.len() == 1 {
        output.resize(output_len, element[0]);
        return;
    }

    output.extend_from_slice(element);
    while output.len() < output_len {
        let len = output.len();
        let copy_len = len.min(output_len - len);
        output.extend_from_within(..copy_len);
    }
}

pub(super) fn decode_struct_to_num_be_chunk(
    stored: StreamInput<'_>,
    header: &[u8],
    limits: Limits,
) -> Result<OwnedStream> {
    require_empty_header(header, "convert_struct_to_num_be headers are unsupported")?;
    decode_big_endian_numeric_conversion(stored, stored.element_width, limits)
}

pub(super) fn decode_serial_to_num_be_chunk(
    stored: StreamInput<'_>,
    header: &[u8],
    limits: Limits,
) -> Result<OwnedStream> {
    let int_size = read_conversion_int_size(header, "convert_serial_to_num_be")?;
    if !stored.bytes.len().is_multiple_of(int_size) {
        return Err(Error::new(ErrorKind::Malformed)
            .with_detail("serial stream size is not a multiple of integer width"));
    }
    decode_big_endian_numeric_conversion(stored, int_size, limits)
}

fn decode_big_endian_numeric_conversion(
    stored: StreamInput<'_>,
    element_width: usize,
    limits: Limits,
) -> Result<OwnedStream> {
    validate_conversion_numeric_width(element_width)?;
    check_output_len(stored.bytes.len(), limits)?;
    if !stored.bytes.len().is_multiple_of(element_width) {
        return Err(
            Error::new(ErrorKind::Malformed).with_detail("numeric stream has partial element")
        );
    }
    let mut output = Vec::new();
    output.try_reserve_exact(stored.bytes.len()).map_err(|_| {
        Error::new(ErrorKind::AllocationFailed).with_detail("conversion allocation failed")
    })?;
    for element in stored.bytes.chunks_exact(element_width) {
        output.extend(element.iter().rev().copied());
    }
    Ok(OwnedStream {
        bytes: output,
        element_width,
        string_lengths: None,
        recyclable: false,
    })
}

pub(super) fn decode_zigzag_numeric_chunk(
    stored: StreamInput<'_>,
    header: &[u8],
    limits: Limits,
) -> Result<OwnedStream> {
    require_empty_header(header, "zigzag transform headers are unsupported")?;
    validate_numeric_stream_width(stored.element_width, "zigzag")?;
    if !stored.bytes.len().is_multiple_of(stored.element_width) {
        return Err(
            Error::new(ErrorKind::Malformed).with_detail("zigzag input has partial element")
        );
    }
    let mut output = alloc_output(stored.bytes.len(), limits, "zigzag allocation failed")?;
    fast_zigzag::decode_numeric(stored.bytes, stored.element_width, &mut output);
    Ok(OwnedStream {
        bytes: output,
        element_width: stored.element_width,
        string_lengths: None,
        recyclable: false,
    })
}

/// First format version that keeps the first value of a delta stream in the
/// transform header. Older versions keep it first in the stream.
const DELTA_HEADER_VERSION_MIN: u32 = 13;

pub(super) fn decode_delta_node(
    stored: StreamInput<'_>,
    header: &[u8],
    format_version: u32,
    limits: Limits,
    scratch: &mut DecodeScratch,
) -> Result<OwnedStream> {
    validate_numeric_stream_width(stored.element_width, "delta input")?;
    numeric_element_count(stored.bytes, stored.element_width)?;
    let (first, deltas) = if format_version < DELTA_HEADER_VERSION_MIN {
        require_empty_header(header, "delta headers before format v13 are unsupported")?;
        stored
            .bytes
            .split_at_checked(stored.element_width)
            .unwrap_or_default()
    } else {
        match header.len() {
            0 if stored.bytes.is_empty() => (header, stored.bytes),
            0 => {
                return Err(
                    Error::new(ErrorKind::Malformed).with_detail("delta stream has no first value")
                );
            }
            len if len == stored.element_width => (header, stored.bytes),
            _ => {
                return Err(Error::new(ErrorKind::Malformed)
                    .with_detail("delta header must contain one element"));
            }
        }
    };
    let output_len = first.len().checked_add(deltas.len()).ok_or_else(|| {
        Error::new(ErrorKind::IntegerOverflow).with_detail("delta size overflowed")
    })?;
    check_output_len(output_len, limits)?;
    let mut output = scratch.take_byte_buffer(output_len, "delta allocation failed")?;
    if first.is_empty() {
        return Ok(OwnedStream {
            bytes: output,
            element_width: stored.element_width,
            string_lengths: None,
            recyclable: true,
        });
    }
    fast_delta::decode_delta_elements(deltas, first, stored.element_width, output_len, &mut output);
    Ok(OwnedStream::pooled(output, stored.element_width))
}

pub(super) fn decode_divide_by_node(
    stored: StreamInput<'_>,
    header: &[u8],
    limits: Limits,
) -> Result<OwnedStream> {
    validate_numeric_stream_width(stored.element_width, "divide_by input")?;
    numeric_element_count(stored.bytes, stored.element_width)?;
    let divisor = parse_divide_by_divisor(header, stored.element_width)?;
    let mut output = alloc_output(stored.bytes.len(), limits, "divide_by allocation failed")?;
    let max_value = max_numeric_value(stored.element_width)?;
    for element in stored.bytes.chunks_exact(stored.element_width) {
        let quotient = read_element(element);
        let decoded = quotient.checked_mul(divisor).ok_or_else(|| {
            Error::new(ErrorKind::Malformed).with_detail("divide_by value overflowed")
        })?;
        if decoded > max_value {
            return Err(Error::new(ErrorKind::Malformed).with_detail("divide_by value overflowed"));
        }
        push_numeric_element(&mut output, stored.element_width, decoded);
    }
    Ok(OwnedStream::typed(output, stored.element_width))
}

pub(super) fn decode_dedup_num_node(
    stored: StreamInput<'_>,
    header: &[u8],
    output_count: usize,
    limits: Limits,
) -> Result<Vec<OwnedStream>> {
    require_empty_header(header, "dedup_num headers are unsupported")?;
    if output_count == 0 {
        return Err(
            Error::new(ErrorKind::InvalidGraph).with_detail("dedup_num output count is zero")
        );
    }
    if stored.string_lengths.is_some() {
        return Err(
            Error::new(ErrorKind::InvalidType).with_detail("dedup_num input must be numeric")
        );
    }
    validate_numeric_stream_width(stored.element_width, "dedup_num input")?;
    numeric_element_count(stored.bytes, stored.element_width)?;
    check_output_len(stored.bytes.len(), limits)?;
    let total_buffer_bytes = stored
        .bytes
        .len()
        .checked_mul(output_count)
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
    if total_buffer_bytes > limits.max_buffer_bytes {
        return Err(
            Error::new(ErrorKind::LimitExceeded).with_detail("decoded output limit exceeded")
        );
    }

    let mut outputs = Vec::new();
    outputs.try_reserve_exact(output_count).map_err(|_| {
        Error::new(ErrorKind::AllocationFailed).with_detail("dedup_num output allocation failed")
    })?;
    for _ in 0..output_count {
        let mut bytes = Vec::new();
        bytes.try_reserve_exact(stored.bytes.len()).map_err(|_| {
            Error::new(ErrorKind::AllocationFailed).with_detail("dedup_num allocation failed")
        })?;
        bytes.extend_from_slice(stored.bytes);
        outputs.push(OwnedStream::typed(bytes, stored.element_width));
    }
    Ok(outputs)
}

fn parse_divide_by_divisor(header: &[u8], element_width: usize) -> Result<u64> {
    if header.is_empty() {
        return Err(Error::new(ErrorKind::Malformed).with_detail("divide_by header is malformed"));
    }
    let mut offset = 0usize;
    let divisor = read_var_u64(header, &mut offset)?;
    if offset != header.len() {
        return Err(
            Error::new(ErrorKind::Malformed).with_detail("divide_by header has trailing bytes")
        );
    }
    if divisor == 0 || divisor > max_numeric_value(element_width)? {
        return Err(Error::new(ErrorKind::Malformed).with_detail("divide_by divisor is invalid"));
    }
    Ok(divisor)
}

pub(super) fn decode_bitunpack_node(
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

pub(super) fn decode_range_pack_node(
    stored: StreamInput<'_>,
    header: &[u8],
    limits: Limits,
) -> Result<OwnedStream> {
    validate_numeric_stream_width(stored.element_width, "range_pack input")?;
    let elements = numeric_element_count(stored.bytes, stored.element_width)?;
    let (&output_width, min_bytes) = header.split_first().ok_or_else(|| {
        Error::new(ErrorKind::Malformed).with_detail("range_pack header is malformed")
    })?;
    let output_width = usize::from(output_width);
    if !matches!(output_width, 1 | 2 | 4 | 8) || output_width < stored.element_width {
        return Err(
            Error::new(ErrorKind::Malformed).with_detail("range_pack output width is invalid")
        );
    }
    let min_value = match min_bytes.len() {
        0 => 0,
        len if len == output_width => read_element(min_bytes),
        _ => {
            return Err(
                Error::new(ErrorKind::Malformed).with_detail("range_pack header is malformed")
            );
        }
    };
    let output_len = elements
        .checked_mul(output_width)
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
    let mut output = alloc_output(output_len, limits, "range_pack allocation failed")?;
    let overflowed = || Error::new(ErrorKind::Malformed).with_detail("range_pack value overflowed");
    if output_width == 1 {
        let min_value = min_bytes.first().copied().unwrap_or(0);
        for &value in stored.bytes {
            output.push(value.checked_add(min_value).ok_or_else(overflowed)?);
        }
    } else {
        let max_value = max_numeric_value(output_width)?;
        for element in stored.bytes.chunks_exact(stored.element_width) {
            let value = read_element(element)
                .checked_add(min_value)
                .filter(|&value| value <= max_value)
                .ok_or_else(overflowed)?;
            push_numeric_element(&mut output, output_width, value);
        }
    }
    Ok(OwnedStream::typed(output, output_width))
}
