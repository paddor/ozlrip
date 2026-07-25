use alloc::vec::Vec;

use ozlrip_core::{Error, ErrorKind, Limits, Result};

use super::{
    DecodeScratch, OwnedStream, StreamInput, fast_bitpack, fast_delta, fast_zigzag,
    numeric_element_count, read_conversion_int_size, read_var_u64,
    validate_conversion_numeric_width, validate_numeric_stream_width,
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
    if output_len > limits.max_decoded_bytes || output_len > limits.max_buffer_bytes {
        return Err(
            Error::new(ErrorKind::LimitExceeded).with_detail("decoded output limit exceeded")
        );
    }
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
) -> Result<Vec<u8>> {
    if stored.len() != 1 {
        return Err(Error::new(ErrorKind::Malformed)
            .with_detail("constant_serial input must contain one byte"));
    }
    let mut offset = 0usize;
    let output_len = read_var_u64(header, &mut offset)?;
    if offset != header.len() {
        return Err(
            Error::new(ErrorKind::Malformed).with_detail("unexpected constant_serial header bytes")
        );
    }
    if output_len == 0 {
        return Err(Error::new(ErrorKind::Malformed)
            .with_detail("constant_serial output count must be nonzero"));
    }
    let output_len = usize::try_from(output_len).map_err(|_| {
        Error::new(ErrorKind::LimitExceeded).with_detail("output count is too large")
    })?;
    if output_len > limits.max_decoded_bytes || output_len > limits.max_buffer_bytes {
        return Err(
            Error::new(ErrorKind::LimitExceeded).with_detail("decoded output limit exceeded")
        );
    }
    let mut output = Vec::new();
    output.try_reserve_exact(output_len).map_err(|_| {
        Error::new(ErrorKind::LimitExceeded).with_detail("constant allocation failed")
    })?;
    output.resize(output_len, stored[0]);
    Ok(output)
}

pub(super) fn decode_byte_preserving_conversion_chunk(
    stored: StreamInput<'_>,
    header: &[u8],
    limits: Limits,
) -> Result<OwnedStream> {
    if !header.is_empty() {
        return Err(
            Error::new(ErrorKind::Unsupported).with_detail("conversion headers are unsupported")
        );
    }
    copy_byte_preserving_conversion(stored, stored.element_width, limits)
}

pub(super) fn decode_num_to_struct_le_chunk(
    stored: StreamInput<'_>,
    header: &[u8],
    limits: Limits,
) -> Result<OwnedStream> {
    if !header.is_empty() {
        return Err(Error::new(ErrorKind::Unsupported)
            .with_detail("convert_num_to_struct_le headers are unsupported"));
    }
    copy_byte_preserving_conversion(stored, stored.element_width, limits)
}

pub(super) fn decode_serial_to_struct_chunk(
    stored: StreamInput<'_>,
    header: &[u8],
    limits: Limits,
) -> Result<OwnedStream> {
    let mut offset = 0usize;
    let element_width = read_var_u64(header, &mut offset)?;
    if offset != header.len() {
        return Err(Error::new(ErrorKind::Malformed)
            .with_detail("convert_struct_to_serial header has trailing bytes"));
    }
    let element_width = usize::try_from(element_width).map_err(|_| {
        Error::new(ErrorKind::LimitExceeded).with_detail("conversion element width is too large")
    })?;
    if element_width == 0 {
        return Err(Error::new(ErrorKind::Malformed)
            .with_detail("conversion element width must be nonzero"));
    }
    if !stored.bytes.len().is_multiple_of(element_width) {
        return Err(Error::new(ErrorKind::Malformed)
            .with_detail("serial stream size is not a multiple of struct width"));
    }
    copy_byte_preserving_conversion(stored, element_width, limits)
}

pub(super) fn decode_numeric_to_serial_le_chunk(
    stored: StreamInput<'_>,
    header: &[u8],
    limits: Limits,
) -> Result<Vec<u8>> {
    if !header.is_empty() {
        return Err(Error::new(ErrorKind::Unsupported)
            .with_detail("convert_serial_to_num_le headers are unsupported"));
    }
    Ok(copy_byte_preserving_conversion(stored, 1, limits)?.bytes)
}

pub(super) fn decode_serial_to_numeric_le_chunk(
    stored: StreamInput<'_>,
    header: &[u8],
    limits: Limits,
) -> Result<OwnedStream> {
    let int_size = read_conversion_int_size(header, "convert_num_to_serial_le")?;
    if !stored.bytes.len().is_multiple_of(int_size) {
        return Err(Error::new(ErrorKind::Malformed)
            .with_detail("serial stream size is not a multiple of integer width"));
    }
    copy_byte_preserving_conversion(stored, int_size, limits)
}

pub(super) fn decode_struct_to_num_be_chunk(
    stored: StreamInput<'_>,
    header: &[u8],
    limits: Limits,
) -> Result<OwnedStream> {
    if !header.is_empty() {
        return Err(Error::new(ErrorKind::Unsupported)
            .with_detail("convert_struct_to_num_be headers are unsupported"));
    }
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
    if stored.bytes.len() > limits.max_decoded_bytes || stored.bytes.len() > limits.max_buffer_bytes
    {
        return Err(
            Error::new(ErrorKind::LimitExceeded).with_detail("decoded output limit exceeded")
        );
    }
    if !stored.bytes.len().is_multiple_of(element_width) {
        return Err(
            Error::new(ErrorKind::Malformed).with_detail("numeric stream has partial element")
        );
    }
    let mut output = Vec::new();
    output.try_reserve_exact(stored.bytes.len()).map_err(|_| {
        Error::new(ErrorKind::LimitExceeded).with_detail("conversion allocation failed")
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

fn copy_byte_preserving_conversion(
    stored: StreamInput<'_>,
    element_width: usize,
    limits: Limits,
) -> Result<OwnedStream> {
    if stored.bytes.len() > limits.max_decoded_bytes || stored.bytes.len() > limits.max_buffer_bytes
    {
        return Err(
            Error::new(ErrorKind::LimitExceeded).with_detail("decoded output limit exceeded")
        );
    }
    let mut output = Vec::new();
    output.try_reserve_exact(stored.bytes.len()).map_err(|_| {
        Error::new(ErrorKind::LimitExceeded).with_detail("conversion allocation failed")
    })?;
    output.extend_from_slice(stored.bytes);
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
    if !header.is_empty() {
        return Err(Error::new(ErrorKind::Unsupported)
            .with_detail("zigzag transform headers are unsupported"));
    }
    validate_numeric_stream_width(stored.element_width, "zigzag")?;
    if !stored.bytes.len().is_multiple_of(stored.element_width) {
        return Err(
            Error::new(ErrorKind::Malformed).with_detail("zigzag input has partial element")
        );
    }
    if stored.bytes.len() > limits.max_decoded_bytes || stored.bytes.len() > limits.max_buffer_bytes
    {
        return Err(
            Error::new(ErrorKind::LimitExceeded).with_detail("decoded output limit exceeded")
        );
    }
    let mut output = Vec::new();
    output.try_reserve_exact(stored.bytes.len()).map_err(|_| {
        Error::new(ErrorKind::LimitExceeded).with_detail("zigzag allocation failed")
    })?;
    fast_zigzag::decode_numeric(stored.bytes, stored.element_width, &mut output);
    Ok(OwnedStream {
        bytes: output,
        element_width: stored.element_width,
        string_lengths: None,
        recyclable: false,
    })
}

pub(super) fn decode_delta_node(
    stored: StreamInput<'_>,
    header: &[u8],
    limits: Limits,
    scratch: &mut DecodeScratch,
) -> Result<OwnedStream> {
    validate_numeric_stream_width(stored.element_width, "delta input")?;
    let stored_elements = numeric_element_count(stored.bytes, stored.element_width)?;
    let output_elements = match header.len() {
        0 if stored_elements == 0 => 0,
        0 => {
            return Err(
                Error::new(ErrorKind::Malformed).with_detail("delta stream has no first value")
            );
        }
        len if len == stored.element_width => stored_elements.checked_add(1).ok_or_else(|| {
            Error::new(ErrorKind::IntegerOverflow).with_detail("delta size overflowed")
        })?,
        _ => {
            return Err(Error::new(ErrorKind::Malformed)
                .with_detail("delta header must contain one element"));
        }
    };
    let output_len = output_elements
        .checked_mul(stored.element_width)
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
    if output_len > limits.max_decoded_bytes || output_len > limits.max_buffer_bytes {
        return Err(
            Error::new(ErrorKind::LimitExceeded).with_detail("decoded output limit exceeded")
        );
    }
    let mut output = scratch.take_byte_buffer(output_len, "delta allocation failed")?;
    if output_elements == 0 {
        return Ok(OwnedStream {
            bytes: output,
            element_width: stored.element_width,
            string_lengths: None,
            recyclable: true,
        });
    }
    fast_delta::decode_delta_elements(
        stored.bytes,
        header,
        stored.element_width,
        output_len,
        &mut output,
    );
    Ok(OwnedStream::pooled(output, stored.element_width))
}

pub(super) fn decode_bitunpack_serial8_chunk(
    stored: &[u8],
    header: &[u8],
    limits: Limits,
) -> Result<Vec<u8>> {
    if header.is_empty() || header.len() > 2 {
        return Err(Error::new(ErrorKind::Malformed).with_detail("bitunpack header is malformed"));
    }
    let bits = usize::from(header[0]);
    if bits == 0 || bits > 8 {
        return Err(Error::new(ErrorKind::Unsupported)
            .with_detail("only byte-width bitunpack input is implemented"));
    }
    let bit_count = stored.len().checked_mul(bits).ok_or_else(|| {
        Error::new(ErrorKind::IntegerOverflow).with_detail("bitunpack size overflowed")
    })?;
    let output_len = bit_count.checked_add(7).ok_or_else(|| {
        Error::new(ErrorKind::IntegerOverflow).with_detail("bitunpack size overflowed")
    })? / 8;
    if output_len > limits.max_decoded_bytes || output_len > limits.max_buffer_bytes {
        return Err(
            Error::new(ErrorKind::LimitExceeded).with_detail("decoded output limit exceeded")
        );
    }
    if bits < 8 {
        let limit = 1u16 << bits;
        if stored.iter().any(|&value| u16::from(value) >= limit) {
            return Err(
                Error::new(ErrorKind::Malformed).with_detail("bitunpack value exceeds bit width")
            );
        }
    }
    let mut output = Vec::new();
    output.try_reserve_exact(output_len).map_err(|_| {
        Error::new(ErrorKind::LimitExceeded).with_detail("bitunpack allocation failed")
    })?;
    output.resize(output_len, 0);
    let mut bit_pos = 0usize;
    for &value in stored {
        let byte_pos = bit_pos / 8;
        let shift = bit_pos % 8;
        output[byte_pos] |= value << shift;
        if shift + bits > 8 {
            output[byte_pos + 1] |= value >> (8 - shift);
        }
        bit_pos += bits;
    }
    if header.len() == 2 {
        let rem_bits = output_len
            .checked_mul(8)
            .and_then(|bits_in_output| bits_in_output.checked_sub(bit_count))
            .ok_or_else(|| {
                Error::new(ErrorKind::IntegerOverflow).with_detail("bitunpack size overflowed")
            })?;
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

pub(super) fn decode_range_pack_serial8_chunk(
    stored: &[u8],
    header: &[u8],
    limits: Limits,
) -> Result<Vec<u8>> {
    if header.is_empty() {
        return Err(Error::new(ErrorKind::Malformed).with_detail("range_pack header is malformed"));
    }
    if header[0] != 1 {
        return Err(Error::new(ErrorKind::Unsupported)
            .with_detail("only byte-width range_pack output is implemented"));
    }
    let min_value = match header.len() {
        1 => 0,
        2 => header[1],
        _ => {
            return Err(
                Error::new(ErrorKind::Malformed).with_detail("range_pack header is malformed")
            );
        }
    };
    if stored.len() > limits.max_decoded_bytes || stored.len() > limits.max_buffer_bytes {
        return Err(
            Error::new(ErrorKind::LimitExceeded).with_detail("decoded output limit exceeded")
        );
    }
    let mut output = Vec::new();
    output.try_reserve_exact(stored.len()).map_err(|_| {
        Error::new(ErrorKind::LimitExceeded).with_detail("range_pack allocation failed")
    })?;
    for &value in stored {
        let decoded = value.checked_add(min_value).ok_or_else(|| {
            Error::new(ErrorKind::Malformed).with_detail("range_pack value overflowed")
        })?;
        output.push(decoded);
    }
    Ok(output)
}
