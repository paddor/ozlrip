//! The deprecated FSE and Huffman nodes and the legacy entropy container
//! they store their payloads in.

use alloc::format;
use alloc::vec::Vec;

use ozlrip_core::{Error, ErrorKind, Limits, Result};
use zrip_core::bitstream::reader::BitReader;
use zrip_core::fse::table_builder::{build_decode_table, parse_fse_table_description};

use super::fse::decode_fse_symbols;
use super::legacy_huffman::decode_legacy_huffman_block;
use crate::execute::elements::read_var_u64;
use crate::execute::header::require_empty_header;
use crate::execute::output::check_output_len;
use crate::execute::streams::{OwnedStream, StreamInput};

pub(in crate::execute) fn decode_fse_deprecated_node(
    source: StreamInput<'_>,
    header: &[u8],
    limits: Limits,
) -> Result<Vec<u8>> {
    require_legacy_serial_input(source, "fse_deprecated")?;
    let nb_states = match header {
        [] | [2] => 2,
        [4] => 4,
        [_] => {
            return Err(Error::new(ErrorKind::Malformed)
                .with_detail("fse_deprecated state count is invalid"));
        }
        _ => {
            return Err(
                Error::new(ErrorKind::Malformed).with_detail("fse_deprecated header is malformed")
            );
        }
    };
    decode_legacy_entropy_payload(source.bytes, 1, nb_states, limits, "fse_deprecated")
        .map(|payload| payload.bytes)
}

pub(in crate::execute) fn decode_huffman_deprecated_node(
    source: StreamInput<'_>,
    header: &[u8],
    limits: Limits,
) -> Result<Vec<u8>> {
    require_legacy_serial_input(source, "huffman_deprecated")?;
    require_empty_header(header, "huffman_deprecated headers are unsupported")?;
    decode_legacy_entropy_payload(source.bytes, 1, 2, limits, "huffman_deprecated")
        .map(|payload| payload.bytes)
}

pub(in crate::execute) fn decode_huffman_fixed_deprecated_node(
    source: StreamInput<'_>,
    header: &[u8],
    format_version: u32,
    limits: Limits,
) -> Result<OwnedStream> {
    require_legacy_serial_input(source, "huffman_fixed_deprecated")?;
    let parsed = parse_huffman_fixed_deprecated_header(header, format_version)?;
    let entropy_width = if parsed.is_transposed {
        1
    } else {
        parsed.element_width
    };
    let payload = decode_legacy_entropy_payload(
        source.bytes,
        entropy_width,
        2,
        limits,
        "huffman_fixed_deprecated",
    )?;
    if parsed.is_transposed
        && !payload
            .decoded_elements
            .is_multiple_of(parsed.element_width)
    {
        return Err(Error::new(ErrorKind::Malformed)
            .with_detail("huffman_fixed_deprecated transposed size is invalid"));
    }
    Ok(OwnedStream::typed(payload.bytes, parsed.element_width))
}

struct HuffmanFixedDeprecatedHeader {
    is_transposed: bool,
    element_width: usize,
}

fn parse_huffman_fixed_deprecated_header(
    header: &[u8],
    format_version: u32,
) -> Result<HuffmanFixedDeprecatedHeader> {
    if header.len() < 2 {
        return Err(Error::new(ErrorKind::Malformed)
            .with_detail("huffman_fixed_deprecated header is malformed"));
    }
    let is_transposed = header[0] != 0;
    let mut offset = 1usize;
    let element_width = usize::try_from(read_var_u64(header, &mut offset)?).map_err(|_| {
        Error::new(ErrorKind::LimitExceeded)
            .with_detail("huffman_fixed_deprecated element width is too large")
    })?;
    if offset != header.len() {
        return Err(Error::new(ErrorKind::Malformed)
            .with_detail("huffman_fixed_deprecated header has trailing bytes"));
    }
    if element_width == 0 {
        return Err(Error::new(ErrorKind::Malformed)
            .with_detail("huffman_fixed_deprecated element width is zero"));
    }
    if format_version >= 11 && element_width > 2 {
        return Err(Error::new(ErrorKind::Unsupported)
            .with_detail("huffman_fixed_deprecated element width is unsupported"));
    }
    Ok(HuffmanFixedDeprecatedHeader {
        is_transposed,
        element_width,
    })
}

pub(super) struct LegacyEntropyPayload {
    pub(super) bytes: Vec<u8>,
    pub(super) decoded_elements: usize,
}

pub(in crate::execute) const LEGACY_ENTROPY_MAX_DEPTH: usize = 64;

fn decode_legacy_entropy_payload(
    source: &[u8],
    element_width: usize,
    fse_nb_states: usize,
    limits: Limits,
    transform_name: &str,
) -> Result<LegacyEntropyPayload> {
    validate_legacy_entropy_width(element_width, transform_name)?;
    if source.is_empty() {
        return Ok(LegacyEntropyPayload {
            bytes: Vec::new(),
            decoded_elements: 0,
        });
    }

    let mut offset = 0usize;
    let payload = decode_legacy_entropy_payload_internal(
        source,
        &mut offset,
        element_width,
        fse_nb_states,
        limits,
        transform_name,
        LEGACY_ENTROPY_MAX_DEPTH,
    )?;
    if offset != source.len() {
        return Err(Error::new(ErrorKind::Malformed)
            .with_detail(format!("{transform_name} input has trailing bytes")));
    }
    Ok(payload)
}

pub(super) fn decode_legacy_entropy_payload_internal(
    source: &[u8],
    offset: &mut usize,
    element_width: usize,
    fse_nb_states: usize,
    limits: Limits,
    transform_name: &str,
    max_depth: usize,
) -> Result<LegacyEntropyPayload> {
    let header = *source.get(*offset).ok_or_else(|| {
        Error::new(ErrorKind::Malformed)
            .with_detail(format!("{transform_name} entropy header is truncated"))
    })?;
    match header & 0x07 {
        4 => decode_legacy_entropy_bit_block(
            source,
            offset,
            header,
            element_width,
            limits,
            transform_name,
        ),
        1 => decode_legacy_entropy_fse(
            source,
            offset,
            element_width,
            fse_nb_states,
            limits,
            transform_name,
        ),
        0 => {
            let bytes = decode_legacy_huffman_block(
                source,
                offset,
                element_width,
                limits,
                transform_name,
                max_depth,
            )?;
            Ok(LegacyEntropyPayload {
                decoded_elements: bytes.len() / element_width,
                bytes,
            })
        }
        _ => decode_legacy_entropy_sized_block(
            source,
            offset,
            element_width,
            fse_nb_states,
            limits,
            transform_name,
            max_depth,
        ),
    }
}

/// A bit-packed block: the header byte holds the bit width, then the
/// element count follows as a varint.
fn decode_legacy_entropy_bit_block(
    source: &[u8],
    offset: &mut usize,
    header: u8,
    element_width: usize,
    limits: Limits,
    transform_name: &str,
) -> Result<LegacyEntropyPayload> {
    *offset = (*offset)
        .checked_add(1)
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
    let num_bits = usize::from(header >> 3);
    let decoded_elements = usize::try_from(read_var_u64(source, offset)?).map_err(|_| {
        Error::new(ErrorKind::LimitExceeded)
            .with_detail(format!("{transform_name} output size is too large"))
    })?;
    decode_legacy_entropy_bit(
        source,
        offset,
        decoded_elements,
        element_width,
        num_bits,
        limits,
        transform_name,
    )
}

/// Blocks whose header holds the element count: constant, raw and multi.
fn decode_legacy_entropy_sized_block(
    source: &[u8],
    offset: &mut usize,
    element_width: usize,
    fse_nb_states: usize,
    limits: Limits,
    transform_name: &str,
    max_depth: usize,
) -> Result<LegacyEntropyPayload> {
    let (entropy_type, decoded_elements) =
        read_legacy_entropy_header(source, offset, transform_name)?;
    match entropy_type {
        2 => decode_legacy_entropy_constant(
            source,
            offset,
            decoded_elements,
            element_width,
            limits,
            transform_name,
        ),
        3 => decode_legacy_entropy_raw(
            source,
            offset,
            decoded_elements,
            element_width,
            limits,
            transform_name,
        ),
        5 => decode_legacy_entropy_multi(
            source,
            offset,
            decoded_elements,
            element_width,
            fse_nb_states,
            limits,
            transform_name,
            max_depth,
        ),
        _ => Err(Error::new(ErrorKind::Malformed)
            .with_detail(format!("{transform_name} entropy mode is reserved"))),
    }
}

fn validate_legacy_entropy_width(element_width: usize, transform_name: &str) -> Result<()> {
    if element_width == 0 || element_width > 8 || !element_width.is_power_of_two() {
        return Err(Error::new(ErrorKind::Unsupported)
            .with_detail(format!("{transform_name} element width is unsupported")));
    }
    Ok(())
}

pub(in crate::execute) fn read_legacy_entropy_header(
    source: &[u8],
    offset: &mut usize,
    transform_name: &str,
) -> Result<(u8, usize)> {
    let header = *source.get(*offset).ok_or_else(|| {
        Error::new(ErrorKind::Malformed)
            .with_detail(format!("{transform_name} entropy header is truncated"))
    })?;
    *offset = (*offset)
        .checked_add(1)
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
    let decoded_elements = read_legacy_entropy_size(header, source, offset, transform_name)?;
    Ok((header & 0x07, decoded_elements))
}

pub(super) fn read_legacy_entropy_size(
    header: u8,
    source: &[u8],
    offset: &mut usize,
    transform_name: &str,
) -> Result<usize> {
    let low = u64::from((header >> 3) & 0x0f);
    let high = if header & 0x80 == 0 {
        0
    } else {
        let high = read_var_u64(source, offset)?;
        if high > (u64::MAX >> 4) {
            return Err(Error::new(ErrorKind::IntegerOverflow));
        }
        high << 4
    };
    let decoded = low
        .checked_add(high)
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
    usize::try_from(decoded).map_err(|_| {
        Error::new(ErrorKind::LimitExceeded)
            .with_detail(format!("{transform_name} output size is too large"))
    })
}

pub(super) fn checked_legacy_entropy_output_len(
    decoded_elements: usize,
    element_width: usize,
    limits: Limits,
) -> Result<usize> {
    let output_len = decoded_elements
        .checked_mul(element_width)
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
    check_output_len(output_len, limits)?;
    Ok(output_len)
}

fn decode_legacy_entropy_raw(
    source: &[u8],
    offset: &mut usize,
    decoded_elements: usize,
    element_width: usize,
    limits: Limits,
    transform_name: &str,
) -> Result<LegacyEntropyPayload> {
    let output_len = checked_legacy_entropy_output_len(decoded_elements, element_width, limits)?;
    let end = (*offset)
        .checked_add(output_len)
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
    let payload = source
        .get(*offset..end)
        .ok_or_else(|| Error::new(ErrorKind::Malformed))?;
    *offset = end;
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(output_len).map_err(|_| {
        Error::new(ErrorKind::AllocationFailed)
            .with_detail(format!("{transform_name} allocation failed"))
    })?;
    bytes.extend_from_slice(payload);
    Ok(LegacyEntropyPayload {
        bytes,
        decoded_elements,
    })
}

fn decode_legacy_entropy_constant(
    source: &[u8],
    offset: &mut usize,
    decoded_elements: usize,
    element_width: usize,
    limits: Limits,
    transform_name: &str,
) -> Result<LegacyEntropyPayload> {
    let output_len = checked_legacy_entropy_output_len(decoded_elements, element_width, limits)?;
    let end = (*offset)
        .checked_add(element_width)
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
    let value = source
        .get(*offset..end)
        .ok_or_else(|| Error::new(ErrorKind::Malformed))?;
    *offset = end;
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(output_len).map_err(|_| {
        Error::new(ErrorKind::AllocationFailed)
            .with_detail(format!("{transform_name} allocation failed"))
    })?;
    for _ in 0..decoded_elements {
        bytes.extend_from_slice(value);
    }
    Ok(LegacyEntropyPayload {
        bytes,
        decoded_elements,
    })
}

#[expect(
    clippy::too_many_arguments,
    reason = "legacy entropy recursion threads limits and format labels for errors"
)]
fn decode_legacy_entropy_multi(
    source: &[u8],
    offset: &mut usize,
    blocks: usize,
    element_width: usize,
    fse_nb_states: usize,
    limits: Limits,
    transform_name: &str,
    max_depth: usize,
) -> Result<LegacyEntropyPayload> {
    if max_depth == 0 {
        return Err(Error::new(ErrorKind::LimitExceeded).with_detail(format!(
            "{transform_name} multi entropy depth exceeds limit"
        )));
    }
    if blocks > limits.max_buffer_bytes {
        return Err(Error::new(ErrorKind::LimitExceeded).with_detail(format!(
            "{transform_name} multi entropy block count exceeds buffer limit"
        )));
    }

    let mut bytes = Vec::new();
    let mut decoded_elements = 0usize;
    for _ in 0..blocks {
        let block = decode_legacy_entropy_payload_internal(
            source,
            offset,
            element_width,
            fse_nb_states,
            limits,
            transform_name,
            max_depth - 1,
        )?;
        if block.decoded_elements == 0 {
            return Err(Error::new(ErrorKind::Malformed)
                .with_detail(format!("{transform_name} multi entropy block is empty")));
        }
        decoded_elements = decoded_elements
            .checked_add(block.decoded_elements)
            .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
        let output_len =
            checked_legacy_entropy_output_len(decoded_elements, element_width, limits)?;
        bytes.try_reserve_exact(block.bytes.len()).map_err(|_| {
            Error::new(ErrorKind::AllocationFailed)
                .with_detail(format!("{transform_name} allocation failed"))
        })?;
        bytes.extend_from_slice(&block.bytes);
        debug_assert_eq!(bytes.len(), output_len);
    }
    Ok(LegacyEntropyPayload {
        bytes,
        decoded_elements,
    })
}

pub(in crate::execute) struct LegacyCompressedEntropyHeader {
    pub(in crate::execute) decoded_elements: usize,
    pub(in crate::execute) encoded_len: usize,
    /// The block uses upstream's AVX2 Huffman layout.
    pub(in crate::execute) avx2_huffman: bool,
}

fn decode_legacy_entropy_fse(
    source: &[u8],
    offset: &mut usize,
    element_width: usize,
    nb_states: usize,
    limits: Limits,
    transform_name: &str,
) -> Result<LegacyEntropyPayload> {
    if element_width != 1 {
        return Err(Error::new(ErrorKind::Unsupported).with_detail(format!(
            "{transform_name} fse entropy element width is unsupported"
        )));
    }
    let header = read_legacy_compressed_entropy_header(source, offset, transform_name)?;
    let output_len =
        checked_legacy_entropy_output_len(header.decoded_elements, element_width, limits)?;
    let end = (*offset)
        .checked_add(header.encoded_len)
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
    let encoded = source
        .get(*offset..end)
        .ok_or_else(|| Error::new(ErrorKind::Malformed))?;

    let mut reader = BitReader::new(encoded);
    let (distribution, accuracy_log) =
        parse_fse_table_description(&mut reader, u8::MAX).map_err(|err| {
            Error::new(ErrorKind::Malformed)
                .with_detail(format!("{transform_name} fse table is invalid: {err}"))
        })?;
    let bits_offset = reader.bytes_consumed();
    let bits = encoded.get(bits_offset..).ok_or_else(|| {
        Error::new(ErrorKind::Malformed)
            .with_detail(format!("{transform_name} fse bitstream is missing"))
    })?;
    let table = build_decode_table(&distribution, accuracy_log).map_err(|err| {
        Error::new(ErrorKind::Malformed)
            .with_detail(format!("{transform_name} fse table is invalid: {err}"))
    })?;
    let bytes = decode_fse_symbols(
        bits,
        header.decoded_elements,
        nb_states,
        &table,
        accuracy_log,
        transform_name,
    )?;
    debug_assert_eq!(bytes.len(), output_len);
    *offset = end;
    Ok(LegacyEntropyPayload {
        bytes,
        decoded_elements: header.decoded_elements,
    })
}

pub(in crate::execute) fn read_legacy_compressed_entropy_header(
    source: &[u8],
    offset: &mut usize,
    transform_name: &str,
) -> Result<LegacyCompressedEntropyHeader> {
    let end = (*offset)
        .checked_add(2)
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
    let header = source.get(*offset..end).ok_or_else(|| {
        Error::new(ErrorKind::Malformed).with_detail(format!(
            "{transform_name} compressed entropy header is truncated"
        ))
    })?;
    let header = u16::from_le_bytes(header.try_into().map_err(|_| {
        Error::new(ErrorKind::Malformed).with_detail(format!(
            "{transform_name} compressed entropy header is malformed"
        ))
    })?);
    *offset = end;

    let avx2_huffman = ((header >> 5) & 1) != 0;
    let has_varints = ((header >> 6) & 1) != 0;
    let mut decoded_elements = u64::from((header >> 7) & 0x1f);
    let mut encoded_len = u64::from((header >> 12) & 0x0f);
    if has_varints {
        let decoded_high = read_var_u64(source, offset)?;
        if decoded_high > (u64::MAX >> 5) {
            return Err(Error::new(ErrorKind::IntegerOverflow));
        }
        decoded_elements |= decoded_high << 5;

        let encoded_high = read_var_u64(source, offset)?;
        if encoded_high > (u64::MAX >> 4) {
            return Err(Error::new(ErrorKind::IntegerOverflow));
        }
        encoded_len |= encoded_high << 4;
    }

    Ok(LegacyCompressedEntropyHeader {
        decoded_elements: usize::try_from(decoded_elements).map_err(|_| {
            Error::new(ErrorKind::LimitExceeded)
                .with_detail(format!("{transform_name} output size is too large"))
        })?,
        encoded_len: usize::try_from(encoded_len).map_err(|_| {
            Error::new(ErrorKind::LimitExceeded)
                .with_detail(format!("{transform_name} encoded size is too large"))
        })?,
        avx2_huffman,
    })
}

fn decode_legacy_entropy_bit(
    source: &[u8],
    offset: &mut usize,
    decoded_elements: usize,
    element_width: usize,
    num_bits: usize,
    limits: Limits,
    transform_name: &str,
) -> Result<LegacyEntropyPayload> {
    let max_bits = element_width.checked_mul(8).ok_or_else(|| {
        Error::new(ErrorKind::IntegerOverflow)
            .with_detail(format!("{transform_name} element width is too large"))
    })?;
    if num_bits >= max_bits {
        return Err(Error::new(ErrorKind::Malformed)
            .with_detail(format!("{transform_name} bit width is invalid")));
    }

    let output_len = checked_legacy_entropy_output_len(decoded_elements, element_width, limits)?;
    let bytes = unpack_legacy_bits(
        source,
        offset,
        decoded_elements,
        element_width,
        num_bits,
        output_len,
        transform_name,
    )?;
    Ok(LegacyEntropyPayload {
        bytes,
        decoded_elements,
    })
}

/// Unpacks `decoded_elements` little-endian values of `num_bits` bits each
/// from `source` at `offset` into `output_len` bytes of `element_width`-byte
/// elements. Callers check the widths and the output size.
pub(in crate::execute) fn unpack_legacy_bits(
    source: &[u8],
    offset: &mut usize,
    decoded_elements: usize,
    element_width: usize,
    num_bits: usize,
    output_len: usize,
    transform_name: &str,
) -> Result<Vec<u8>> {
    let encoded_bits = decoded_elements
        .checked_mul(num_bits)
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
    let encoded_len = encoded_bits
        .checked_add(7)
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?
        / 8;
    let end = (*offset)
        .checked_add(encoded_len)
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
    let encoded = source
        .get(*offset..end)
        .ok_or_else(|| Error::new(ErrorKind::Malformed))?;
    *offset = end;

    let mut bytes = Vec::new();
    bytes.try_reserve_exact(output_len).map_err(|_| {
        Error::new(ErrorKind::AllocationFailed)
            .with_detail(format!("{transform_name} allocation failed"))
    })?;
    if num_bits == 0 {
        bytes.resize(output_len, 0);
        return Ok(bytes);
    }

    let mask = if num_bits == 64 {
        u64::MAX
    } else {
        (1u64 << num_bits) - 1
    };
    let mut bit_pos = 0usize;
    for _ in 0..decoded_elements {
        let mut value = 0u64;
        let mut bits_read = 0usize;
        while bits_read < num_bits {
            let byte = encoded.get(bit_pos / 8).ok_or_else(|| {
                Error::new(ErrorKind::Malformed)
                    .with_detail(format!("{transform_name} bit stream is truncated"))
            })?;
            let take = (8 - (bit_pos & 7)).min(num_bits - bits_read);
            let chunk_mask = (1u16 << take) - 1;
            let chunk = u16::from(*byte >> (bit_pos & 7)) & chunk_mask;
            value |= u64::from(chunk) << bits_read;
            bit_pos = bit_pos
                .checked_add(take)
                .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
            bits_read += take;
        }
        push_legacy_value(&mut bytes, element_width, value & mask, transform_name)?;
    }
    Ok(bytes)
}

/// Appends `value` as a little-endian element of `element_width` bytes.
fn push_legacy_value(
    bytes: &mut Vec<u8>,
    element_width: usize,
    value: u64,
    transform_name: &str,
) -> Result<()> {
    let too_large = || {
        Error::new(ErrorKind::Malformed)
            .with_detail(format!("{transform_name} bit value is too large"))
    };
    match element_width {
        1 => bytes.push(u8::try_from(value).map_err(|_| too_large())?),
        2 => bytes.extend_from_slice(&u16::try_from(value).map_err(|_| too_large())?.to_le_bytes()),
        4 => bytes.extend_from_slice(&u32::try_from(value).map_err(|_| too_large())?.to_le_bytes()),
        8 => bytes.extend_from_slice(&value.to_le_bytes()),
        _ => unreachable!("validated element width"),
    }
    Ok(())
}

fn require_legacy_serial_input(source: StreamInput<'_>, transform_name: &str) -> Result<()> {
    if source.element_width != 1 {
        return Err(Error::new(ErrorKind::InvalidType)
            .with_detail(format!("{transform_name} input must be serial")));
    }
    Ok(())
}
