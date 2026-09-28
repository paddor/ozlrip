//! Literal and token streams of the deprecated LZ nodes, stored in the
//! legacy entropy container, and a cursor that reads them in order.

use alloc::format;
use alloc::vec::Vec;

use ozlrip_core::{Error, ErrorKind, Limits, Result};
use zrip_core::bitstream::reader::BitReader;
use zrip_core::fse::table_builder::{build_decode_table, parse_fse_table_description};

use crate::execute::elements::read_var_u64;
use crate::execute::entropy::{
    LEGACY_ENTROPY_MAX_DEPTH, decode_fse_symbols, decode_legacy_huffman_block,
    read_legacy_compressed_entropy_header, read_legacy_entropy_header, unpack_legacy_bits,
};
use crate::execute::output::check_output_len;
use crate::execute::streams::StreamInput;

pub(super) enum LegacyLiteralPayload<'a> {
    Raw(&'a [u8]),
    Constant {
        value: &'a [u8],
        decoded_elements: usize,
        element_width: usize,
    },
    Decoded(Vec<u8>),
}

impl LegacyLiteralPayload<'_> {
    pub(super) fn byte_len(&self) -> Result<usize> {
        match self {
            Self::Raw(bytes) => Ok(bytes.len()),
            Self::Constant {
                decoded_elements,
                element_width,
                ..
            } => legacy_entropy_output_len(*decoded_elements, *element_width),
            Self::Decoded(bytes) => Ok(bytes.len()),
        }
    }
}

pub(super) struct LegacyLiteralCursor<'a> {
    payload: LegacyLiteralPayload<'a>,
    offset: usize,
}

impl<'a> LegacyLiteralCursor<'a> {
    pub(super) const fn new(payload: LegacyLiteralPayload<'a>) -> Self {
        Self { payload, offset: 0 }
    }

    pub(super) fn remaining_len(&self) -> Result<usize> {
        self.payload
            .byte_len()?
            .checked_sub(self.offset)
            .ok_or_else(|| {
                Error::new(ErrorKind::Malformed)
                    .with_detail("fastlz_deprecated literal stream is too short")
            })
    }

    pub(super) fn extend_next(&mut self, len: usize, output: &mut Vec<u8>) -> Result<()> {
        let end = self
            .offset
            .checked_add(len)
            .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
        if end > self.payload.byte_len()? {
            return Err(Error::new(ErrorKind::Malformed)
                .with_detail("fastlz_deprecated literal stream is too short"));
        }
        match &self.payload {
            LegacyLiteralPayload::Raw(bytes) => {
                let chunk = bytes.get(self.offset..end).ok_or_else(|| {
                    Error::new(ErrorKind::Malformed)
                        .with_detail("fastlz_deprecated literal stream is too short")
                })?;
                output.extend_from_slice(chunk);
            }
            LegacyLiteralPayload::Decoded(bytes) => {
                let chunk = bytes.get(self.offset..end).ok_or_else(|| {
                    Error::new(ErrorKind::Malformed)
                        .with_detail("fastlz_deprecated literal stream is too short")
                })?;
                output.extend_from_slice(chunk);
            }
            LegacyLiteralPayload::Constant {
                value,
                element_width,
                ..
            } => {
                if !self.offset.is_multiple_of(*element_width)
                    || !len.is_multiple_of(*element_width)
                {
                    return Err(Error::new(ErrorKind::Malformed)
                        .with_detail("deprecated lz constant literal range is misaligned"));
                }
                let elements = len / *element_width;
                for _ in 0..elements {
                    output.extend_from_slice(value);
                }
            }
        }
        self.offset = end;
        Ok(())
    }

    pub(super) fn extend_remaining(&mut self, output: &mut Vec<u8>) -> Result<()> {
        let len = self.remaining_len()?;
        self.extend_next(len, output)
    }
}

pub(super) fn decode_deprecated_lz_entropy_payload_to_vec(
    source: &[u8],
    offset: &mut usize,
    expected_len: usize,
    limits: Limits,
    transform_name: &str,
) -> Result<Vec<u8>> {
    let payload = parse_legacy_literal_entropy_payload(source, offset, 1, limits, transform_name)?;
    if payload.byte_len()? != expected_len {
        return Err(Error::new(ErrorKind::Malformed)
            .with_detail(format!("{transform_name} count is invalid")));
    }
    if expected_len > limits.max_buffer_bytes {
        return Err(Error::new(ErrorKind::LimitExceeded)
            .with_detail(format!("{transform_name} exceeds buffer limit")));
    }
    copy_deprecated_lz_literals(payload, transform_name)
}

pub(super) fn parse_deprecated_lz_stored_stream<'a>(
    source: StreamInput<'a>,
    limits: Limits,
    transform_name: &str,
) -> Result<(usize, &'a [u8])> {
    if source.element_width != 1 {
        return Err(Error::new(ErrorKind::InvalidType)
            .with_detail(format!("{transform_name} input must be serial")));
    }
    let size_prefix = source.bytes.get(..4).ok_or_else(|| {
        Error::new(ErrorKind::Malformed).with_detail("deprecated lz stream is missing size prefix")
    })?;
    let decoded_size = usize::try_from(u32::from_le_bytes([
        size_prefix[0],
        size_prefix[1],
        size_prefix[2],
        size_prefix[3],
    ]))
    .map_err(|_| {
        Error::new(ErrorKind::LimitExceeded).with_detail("deprecated lz output size is too large")
    })?;
    check_output_len(decoded_size, limits)?;
    Ok((decoded_size, &source.bytes[4..]))
}

pub(super) fn parse_legacy_literal_entropy_payload<'a>(
    source: &'a [u8],
    offset: &mut usize,
    element_width: usize,
    limits: Limits,
    transform_name: &str,
) -> Result<LegacyLiteralPayload<'a>> {
    parse_legacy_literal_entropy_payload_internal(
        source,
        offset,
        element_width,
        limits,
        transform_name,
        LEGACY_ENTROPY_MAX_DEPTH,
    )
}

fn parse_legacy_literal_entropy_payload_internal<'a>(
    source: &'a [u8],
    offset: &mut usize,
    element_width: usize,
    limits: Limits,
    transform_name: &str,
    max_depth: usize,
) -> Result<LegacyLiteralPayload<'a>> {
    let header = *source.get(*offset).ok_or_else(|| {
        Error::new(ErrorKind::Malformed)
            .with_detail(format!("{transform_name} entropy header is truncated"))
    })?;
    match header & 0x07 {
        4 => parse_legacy_literal_bit_block(
            source,
            offset,
            header,
            element_width,
            limits,
            transform_name,
        ),
        1 => {
            decode_legacy_fse_entropy_payload(source, offset, element_width, limits, transform_name)
                .map(LegacyLiteralPayload::Decoded)
        }
        0 => decode_legacy_huffman_block(
            source,
            offset,
            element_width,
            limits,
            transform_name,
            max_depth,
        )
        .map(LegacyLiteralPayload::Decoded),
        _ => parse_legacy_literal_sized_block(
            source,
            offset,
            element_width,
            limits,
            transform_name,
            max_depth,
        ),
    }
}

/// A bit-packed block: the header byte holds the bit width, then the
/// element count follows as a varint.
fn parse_legacy_literal_bit_block<'a>(
    source: &'a [u8],
    offset: &mut usize,
    header: u8,
    element_width: usize,
    limits: Limits,
    transform_name: &str,
) -> Result<LegacyLiteralPayload<'a>> {
    *offset = (*offset)
        .checked_add(1)
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
    let num_bits = usize::from(header >> 3);
    let decoded_elements = usize::try_from(read_var_u64(source, offset)?).map_err(|_| {
        Error::new(ErrorKind::LimitExceeded)
            .with_detail(format!("{transform_name} output size is too large"))
    })?;
    decode_legacy_bit_entropy_payload(
        source,
        offset,
        decoded_elements,
        element_width,
        num_bits,
        limits,
        transform_name,
    )
    .map(LegacyLiteralPayload::Decoded)
}

/// Blocks whose header holds the element count: constant, raw and multi.
fn parse_legacy_literal_sized_block<'a>(
    source: &'a [u8],
    offset: &mut usize,
    element_width: usize,
    limits: Limits,
    transform_name: &str,
    max_depth: usize,
) -> Result<LegacyLiteralPayload<'a>> {
    let (entropy_type, decoded_elements) =
        read_legacy_entropy_header(source, offset, transform_name)?;
    match entropy_type {
        2 => {
            let output_len = legacy_entropy_output_len(decoded_elements, element_width)?;
            if output_len > limits.max_buffer_bytes {
                return Err(Error::new(ErrorKind::LimitExceeded)
                    .with_detail(format!("{transform_name} exceeds buffer limit")));
            }
            let end = (*offset)
                .checked_add(element_width)
                .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
            let value = source
                .get(*offset..end)
                .ok_or_else(|| Error::new(ErrorKind::Malformed))?;
            *offset = end;
            Ok(LegacyLiteralPayload::Constant {
                value,
                decoded_elements,
                element_width,
            })
        }
        3 => {
            let output_len = legacy_entropy_output_len(decoded_elements, element_width)?;
            if output_len > limits.max_buffer_bytes {
                return Err(Error::new(ErrorKind::LimitExceeded)
                    .with_detail(format!("{transform_name} exceeds buffer limit")));
            }
            let end = (*offset)
                .checked_add(output_len)
                .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
            let payload = source
                .get(*offset..end)
                .ok_or_else(|| Error::new(ErrorKind::Malformed))?;
            *offset = end;
            Ok(LegacyLiteralPayload::Raw(payload))
        }
        5 => decode_legacy_multi_entropy_payload(
            source,
            offset,
            decoded_elements,
            element_width,
            limits,
            transform_name,
            max_depth,
        )
        .map(LegacyLiteralPayload::Decoded),
        _ => Err(Error::new(ErrorKind::Malformed)
            .with_detail(format!("{transform_name} entropy mode is reserved"))),
    }
}

fn decode_legacy_multi_entropy_payload(
    source: &[u8],
    offset: &mut usize,
    blocks: usize,
    element_width: usize,
    limits: Limits,
    transform_name: &str,
    max_depth: usize,
) -> Result<Vec<u8>> {
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
    let mut output = Vec::new();
    for _ in 0..blocks {
        let block = parse_legacy_literal_entropy_payload_internal(
            source,
            offset,
            element_width,
            limits,
            transform_name,
            max_depth - 1,
        )?;
        let block_len = block.byte_len()?;
        if block_len == 0 {
            return Err(Error::new(ErrorKind::Malformed)
                .with_detail(format!("{transform_name} multi entropy block is empty")));
        }
        let output_len = output
            .len()
            .checked_add(block_len)
            .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
        if output_len > limits.max_buffer_bytes {
            return Err(Error::new(ErrorKind::LimitExceeded)
                .with_detail(format!("{transform_name} exceeds buffer limit")));
        }
        output.try_reserve_exact(block_len).map_err(|_| {
            Error::new(ErrorKind::AllocationFailed)
                .with_detail(format!("{transform_name} allocation failed"))
        })?;
        append_legacy_literal_payload(block, &mut output);
    }
    Ok(output)
}

fn decode_legacy_fse_entropy_payload(
    source: &[u8],
    offset: &mut usize,
    element_width: usize,
    limits: Limits,
    transform_name: &str,
) -> Result<Vec<u8>> {
    if element_width != 1 {
        return Err(Error::new(ErrorKind::Unsupported).with_detail(format!(
            "{transform_name} fse entropy element width is unsupported"
        )));
    }
    let header = read_legacy_compressed_entropy_header(source, offset, transform_name)?;
    let output_len = legacy_entropy_output_len(header.decoded_elements, element_width)?;
    if output_len > limits.max_buffer_bytes {
        return Err(Error::new(ErrorKind::LimitExceeded)
            .with_detail(format!("{transform_name} exceeds buffer limit")));
    }

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
        2,
        &table,
        accuracy_log,
        transform_name,
    )?;
    debug_assert_eq!(bytes.len(), output_len);
    *offset = end;
    Ok(bytes)
}

fn decode_legacy_bit_entropy_payload(
    source: &[u8],
    offset: &mut usize,
    decoded_elements: usize,
    element_width: usize,
    num_bits: usize,
    limits: Limits,
    transform_name: &str,
) -> Result<Vec<u8>> {
    let max_bits = element_width.checked_mul(8).ok_or_else(|| {
        Error::new(ErrorKind::IntegerOverflow)
            .with_detail(format!("{transform_name} element width is too large"))
    })?;
    if !matches!(element_width, 1 | 2 | 4 | 8) || num_bits >= max_bits {
        return Err(Error::new(ErrorKind::Malformed)
            .with_detail(format!("{transform_name} bit width is invalid")));
    }

    let output_len = legacy_entropy_output_len(decoded_elements, element_width)?;
    if output_len > limits.max_buffer_bytes {
        return Err(Error::new(ErrorKind::LimitExceeded)
            .with_detail(format!("{transform_name} exceeds buffer limit")));
    }
    unpack_legacy_bits(
        source,
        offset,
        decoded_elements,
        element_width,
        num_bits,
        output_len,
        transform_name,
    )
}

fn legacy_entropy_output_len(decoded_elements: usize, element_width: usize) -> Result<usize> {
    decoded_elements
        .checked_mul(element_width)
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))
}

pub(super) fn read_legacy_literal_byte(
    literals: &LegacyLiteralPayload<'_>,
    offset: usize,
    transform_name: &str,
) -> Result<u8> {
    match literals {
        LegacyLiteralPayload::Raw(bytes) => bytes.get(offset).copied().ok_or_else(|| {
            Error::new(ErrorKind::Malformed)
                .with_detail(format!("{transform_name} stream is too short"))
        }),
        LegacyLiteralPayload::Decoded(bytes) => bytes.get(offset).copied().ok_or_else(|| {
            Error::new(ErrorKind::Malformed)
                .with_detail(format!("{transform_name} stream is too short"))
        }),
        LegacyLiteralPayload::Constant {
            value,
            decoded_elements,
            element_width,
        } => {
            let len = legacy_entropy_output_len(*decoded_elements, *element_width)?;
            if offset >= len {
                return Err(Error::new(ErrorKind::Malformed)
                    .with_detail(format!("{transform_name} stream is too short")));
            }
            let value_offset = offset.checked_rem(*element_width).ok_or_else(|| {
                Error::new(ErrorKind::Malformed)
                    .with_detail(format!("{transform_name} literal width is invalid"))
            })?;
            value.get(value_offset).copied().ok_or_else(|| {
                Error::new(ErrorKind::Malformed)
                    .with_detail(format!("{transform_name} stream is too short"))
            })
        }
    }
}

pub(super) fn read_deprecated_lz_le_u32(
    source: &[u8],
    offset: usize,
    transform_name: &str,
) -> Result<u32> {
    let end = offset
        .checked_add(4)
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
    let bytes = source.get(offset..end).ok_or_else(|| {
        Error::new(ErrorKind::Malformed).with_detail(format!("{transform_name} is truncated"))
    })?;
    Ok(u32::from_le_bytes(
        bytes
            .try_into()
            .map_err(|_| Error::new(ErrorKind::Malformed))?,
    ))
}

pub(super) fn read_deprecated_lz_sized_slice<'a>(
    source: &'a [u8],
    offset: &mut usize,
    transform_name: &str,
) -> Result<&'a [u8]> {
    let size = usize::try_from(read_var_u64(source, offset)?).map_err(|_| {
        Error::new(ErrorKind::LimitExceeded)
            .with_detail(format!("{transform_name} stream is too large"))
    })?;
    let end = (*offset)
        .checked_add(size)
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
    let slice = source.get(*offset..end).ok_or_else(|| {
        Error::new(ErrorKind::Malformed)
            .with_detail(format!("{transform_name} stream is truncated"))
    })?;
    *offset = end;
    Ok(slice)
}

fn append_legacy_literal_payload(literals: LegacyLiteralPayload<'_>, output: &mut Vec<u8>) {
    match literals {
        LegacyLiteralPayload::Raw(bytes) => output.extend_from_slice(bytes),
        LegacyLiteralPayload::Decoded(bytes) => output.extend_from_slice(&bytes),
        LegacyLiteralPayload::Constant {
            value,
            decoded_elements,
            ..
        } => {
            for _ in 0..decoded_elements {
                output.extend_from_slice(value);
            }
        }
    }
}

pub(super) fn copy_deprecated_lz_literals(
    literals: LegacyLiteralPayload<'_>,
    transform_name: &str,
) -> Result<Vec<u8>> {
    let output_len = literals.byte_len()?;
    let mut output = Vec::new();
    output.try_reserve_exact(output_len).map_err(|_| {
        Error::new(ErrorKind::AllocationFailed)
            .with_detail(format!("{transform_name} allocation failed"))
    })?;
    append_legacy_literal_payload(literals, &mut output);
    Ok(output)
}
