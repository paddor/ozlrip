use alloc::vec::Vec;

use crate::info::FrameValueType;
use ozlrip_core::{Error, ErrorKind, Limits, Result};

use super::reader::{Reader, check_limit, checked_add, checked_mul};
use super::{
    CHUNK_VERSION_MIN, COMMENT_VERSION_MIN, MAGIC_BASE, MATERIALIZED_DICT_VERSION_MIN,
    MAX_FORMAT_VERSION, MAX_HEADER_COMMENT_BYTES, MIN_FORMAT_VERSION, OutputSizeValues,
    OutputTypes, UNIQUE_ID_BYTES,
};

pub(super) fn format_version_from_magic(magic: u32) -> Result<u32> {
    let Some(version) = magic.checked_sub(MAGIC_BASE) else {
        return Err(
            Error::at(ErrorKind::Unsupported, 0).with_detail("unrecognized OpenZL frame magic")
        );
    };

    if !(MIN_FORMAT_VERSION..=MAX_FORMAT_VERSION).contains(&version) {
        return Err(
            Error::at(ErrorKind::Unsupported, 0).with_detail("unsupported OpenZL format version")
        );
    }
    Ok(version)
}

pub(super) fn read_bundle_id(reader: &mut Reader<'_>) -> Result<Vec<u8>> {
    let offset = reader.offset();
    let len = usize::from(reader.read_byte()?);
    if len == 0 {
        return Err(Error::at(ErrorKind::Malformed, offset)
            .with_detail("bundle ID flag is set with zero encoded length"));
    }
    if len > UNIQUE_ID_BYTES {
        return Err(Error::at(ErrorKind::Malformed, offset)
            .with_detail("bundle ID encoded length is too large"));
    }
    let id = reader.read_slice(len)?.to_vec();
    if id.iter().all(|&byte| byte == 0) {
        return Err(Error::at(ErrorKind::Malformed, offset)
            .with_detail("bundle ID flag is set with all-zero ID"));
    }
    Ok(id)
}

pub(super) fn read_output_header(
    reader: &mut Reader<'_>,
    input: &[u8],
    format_version: u32,
    limits: Limits,
) -> Result<OutputHeader> {
    let outputs = read_output_count(reader, format_version)?;
    check_limit(
        outputs,
        runtime_input_limit(format_version),
        ErrorKind::Malformed,
    )?;
    check_limit(outputs, limits.max_streams, ErrorKind::LimitExceeded)?;
    if outputs == 0 {
        return Err(Error::at(ErrorKind::Malformed, reader.offset())
            .with_detail("OpenZL frames with zero outputs are unsupported"));
    }

    let output_types = read_output_types(reader, input, outputs, format_version)?;
    Ok(OutputHeader {
        outputs,
        output_types,
    })
}

pub(super) fn read_output_count(reader: &mut Reader<'_>, format_version: u32) -> Result<usize> {
    if format_version <= 14 {
        if format_version == 14 {
            let _ = reader.read_byte()?;
        }
        return Ok(1);
    }

    if format_version < CHUNK_VERSION_MIN {
        let token1 = reader.read_byte()?;
        let mut outputs = usize::from(token1 >> 6) + 1;
        if outputs == 4 {
            outputs = usize::from(reader.read_byte()? >> 4) + 4;
        }
        if outputs == 19 {
            outputs = usize::from(reader.read_byte()?) + 19;
        }
        if outputs == 274 {
            outputs = usize::from(reader.read_u16_le()?) + 274;
        }
        return Ok(outputs);
    }

    let token1 = reader.read_byte()?;
    let mut outputs = usize::from(token1 & 0x0f);
    if outputs == 15 {
        let token2 = reader.read_byte()?;
        outputs = (usize::from(token2) << 4) + usize::from(token1 >> 4) + 15;
    }
    Ok(outputs)
}

pub(super) fn read_output_types(
    reader: &mut Reader<'_>,
    input: &[u8],
    outputs: usize,
    format_version: u32,
) -> Result<OutputTypes> {
    let mut types = OutputTypes::new();
    types.try_reserve_exact(outputs).map_err(|_| {
        Error::new(ErrorKind::LimitExceeded).with_detail("output type allocation failed")
    })?;

    if format_version < 14 {
        types.push(FrameValueType::Serial);
        return Ok(types);
    }

    if format_version == 14 {
        let encoded = *input
            .get(4)
            .ok_or_else(|| Error::at(ErrorKind::Truncated, 4))?;
        if encoded > 3 {
            return Err(
                Error::at(ErrorKind::InvalidType, 4).with_detail("invalid OpenZL output type")
            );
        }
        types.push(decode_type(encoded, 4)?);
        return Ok(types);
    }

    if format_version < CHUNK_VERSION_MIN {
        let first_token = outputs.min(3);
        for n in 0..first_token {
            let shift = checked_mul(n, 2)?;
            types.push(decode_type((input[4] >> shift) & 3, 4)?);
        }
        if outputs > 3 {
            let limit = outputs.min(5);
            let token = *input
                .get(5)
                .ok_or_else(|| Error::at(ErrorKind::Truncated, 5))?;
            for n in 3..limit {
                let shift = checked_mul(n - 3, 2)?;
                types.push(decode_type((token >> shift) & 3, 5)?);
            }
        }
        if outputs > 5 {
            read_packed_types(reader, &mut types, outputs, 5)?;
        }
        return Ok(types);
    }

    let token_offset = if outputs <= 14 {
        reader
            .offset()
            .checked_sub(1)
            .ok_or_else(|| Error::at(ErrorKind::IntegerOverflow, reader.offset()))?
    } else {
        reader.offset()
    };
    if outputs <= 14 {
        let token = *input
            .get(token_offset)
            .ok_or_else(|| Error::at(ErrorKind::Truncated, token_offset))?;
        let max = outputs.min(2);
        for n in 0..max {
            let shift = checked_add(checked_mul(n, 2)?, 4)?;
            types.push(decode_type((token >> shift) & 3, token_offset)?);
        }
        if outputs <= 2 {
            return Ok(types);
        }
    }

    let done = types.len();
    read_packed_types(reader, &mut types, outputs, done)?;
    Ok(types)
}

pub(super) fn read_packed_types(
    reader: &mut Reader<'_>,
    types: &mut OutputTypes,
    outputs: usize,
    done: usize,
) -> Result<()> {
    let mut token = 0;
    for n in done..outputs {
        let shift = checked_mul((n - done) % 4, 2)?;
        let offset = reader.offset();
        if shift == 0 {
            token = reader.read_byte()?;
        }
        types.push(decode_type((token >> shift) & 3, offset)?);
    }
    Ok(())
}

pub(super) fn decode_type(encoded: u8, offset: usize) -> Result<FrameValueType> {
    match encoded {
        0 => Ok(FrameValueType::Serial),
        1 => Ok(FrameValueType::Struct),
        2 => Ok(FrameValueType::Numeric),
        3 => Ok(FrameValueType::String),
        _ => {
            Err(Error::at(ErrorKind::InvalidType, offset).with_detail("invalid OpenZL output type"))
        }
    }
}

pub(super) fn read_output_sizes(
    reader: &mut Reader<'_>,
    types: &[FrameValueType],
    format_version: u32,
    limits: Limits,
) -> Result<OutputSizes> {
    let outputs = types.len();
    let mut sizes = OutputSizeValues::new();
    let mut elements = OutputSizeValues::new();
    sizes.try_reserve_exact(outputs).map_err(|_| {
        Error::new(ErrorKind::LimitExceeded).with_detail("output size allocation failed")
    })?;
    elements.try_reserve_exact(outputs).map_err(|_| {
        Error::new(ErrorKind::LimitExceeded).with_detail("output element allocation failed")
    })?;

    if format_version < CHUNK_VERSION_MIN {
        let mut total = 0usize;
        for value_type in types {
            let size = u64::from(reader.read_u32_le()?);
            let size_usize = usize::try_from(size)
                .map_err(|_| Error::at(ErrorKind::LimitExceeded, reader.offset()))?;
            check_limit(
                size_usize,
                limits.max_buffer_bytes,
                ErrorKind::LimitExceeded,
            )?;
            total = checked_add(total, size_usize)?;
            check_limit(total, limits.max_decoded_bytes, ErrorKind::LimitExceeded)?;
            sizes.push(Some(size));
            elements.push(match value_type {
                FrameValueType::Serial => Some(size),
                FrameValueType::String | FrameValueType::Struct | FrameValueType::Numeric => None,
            });
        }
        return Ok(OutputSizes {
            sizes,
            elements,
            decoded_bytes: Some(total),
        });
    }

    let first = reader.peek_byte()?;
    if first == 0 {
        return Err(Error::at(ErrorKind::Unsupported, reader.offset())
            .with_detail("unknown OpenZL output sizes are unsupported"));
    }

    let mut total = 0usize;
    for _ in 0..outputs {
        let encoded = reader.read_var_u64()?;
        if encoded == 0 {
            return Err(Error::at(ErrorKind::Malformed, reader.offset())
                .with_detail("mixed known and unknown output sizes"));
        }
        let size = encoded
            .checked_sub(1)
            .ok_or_else(|| Error::at(ErrorKind::IntegerOverflow, reader.offset()))?;
        let size_usize = usize::try_from(size)
            .map_err(|_| Error::at(ErrorKind::LimitExceeded, reader.offset()))?;
        check_limit(
            size_usize,
            limits.max_buffer_bytes,
            ErrorKind::LimitExceeded,
        )?;
        total = checked_add(total, size_usize)?;
        check_limit(total, limits.max_decoded_bytes, ErrorKind::LimitExceeded)?;
        sizes.push(Some(size));
    }

    for (idx, value_type) in types.iter().enumerate() {
        match value_type {
            FrameValueType::Serial => elements.push(sizes[idx]),
            FrameValueType::String => elements.push(Some(reader.read_var_u64()?)),
            FrameValueType::Struct | FrameValueType::Numeric => elements.push(None),
        }
    }

    Ok(OutputSizes {
        sizes,
        elements,
        decoded_bytes: Some(total),
    })
}

pub(super) fn read_comment(reader: &mut Reader<'_>) -> Result<Vec<u8>> {
    let offset = reader.offset();
    let len = reader.read_var_u64()?;
    if len == 0 {
        return Err(Error::at(ErrorKind::Malformed, offset)
            .with_detail("comment flag is set with zero comment length"));
    }
    if len > MAX_HEADER_COMMENT_BYTES {
        return Err(Error::at(ErrorKind::LimitExceeded, offset)
            .with_detail("OpenZL frame comment exceeds configured hard limit"));
    }
    let len = usize::try_from(len).map_err(|_| Error::at(ErrorKind::LimitExceeded, offset))?;
    Ok(reader.read_slice(len)?.to_vec())
}

#[cfg(feature = "checksum")]
pub(super) fn verify_header_checksum(bytes: &[u8], expected: u8, offset: usize) -> Result<()> {
    let actual = (xxhash_rust::xxh3::xxh3_64(bytes) & 0xff) as u8;
    if actual != expected {
        return Err(Error::at(ErrorKind::ChecksumMismatch, offset)
            .with_detail("OpenZL frame header checksum mismatch"));
    }
    Ok(())
}

pub(super) fn runtime_input_limit(format_version: u32) -> usize {
    if format_version <= 14 { 1 } else { 2048 }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(super) struct FrameFlags(u8);

impl FrameFlags {
    pub(super) const fn from_byte(flags: u8, format_version: u32) -> Self {
        let mut normalized = flags & 0b0000_0011;
        if format_version >= COMMENT_VERSION_MIN {
            normalized |= flags & (1 << 2);
        }
        if format_version >= MATERIALIZED_DICT_VERSION_MIN {
            normalized |= flags & (1 << 3);
        }
        Self(normalized)
    }

    pub(super) const fn has_decoded_checksum(self) -> bool {
        self.0 & (1 << 0) != 0
    }

    pub(super) const fn has_encoded_checksum(self) -> bool {
        self.0 & (1 << 1) != 0
    }

    pub(super) const fn has_comment(self) -> bool {
        self.0 & (1 << 2) != 0
    }

    pub(super) const fn has_bundle_id(self) -> bool {
        self.0 & (1 << 3) != 0
    }
}

pub(super) struct OutputHeader {
    pub(super) outputs: usize,
    pub(super) output_types: OutputTypes,
}

pub(super) struct OutputSizes {
    pub(super) sizes: OutputSizeValues,
    pub(super) elements: OutputSizeValues,
    pub(super) decoded_bytes: Option<usize>,
}
