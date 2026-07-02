use alloc::vec::Vec;

use ozlrip_core::{Error, ErrorKind, FrameInfo, FrameValueType, Limits, Result};

const MAGIC_BASE: u32 = 0xd7b1_a5c0;
const MIN_FORMAT_VERSION: u32 = 8;
const MAX_FORMAT_VERSION: u32 = 26;
const CHUNK_VERSION_MIN: u32 = 21;
const COMMENT_VERSION_MIN: u32 = 22;
const MATERIALIZED_DICT_VERSION_MIN: u32 = 25;
const UNIQUE_ID_BYTES: usize = 32;
const MAX_HEADER_COMMENT_BYTES: u64 = 10_000;

pub(crate) fn inspect_frame(input: &[u8], limits: Limits) -> Result<FrameInfo> {
    check_limit(
        input.len(),
        limits.max_frame_bytes,
        ErrorKind::LimitExceeded,
    )?;

    let mut reader = Reader::new(input);
    let magic = reader.read_u32_le()?;
    let format_version = format_version_from_magic(magic)?;

    let mut flags = FrameFlags::default();
    if format_version >= CHUNK_VERSION_MIN {
        flags = FrameFlags::from_byte(reader.read_byte()?, format_version);
    }

    let dictionary_bundle_id = if flags.has_bundle_id() {
        Some(read_bundle_id(&mut reader)?)
    } else {
        None
    };

    let output_header = read_output_header(&mut reader, input, format_version, limits)?;
    let output_sizes = read_output_sizes(
        &mut reader,
        &output_header.output_types,
        format_version,
        limits,
    )?;

    if flags.has_comment() {
        read_comment(&mut reader)?;
    }

    if format_version >= CHUNK_VERSION_MIN && flags.has_encoded_checksum() {
        let checksum_offset = reader.offset();
        let expected = reader.read_byte()?;
        #[cfg(not(feature = "checksum"))]
        let _ = (checksum_offset, expected);
        #[cfg(feature = "checksum")]
        verify_header_checksum(&input[..checksum_offset], expected, checksum_offset)?;
    }

    Ok(FrameInfo {
        format_version,
        frame_bytes: input.len(),
        header_bytes: reader.offset(),
        decoded_bytes: output_sizes.decoded_bytes,
        chunks: 0,
        inputs: output_header.outputs,
        output_types: output_header.output_types,
        output_sizes: output_sizes.sizes,
        output_elements: output_sizes.elements,
        transforms: 0,
        stored_streams: 0,
        regenerated_streams: 0,
        has_decoded_checksum: flags.has_decoded_checksum(),
        has_encoded_checksum: flags.has_encoded_checksum(),
        has_comment: flags.has_comment(),
        dictionary_bundle_id,
    })
}

fn format_version_from_magic(magic: u32) -> Result<u32> {
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

fn read_bundle_id(reader: &mut Reader<'_>) -> Result<Vec<u8>> {
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

fn read_output_header(
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

fn read_output_count(reader: &mut Reader<'_>, format_version: u32) -> Result<usize> {
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

fn read_output_types(
    reader: &mut Reader<'_>,
    input: &[u8],
    outputs: usize,
    format_version: u32,
) -> Result<Vec<FrameValueType>> {
    let mut types = Vec::new();
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

fn read_packed_types(
    reader: &mut Reader<'_>,
    types: &mut Vec<FrameValueType>,
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

fn decode_type(encoded: u8, offset: usize) -> Result<FrameValueType> {
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

fn read_output_sizes(
    reader: &mut Reader<'_>,
    types: &[FrameValueType],
    format_version: u32,
    limits: Limits,
) -> Result<OutputSizes> {
    let outputs = types.len();
    let mut sizes = Vec::new();
    let mut elements = Vec::new();
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
        let _ = reader.read_byte()?;
        sizes.resize(outputs, None);
        elements.resize(outputs, None);
        return Ok(OutputSizes {
            sizes,
            elements,
            decoded_bytes: None,
        });
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

fn read_comment(reader: &mut Reader<'_>) -> Result<()> {
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
    let _ = reader.read_slice(len)?;
    Ok(())
}

#[cfg(feature = "checksum")]
fn verify_header_checksum(bytes: &[u8], expected: u8, offset: usize) -> Result<()> {
    let actual = (xxhash_rust::xxh3::xxh3_64(bytes) & 0xff) as u8;
    if actual != expected {
        return Err(Error::at(ErrorKind::ChecksumMismatch, offset)
            .with_detail("OpenZL frame header checksum mismatch"));
    }
    Ok(())
}

fn runtime_input_limit(format_version: u32) -> usize {
    if format_version <= 14 { 1 } else { 2048 }
}

fn check_limit(value: usize, limit: usize, kind: ErrorKind) -> Result<()> {
    if value > limit {
        return Err(Error::new(kind).with_detail("configured limit exceeded"));
    }
    Ok(())
}

fn checked_add(lhs: usize, rhs: usize) -> Result<usize> {
    lhs.checked_add(rhs)
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))
}

fn checked_mul(lhs: usize, rhs: usize) -> Result<usize> {
    lhs.checked_mul(rhs)
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct FrameFlags(u8);

impl FrameFlags {
    const fn from_byte(flags: u8, format_version: u32) -> Self {
        let mut normalized = flags & 0b0000_0011;
        if format_version >= COMMENT_VERSION_MIN {
            normalized |= flags & (1 << 2);
        }
        if format_version >= MATERIALIZED_DICT_VERSION_MIN {
            normalized |= flags & (1 << 3);
        }
        Self(normalized)
    }

    const fn has_decoded_checksum(self) -> bool {
        self.0 & (1 << 0) != 0
    }

    const fn has_encoded_checksum(self) -> bool {
        self.0 & (1 << 1) != 0
    }

    const fn has_comment(self) -> bool {
        self.0 & (1 << 2) != 0
    }

    const fn has_bundle_id(self) -> bool {
        self.0 & (1 << 3) != 0
    }
}

struct OutputHeader {
    outputs: usize,
    output_types: Vec<FrameValueType>,
}

struct OutputSizes {
    sizes: Vec<Option<u64>>,
    elements: Vec<Option<u64>>,
    decoded_bytes: Option<usize>,
}

struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    const fn offset(&self) -> usize {
        self.offset
    }

    fn read_slice(&mut self, len: usize) -> Result<&'a [u8]> {
        let end = self
            .offset
            .checked_add(len)
            .ok_or_else(|| Error::at(ErrorKind::IntegerOverflow, self.offset))?;
        let slice = self
            .bytes
            .get(self.offset..end)
            .ok_or_else(|| Error::at(ErrorKind::Truncated, self.offset))?;
        self.offset = end;
        Ok(slice)
    }

    fn read_byte(&mut self) -> Result<u8> {
        let byte = self.peek_byte()?;
        self.offset = self
            .offset
            .checked_add(1)
            .ok_or_else(|| Error::at(ErrorKind::IntegerOverflow, self.offset))?;
        Ok(byte)
    }

    fn peek_byte(&self) -> Result<u8> {
        self.bytes
            .get(self.offset)
            .copied()
            .ok_or_else(|| Error::at(ErrorKind::Truncated, self.offset))
    }

    fn read_u16_le(&mut self) -> Result<u16> {
        let bytes = self.read_array::<2>()?;
        Ok(u16::from_le_bytes(bytes))
    }

    fn read_u32_le(&mut self) -> Result<u32> {
        let bytes = self.read_array::<4>()?;
        Ok(u32::from_le_bytes(bytes))
    }

    fn read_array<const N: usize>(&mut self) -> Result<[u8; N]> {
        let slice = self.read_slice(N)?;
        let mut out = [0; N];
        out.copy_from_slice(slice);
        Ok(out)
    }

    fn read_var_u64(&mut self) -> Result<u64> {
        let start = self.offset;
        let mut value = 0u64;
        for index in 0..10 {
            let byte = self.read_byte()?;
            let payload = u64::from(byte & 0x7f);
            let shift = checked_mul(index, 7)?;
            let shifted = payload
                .checked_shl(
                    u32::try_from(shift)
                        .map_err(|_| Error::at(ErrorKind::IntegerOverflow, start))?,
                )
                .ok_or_else(|| Error::at(ErrorKind::IntegerOverflow, start))?;
            value = value
                .checked_add(shifted)
                .ok_or_else(|| Error::at(ErrorKind::IntegerOverflow, start))?;
            if byte & 0x80 == 0 {
                return Ok(value);
            }
        }
        Err(Error::at(ErrorKind::Malformed, start).with_detail("u64 varint is too long"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn magic(version: u32) -> [u8; 4] {
        (MAGIC_BASE + version).to_le_bytes()
    }

    #[test]
    fn rejects_truncated_magic() {
        let err = inspect_frame(&[0xd5, 0xa5], Limits::default()).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Truncated);
        assert_eq!(err.offset(), Some(0));
    }

    #[test]
    fn rejects_unknown_magic() {
        let err = inspect_frame(b"not-openzl", Limits::default()).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Unsupported);
        assert_eq!(err.offset(), Some(0));
    }

    #[test]
    fn parses_v21_single_serial_known_size_header() {
        let mut input = Vec::new();
        input.extend_from_slice(&magic(21));
        input.push(0);
        input.push(1);
        input.push(4);

        let info = inspect_frame(&input, Limits::default()).unwrap();

        assert_eq!(info.format_version, 21);
        assert_eq!(info.header_bytes, input.len());
        assert_eq!(info.decoded_bytes, Some(3));
        assert_eq!(info.inputs, 1);
        assert_eq!(info.output_types, [FrameValueType::Serial]);
        assert_eq!(info.output_sizes, [Some(3)]);
        assert_eq!(info.output_elements, [Some(3)]);
    }

    #[test]
    fn parses_v21_unknown_sizes() {
        let mut input = Vec::new();
        input.extend_from_slice(&magic(21));
        input.push(0);
        input.push(1);
        input.push(0);

        let info = inspect_frame(&input, Limits::default()).unwrap();

        assert_eq!(info.decoded_bytes, None);
        assert_eq!(info.output_sizes, [None]);
        assert_eq!(info.output_elements, [None]);
    }

    #[test]
    fn parses_v25_bundle_id() {
        let mut input = Vec::new();
        input.extend_from_slice(&magic(25));
        input.push(1 << 3);
        input.push(2);
        input.extend_from_slice(&[1, 2]);
        input.push(1);
        input.push(4);

        let info = inspect_frame(&input, Limits::default()).unwrap();

        assert_eq!(info.dictionary_bundle_id.as_deref(), Some(&[1, 2][..]));
    }

    #[test]
    fn rejects_zero_length_bundle_id() {
        let mut input = Vec::new();
        input.extend_from_slice(&magic(25));
        input.push(1 << 3);
        input.push(0);

        let err = inspect_frame(&input, Limits::default()).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Malformed);
    }

    #[test]
    fn enforces_frame_limit_before_parsing() {
        let limits = Limits {
            max_frame_bytes: 1,
            ..Limits::default()
        };
        let err = inspect_frame(&[0; 2], limits).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::LimitExceeded);
    }

    #[cfg(feature = "checksum")]
    #[test]
    fn verifies_v21_header_checksum() {
        let mut input = Vec::new();
        input.extend_from_slice(&magic(21));
        input.push(1 << 1);
        input.push(1);
        input.push(4);
        let checksum = (xxhash_rust::xxh3::xxh3_64(&input) & 0xff) as u8;
        input.push(checksum);

        let info = inspect_frame(&input, Limits::default()).unwrap();

        assert!(info.has_encoded_checksum);
        assert_eq!(info.header_bytes, input.len());
    }

    #[cfg(feature = "checksum")]
    #[test]
    fn rejects_bad_v21_header_checksum() {
        let mut input = Vec::new();
        input.extend_from_slice(&magic(21));
        input.push(1 << 1);
        input.push(1);
        input.push(4);
        input.push(0);

        let err = inspect_frame(&input, Limits::default()).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::ChecksumMismatch);
    }
}
