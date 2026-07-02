use alloc::vec::Vec;

use ozlrip_core::{Error, ErrorKind, FrameValueType, Limits, Result};

use crate::{parse::FramePlan, standard};

pub(crate) fn decode_plan(
    input: &[u8],
    plan: &FramePlan,
    dst: &mut Vec<u8>,
    limits: Limits,
) -> Result<usize> {
    if plan.info.dictionary_bundle_id.is_some() {
        return Err(Error::new(ErrorKind::Unsupported)
            .with_detail("dictionary bundle materialization is not implemented"));
    }
    let decoded = collect_decoded_output(input, plan, limits)?;
    dst.try_reserve_exact(decoded.total_len).map_err(|_| {
        Error::new(ErrorKind::LimitExceeded).with_detail("output allocation failed")
    })?;
    for chunk in decoded.chunks {
        dst.extend_from_slice(chunk.as_slice());
    }
    Ok(decoded.total_len)
}

fn collect_decoded_output<'a>(
    input: &'a [u8],
    plan: &FramePlan,
    limits: Limits,
) -> Result<DecodedOutput<'a>> {
    if plan.info.output_types.as_slice() != [FrameValueType::Serial] {
        return Err(Error::new(ErrorKind::Unsupported)
            .with_detail("only single serial stored-output frames are implemented"));
    }

    let mut chunks = Vec::new();
    chunks.try_reserve_exact(plan.chunks.len()).map_err(|_| {
        Error::new(ErrorKind::LimitExceeded).with_detail("decoded output list allocation failed")
    })?;
    let mut total_len = 0usize;
    for chunk in &plan.chunks {
        let decoded = if chunk.has_nodes() {
            decode_simple_transform_chunk(input, chunk, limits)?
        } else {
            DecodedChunk::Borrowed(stored_only_chunk(input, chunk)?)
        };
        let decoded_len = decoded.as_slice().len();
        total_len = total_len
            .checked_add(decoded_len)
            .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
        #[cfg(not(feature = "checksum"))]
        let _ = chunk.decoded_checksum;
        #[cfg(feature = "checksum")]
        verify_decoded_checksum(decoded.as_slice(), chunk.decoded_checksum)?;
        chunks.push(decoded);
    }
    check_output_size(total_len, input.len(), plan, limits)?;
    Ok(DecodedOutput { chunks, total_len })
}

fn stored_only_chunk<'a>(input: &'a [u8], chunk: &crate::parse::ChunkPlan) -> Result<&'a [u8]> {
    let Some(range) = chunk.stored_stream_range(0) else {
        return Err(Error::new(ErrorKind::Unsupported)
            .with_detail("stored-output chunk does not contain one stored stream"));
    };
    if chunk.stored_stream_range(1).is_some() {
        return Err(Error::new(ErrorKind::Unsupported)
            .with_detail("stored-output chunk contains multiple stored streams"));
    }
    range.as_slice(input)
}

fn decode_simple_transform_chunk(
    input: &[u8],
    chunk: &crate::parse::ChunkPlan,
    limits: Limits,
) -> Result<DecodedChunk<'static>> {
    let Some(node) = chunk.single_node() else {
        return Err(Error::new(ErrorKind::Unsupported)
            .with_detail("only single-node transform chunks are implemented"));
    };
    if node.variable_outputs() != 0 || node.regen_distances() != [0] {
        return Err(Error::new(ErrorKind::Unsupported)
            .with_detail("only single-input single-output transform chunks are implemented"));
    }
    if chunk.stored_stream_range(1).is_some() {
        return Err(Error::new(ErrorKind::Unsupported)
            .with_detail("transform chunk contains multiple stored streams"));
    }
    let Some(stored_range) = chunk.stored_stream_range(0) else {
        return Err(Error::new(ErrorKind::Unsupported)
            .with_detail("transform chunk does not contain one stored stream"));
    };
    let stored = stored_range.as_slice(input)?;
    let header = chunk.transform_header_range().as_slice(input)?;
    match node.standard_id() {
        Some(standard::LZ4_ID) => decode_lz4_chunk(stored, header, limits).map(DecodedChunk::Owned),
        _ => Err(Error::new(ErrorKind::Unsupported)
            .with_detail("transform graph execution is not implemented yet")),
    }
}

#[cfg(feature = "lz4")]
fn decode_lz4_chunk(stored: &[u8], header: &[u8], limits: Limits) -> Result<Vec<u8>> {
    let decoded_size = read_single_varint_header(header)?;
    if decoded_size > limits.max_decoded_bytes || decoded_size > limits.max_buffer_bytes {
        return Err(
            Error::new(ErrorKind::LimitExceeded).with_detail("decoded output limit exceeded")
        );
    }
    let mut output = alloc::vec![0; decoded_size];
    let written = lz4rip::block::decompress_into(stored, &mut output)
        .map_err(|_| Error::new(ErrorKind::Malformed).with_detail("OpenZL lz4 block failed"))?;
    if written != decoded_size {
        return Err(Error::new(ErrorKind::Malformed).with_detail("OpenZL lz4 output size mismatch"));
    }
    Ok(output)
}

#[cfg(not(feature = "lz4"))]
fn decode_lz4_chunk(_stored: &[u8], _header: &[u8], _limits: Limits) -> Result<Vec<u8>> {
    Err(Error::new(ErrorKind::Unsupported).with_detail("lz4 support is disabled"))
}

#[cfg(feature = "lz4")]
fn read_single_varint_header(header: &[u8]) -> Result<usize> {
    let mut offset = 0usize;
    let value = read_var_u64(header, &mut offset)?;
    if offset != header.len() {
        return Err(
            Error::new(ErrorKind::Malformed).with_detail("unexpected transform header bytes")
        );
    }
    usize::try_from(value).map_err(|_| {
        Error::new(ErrorKind::LimitExceeded).with_detail("transform header value is too large")
    })
}

#[cfg(feature = "lz4")]
fn read_var_u64(input: &[u8], offset: &mut usize) -> Result<u64> {
    let start = *offset;
    let mut value = 0u64;
    for index in 0..10 {
        let byte = *input
            .get(*offset)
            .ok_or_else(|| Error::at(ErrorKind::Truncated, *offset))?;
        *offset = (*offset)
            .checked_add(1)
            .ok_or_else(|| Error::at(ErrorKind::IntegerOverflow, *offset))?;
        let payload = u64::from(byte & 0x7f);
        if index == 9 && payload > 1 {
            return Err(Error::at(ErrorKind::IntegerOverflow, start)
                .with_detail("u64 varint payload overflows"));
        }
        let shift = index * 7;
        let shifted = payload
            .checked_shl(shift)
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

struct DecodedOutput<'a> {
    chunks: Vec<DecodedChunk<'a>>,
    total_len: usize,
}

enum DecodedChunk<'a> {
    Borrowed(&'a [u8]),
    Owned(Vec<u8>),
}

impl DecodedChunk<'_> {
    fn as_slice(&self) -> &[u8] {
        match self {
            Self::Borrowed(bytes) => bytes,
            Self::Owned(bytes) => bytes,
        }
    }
}

fn check_output_size(
    size: usize,
    encoded_size: usize,
    plan: &FramePlan,
    limits: Limits,
) -> Result<()> {
    if size > limits.max_decoded_bytes || size > limits.max_buffer_bytes {
        return Err(
            Error::new(ErrorKind::LimitExceeded).with_detail("decoded output limit exceeded")
        );
    }
    let max_expanded = encoded_size
        .checked_mul(limits.max_expansion_ratio)
        .ok_or_else(|| {
            Error::new(ErrorKind::IntegerOverflow)
                .with_detail("encoded size expansion limit overflowed")
        })?;
    if size > max_expanded {
        return Err(
            Error::new(ErrorKind::LimitExceeded).with_detail("decoded expansion ratio exceeded")
        );
    }
    if let Some(expected) = plan.info.output_sizes.first().and_then(|size| *size) {
        let expected = usize::try_from(expected).map_err(|_| {
            Error::new(ErrorKind::LimitExceeded).with_detail("decoded output size is too large")
        })?;
        if expected != size {
            return Err(Error::new(ErrorKind::Malformed)
                .with_detail("stored output size does not match frame header"));
        }
    }
    Ok(())
}

#[cfg(feature = "checksum")]
fn verify_decoded_checksum(output: &[u8], expected: Option<u32>) -> Result<()> {
    if let Some(expected) = expected {
        let actual = (xxhash_rust::xxh3::xxh3_64(output) & 0xffff_ffff) as u32;
        if actual != expected {
            return Err(Error::new(ErrorKind::ChecksumMismatch)
                .with_detail("OpenZL decoded checksum mismatch"));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse::parse_frame_plan;
    use alloc::vec;

    const MAGIC_BASE: u32 = 0xd7b1_a5c0;

    fn magic(version: u32) -> [u8; 4] {
        (MAGIC_BASE + version).to_le_bytes()
    }

    #[cfg(feature = "lz4")]
    fn push_var_u64(out: &mut Vec<u8>, mut value: u64) {
        while value >= 0x80 {
            out.push(u8::try_from(value & 0x7f).unwrap() | 0x80);
            value >>= 7;
        }
        out.push(u8::try_from(value).unwrap());
    }

    #[test]
    fn decodes_v21_stored_serial_output() {
        let mut input = Vec::new();
        input.extend_from_slice(&magic(21));
        input.push(0);
        input.push(1);
        input.push(4);
        input.push(1);
        input.push(1);
        input.push(3);
        input.extend_from_slice(&[7, 8, 9]);
        input.push(0);
        let plan = parse_frame_plan(&input, Limits::default()).unwrap();
        let mut output = Vec::new();

        let written = decode_plan(&input, &plan, &mut output, Limits::default()).unwrap();

        assert_eq!(written, 3);
        assert_eq!(output, [7, 8, 9]);
    }

    #[test]
    fn decodes_empty_v21_stored_serial_output() {
        let mut input = Vec::new();
        input.extend_from_slice(&magic(21));
        input.push(0);
        input.push(1);
        input.push(1);
        input.push(0);
        let plan = parse_frame_plan(&input, Limits::default()).unwrap();
        let mut output = vec![1, 2];

        let written = decode_plan(&input, &plan, &mut output, Limits::default()).unwrap();

        assert_eq!(written, 0);
        assert_eq!(output, [1, 2]);
    }

    #[test]
    fn decodes_v21_stored_serial_chunks() {
        let mut input = Vec::new();
        input.extend_from_slice(&magic(21));
        input.push(0);
        input.push(1);
        input.push(8);
        input.push(1);
        input.push(1);
        input.push(3);
        input.extend_from_slice(&[7, 8, 9]);
        input.push(1);
        input.push(1);
        input.push(4);
        input.extend_from_slice(&[10, 11, 12, 13]);
        input.push(0);
        let plan = parse_frame_plan(&input, Limits::default()).unwrap();
        let mut output = Vec::new();

        let written = decode_plan(&input, &plan, &mut output, Limits::default()).unwrap();

        assert_eq!(written, 7);
        assert_eq!(output, [7, 8, 9, 10, 11, 12, 13]);
    }

    #[cfg(feature = "lz4")]
    #[test]
    fn decodes_v23_lz4_serial_chunk() {
        let expected = b"lz4-backed OpenZL serial chunk";
        let compressed = lz4rip::block::compress(expected);
        let mut input = Vec::new();
        input.extend_from_slice(&magic(23));
        input.push(0);
        input.push(1);
        push_var_u64(&mut input, u64::try_from(expected.len() + 1).unwrap());
        input.push(2);
        input.push(1);
        input.push(0);
        input.push(62);
        input.push(1);
        input.push(0);
        input.push(0);
        input.push(0);
        input.push(0);
        push_var_u64(&mut input, u64::try_from(compressed.len()).unwrap());
        push_var_u64(&mut input, u64::try_from(expected.len()).unwrap());
        input.extend_from_slice(&compressed);
        input.push(0);
        let plan = parse_frame_plan(&input, Limits::default()).unwrap();
        let mut output = Vec::new();

        let written = decode_plan(&input, &plan, &mut output, Limits::default()).unwrap();

        assert_eq!(written, expected.len());
        assert_eq!(output, expected);
    }

    #[test]
    fn rejects_size_mismatch_without_mutating_destination() {
        let mut input = Vec::new();
        input.extend_from_slice(&magic(21));
        input.push(0);
        input.push(1);
        input.push(5);
        input.push(1);
        input.push(1);
        input.push(3);
        input.extend_from_slice(&[7, 8, 9]);
        input.push(0);
        let plan = parse_frame_plan(&input, Limits::default()).unwrap();
        let mut output = vec![1, 2];

        let err = decode_plan(&input, &plan, &mut output, Limits::default()).unwrap_err();

        assert_eq!(err.kind(), ErrorKind::Malformed);
        assert_eq!(output, [1, 2]);
    }

    #[test]
    fn enforces_expansion_ratio_without_mutating_destination() {
        let mut input = Vec::new();
        input.extend_from_slice(&magic(21));
        input.push(0);
        input.push(1);
        input.push(4);
        input.push(1);
        input.push(1);
        input.push(3);
        input.extend_from_slice(&[7, 8, 9]);
        input.push(0);
        let plan = parse_frame_plan(&input, Limits::default()).unwrap();
        let mut output = vec![1, 2];
        let limits = Limits {
            max_expansion_ratio: 0,
            ..Limits::default()
        };

        let err = decode_plan(&input, &plan, &mut output, limits).unwrap_err();

        assert_eq!(err.kind(), ErrorKind::LimitExceeded);
        assert_eq!(output, [1, 2]);
    }

    #[cfg(feature = "checksum")]
    #[test]
    fn verifies_decoded_checksum() {
        let mut input = Vec::new();
        input.extend_from_slice(&magic(21));
        input.push(1);
        input.push(1);
        input.push(4);
        input.push(1);
        input.push(1);
        input.push(3);
        input.extend_from_slice(&[7, 8, 9]);
        let checksum = (xxhash_rust::xxh3::xxh3_64(&[7, 8, 9]) & 0xffff_ffff) as u32;
        input.extend_from_slice(&checksum.to_le_bytes());
        input.push(0);
        let plan = parse_frame_plan(&input, Limits::default()).unwrap();
        let mut output = Vec::new();

        let written = decode_plan(&input, &plan, &mut output, Limits::default()).unwrap();

        assert_eq!(written, 3);
        assert_eq!(output, [7, 8, 9]);
    }

    #[cfg(feature = "checksum")]
    #[test]
    fn rejects_decoded_checksum_mismatch_without_mutating_destination() {
        let mut input = Vec::new();
        input.extend_from_slice(&magic(21));
        input.push(1);
        input.push(1);
        input.push(4);
        input.push(1);
        input.push(1);
        input.push(3);
        input.extend_from_slice(&[7, 8, 9]);
        input.extend_from_slice(&0u32.to_le_bytes());
        input.push(0);
        let plan = parse_frame_plan(&input, Limits::default()).unwrap();
        let mut output = vec![1, 2];

        let err = decode_plan(&input, &plan, &mut output, Limits::default()).unwrap_err();

        assert_eq!(err.kind(), ErrorKind::ChecksumMismatch);
        assert_eq!(output, [1, 2]);
    }

    #[cfg(feature = "checksum")]
    #[test]
    fn verifies_compressed_checksum() {
        let mut input = Vec::new();
        input.extend_from_slice(&magic(21));
        input.push(1 << 1);
        input.push(1);
        input.push(4);
        let header_checksum = (xxhash_rust::xxh3::xxh3_64(&input) & 0xff) as u8;
        input.push(header_checksum);
        let chunk_start = input.len();
        input.push(1);
        input.push(1);
        input.push(3);
        input.extend_from_slice(&[7, 8, 9]);
        let checksum = (xxhash_rust::xxh3::xxh3_64(&input[chunk_start..]) & 0xffff_ffff) as u32;
        input.extend_from_slice(&checksum.to_le_bytes());
        input.push(0);
        let plan = parse_frame_plan(&input, Limits::default()).unwrap();
        let mut output = Vec::new();

        let written = decode_plan(&input, &plan, &mut output, Limits::default()).unwrap();

        assert_eq!(written, 3);
        assert_eq!(output, [7, 8, 9]);
    }

    #[cfg(feature = "checksum")]
    #[test]
    fn rejects_compressed_checksum_mismatch() {
        let mut input = Vec::new();
        input.extend_from_slice(&magic(21));
        input.push(1 << 1);
        input.push(1);
        input.push(4);
        let header_checksum = (xxhash_rust::xxh3::xxh3_64(&input) & 0xff) as u8;
        input.push(header_checksum);
        input.push(1);
        input.push(1);
        input.push(3);
        input.extend_from_slice(&[7, 8, 9]);
        input.extend_from_slice(&0u32.to_le_bytes());
        input.push(0);

        let err = parse_frame_plan(&input, Limits::default()).unwrap_err();

        assert_eq!(err.kind(), ErrorKind::ChecksumMismatch);
    }
}
