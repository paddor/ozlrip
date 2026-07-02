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
    if node.standard_id() == Some(standard::CONCAT_SERIAL_ID) {
        return decode_concat_serial_chunk(input, chunk, node, limits).map(DecodedChunk::Owned);
    }
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
        Some(standard::ZSTD_ID) => {
            decode_zstd_chunk(stored, header, limits).map(DecodedChunk::Owned)
        }
        _ => Err(Error::new(ErrorKind::Unsupported)
            .with_detail("transform graph execution is not implemented yet")),
    }
}

fn decode_concat_serial_chunk(
    input: &[u8],
    chunk: &crate::parse::ChunkPlan,
    node: &crate::parse::NodePlan,
    limits: Limits,
) -> Result<Vec<u8>> {
    if chunk.transform_header_range().len() != 0 {
        return Err(Error::new(ErrorKind::Unsupported)
            .with_detail("concat_serial transform headers are unsupported"));
    }
    if node.regen_distances() != [0] {
        return Err(Error::new(ErrorKind::Unsupported)
            .with_detail("only single-output concat_serial chunks are implemented"));
    }
    if node.variable_outputs() != 0 {
        return Err(Error::new(ErrorKind::Unsupported)
            .with_detail("variable concat_serial outputs are unsupported"));
    }
    if chunk.stored_streams() != 2 {
        return Err(Error::new(ErrorKind::InvalidGraph)
            .with_detail("concat_serial input count does not match stored streams"));
    }

    let sizes_range = chunk
        .stored_stream_range(0)
        .ok_or_else(|| Error::new(ErrorKind::InvalidGraph).with_detail("missing concat sizes"))?;
    let concatenated_range = chunk
        .stored_stream_range(1)
        .ok_or_else(|| Error::new(ErrorKind::InvalidGraph).with_detail("missing concat input"))?;
    let sizes = sizes_range.as_slice(input)?;
    if sizes.len() != 4 {
        return Err(
            Error::new(ErrorKind::Malformed).with_detail("concat_serial size table is malformed")
        );
    }
    let decoded_size =
        usize::try_from(u32::from_le_bytes(sizes.try_into().map_err(|_| {
            Error::new(ErrorKind::Malformed).with_detail("invalid concat size")
        })?))
        .map_err(|_| {
            Error::new(ErrorKind::LimitExceeded).with_detail("concat size is too large")
        })?;
    if decoded_size != concatenated_range.len() {
        return Err(
            Error::new(ErrorKind::Malformed).with_detail("concat_serial size does not match input")
        );
    }
    if decoded_size > limits.max_decoded_bytes || decoded_size > limits.max_buffer_bytes {
        return Err(
            Error::new(ErrorKind::LimitExceeded).with_detail("decoded output limit exceeded")
        );
    }

    let mut output = Vec::new();
    output.try_reserve_exact(decoded_size).map_err(|_| {
        Error::new(ErrorKind::LimitExceeded).with_detail("concat allocation failed")
    })?;
    output.extend_from_slice(concatenated_range.as_slice(input)?);
    Ok(output)
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

#[cfg(feature = "zstd")]
fn decode_zstd_chunk(stored: &[u8], header: &[u8], limits: Limits) -> Result<Vec<u8>> {
    if !header.is_empty() {
        return Err(Error::new(ErrorKind::Unsupported)
            .with_detail("zstd transform headers are unsupported"));
    }
    let mut offset = 0usize;
    let element_width = read_var_u64(stored, &mut offset)?;
    if element_width == 0 || element_width != 1 {
        return Err(Error::new(ErrorKind::Unsupported)
            .with_detail("only serial byte zstd output is implemented"));
    }
    let magicless = stored
        .get(offset..)
        .ok_or_else(|| Error::at(ErrorKind::Truncated, offset))?;
    let mut frame = Vec::new();
    frame
        .try_reserve_exact(4usize.checked_add(magicless.len()).ok_or_else(|| {
            Error::new(ErrorKind::IntegerOverflow).with_detail("zstd frame size overflowed")
        })?)
        .map_err(|_| {
            Error::new(ErrorKind::LimitExceeded).with_detail("zstd frame allocation failed")
        })?;
    frame.extend_from_slice(&0xfd2f_b528u32.to_le_bytes());
    frame.extend_from_slice(magicless);
    let output = zrip::decompress_with_limit(&frame, limits.max_decoded_bytes).map_err(|err| {
        if err == zrip::DecompressError::OutputTooSmall {
            Error::new(ErrorKind::LimitExceeded).with_detail("decoded output limit exceeded")
        } else {
            Error::new(ErrorKind::Malformed).with_detail("OpenZL zstd frame failed")
        }
    })?;
    if output.len() > limits.max_buffer_bytes {
        return Err(
            Error::new(ErrorKind::LimitExceeded).with_detail("decoded output limit exceeded")
        );
    }
    Ok(output)
}

#[cfg(not(feature = "zstd"))]
fn decode_zstd_chunk(_stored: &[u8], _header: &[u8], _limits: Limits) -> Result<Vec<u8>> {
    Err(Error::new(ErrorKind::Unsupported).with_detail("zstd support is disabled"))
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

#[cfg(any(feature = "lz4", feature = "zstd"))]
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

    fn push_var_u64(out: &mut Vec<u8>, mut value: u64) {
        while value >= 0x80 {
            out.push(u8::try_from(value & 0x7f).unwrap() | 0x80);
            value >>= 7;
        }
        out.push(u8::try_from(value).unwrap());
    }

    fn lz4_serial_frame(stored: &[u8], decoded_len: usize) -> Vec<u8> {
        let mut transform_header = Vec::new();
        push_var_u64(&mut transform_header, u64::try_from(decoded_len).unwrap());
        let mut input = Vec::new();
        input.extend_from_slice(&magic(23));
        input.push(0);
        input.push(1);
        push_var_u64(&mut input, u64::try_from(decoded_len + 1).unwrap());
        input.push(2);
        input.push(1);
        input.push(0);
        input.push(62);
        input.push(1);
        push_var_u64(
            &mut input,
            u64::try_from(transform_header.len() - 1).unwrap(),
        );
        input.push(0);
        input.push(0);
        input.push(0);
        push_var_u64(&mut input, u64::try_from(stored.len()).unwrap());
        input.extend_from_slice(&transform_header);
        input.extend_from_slice(stored);
        input.push(0);
        input
    }

    fn standard_transform_serial_frame(
        version: u32,
        transform_id: u8,
        stored: &[u8],
        decoded_len: usize,
        transform_header: &[u8],
    ) -> Vec<u8> {
        let mut input = Vec::new();
        input.extend_from_slice(&magic(version));
        input.push(0);
        input.push(1);
        push_var_u64(&mut input, u64::try_from(decoded_len + 1).unwrap());
        input.push(2);
        input.push(1);
        input.push(0);
        input.push(transform_id);
        if transform_header.is_empty() {
            input.push(0);
        } else {
            input.push(1);
            push_var_u64(
                &mut input,
                u64::try_from(transform_header.len() - 1).unwrap(),
            );
        }
        input.push(0);
        input.push(0);
        input.push(0);
        push_var_u64(&mut input, u64::try_from(stored.len()).unwrap());
        input.extend_from_slice(transform_header);
        input.extend_from_slice(stored);
        input.push(0);
        input
    }

    fn concat_serial_frame(payload: &[u8]) -> Vec<u8> {
        let size_stream = u32::try_from(payload.len()).unwrap().to_le_bytes();
        let mut input = Vec::new();
        input.extend_from_slice(&magic(21));
        input.push(0);
        input.push(1);
        push_var_u64(&mut input, u64::try_from(payload.len() + 1).unwrap());
        input.push(2);
        input.push(2);
        input.push(0);
        input.push(55);
        input.push(0);
        input.push(0);
        input.push(0);
        input.push(0);
        input.push(4);
        push_var_u64(&mut input, u64::try_from(payload.len()).unwrap());
        input.extend_from_slice(&size_stream);
        input.extend_from_slice(payload);
        input.push(0);
        input
    }

    fn zstd_serial_frame(stored: &[u8], decoded_len: usize) -> Vec<u8> {
        standard_transform_serial_frame(21, 22, stored, decoded_len, &[])
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

    #[test]
    fn decodes_v21_concat_serial_chunk() {
        let input = concat_serial_frame(b"openzl concat");
        let plan = parse_frame_plan(&input, Limits::default()).unwrap();
        let mut output = Vec::new();

        let written = decode_plan(&input, &plan, &mut output, Limits::default()).unwrap();

        assert_eq!(written, 13);
        assert_eq!(output, b"openzl concat");
    }

    #[test]
    fn rejects_concat_serial_output_limit_without_mutating_destination() {
        let input = concat_serial_frame(b"openzl concat");
        let plan = parse_frame_plan(&input, Limits::default()).unwrap();
        let mut output = vec![1, 2];
        let limits = Limits {
            max_decoded_bytes: 8,
            max_buffer_bytes: 8,
            ..Limits::default()
        };

        let err = decode_plan(&input, &plan, &mut output, limits).unwrap_err();

        assert_eq!(err.kind(), ErrorKind::LimitExceeded);
        assert_eq!(output, [1, 2]);
    }

    #[cfg(feature = "lz4")]
    #[test]
    fn decodes_v23_lz4_serial_chunk() {
        let expected = b"lz4-backed OpenZL serial chunk";
        let compressed = lz4rip::block::compress(expected);
        let input = lz4_serial_frame(&compressed, expected.len());
        let plan = parse_frame_plan(&input, Limits::default()).unwrap();
        let mut output = Vec::new();

        let written = decode_plan(&input, &plan, &mut output, Limits::default()).unwrap();

        assert_eq!(written, expected.len());
        assert_eq!(output, expected);
    }

    #[cfg(feature = "zstd")]
    #[test]
    fn decodes_v21_zstd_serial_chunk() {
        let expected = b"zstd-backed OpenZL serial chunk";
        let compressed = zrip::compress(expected, 1).unwrap();
        let mut stored = Vec::new();
        push_var_u64(&mut stored, 1);
        stored.extend_from_slice(&compressed[4..]);
        let input = zstd_serial_frame(&stored, expected.len());
        let plan = parse_frame_plan(&input, Limits::default()).unwrap();
        let mut output = Vec::new();

        let written = decode_plan(&input, &plan, &mut output, Limits::default()).unwrap();

        assert_eq!(written, expected.len());
        assert_eq!(output, expected);
    }

    #[cfg(feature = "zstd")]
    #[test]
    fn rejects_malformed_zstd_chunk_without_mutating_destination() {
        let mut stored = Vec::new();
        push_var_u64(&mut stored, 1);
        stored.extend_from_slice(&[0]);
        let input = zstd_serial_frame(&stored, 8);
        let plan = parse_frame_plan(&input, Limits::default()).unwrap();
        let mut output = vec![1, 2];

        let err = decode_plan(&input, &plan, &mut output, Limits::default()).unwrap_err();

        assert_eq!(err.kind(), ErrorKind::Malformed);
        assert_eq!(output, [1, 2]);
    }

    #[cfg(feature = "zstd")]
    #[test]
    fn rejects_zstd_non_byte_output_width_without_mutating_destination() {
        let expected = b"zstd-backed OpenZL serial chunk";
        let compressed = zrip::compress(expected, 1).unwrap();
        let mut stored = Vec::new();
        push_var_u64(&mut stored, 2);
        stored.extend_from_slice(&compressed[4..]);
        let input = zstd_serial_frame(&stored, expected.len());
        let plan = parse_frame_plan(&input, Limits::default()).unwrap();
        let mut output = vec![1, 2];

        let err = decode_plan(&input, &plan, &mut output, Limits::default()).unwrap_err();

        assert_eq!(err.kind(), ErrorKind::Unsupported);
        assert_eq!(output, [1, 2]);
    }

    #[cfg(feature = "zstd")]
    #[test]
    fn rejects_zstd_transform_header_without_mutating_destination() {
        let expected = b"zstd-backed OpenZL serial chunk";
        let compressed = zrip::compress(expected, 1).unwrap();
        let mut stored = Vec::new();
        push_var_u64(&mut stored, 1);
        stored.extend_from_slice(&compressed[4..]);
        let input = standard_transform_serial_frame(21, 22, &stored, expected.len(), &[0]);
        let plan = parse_frame_plan(&input, Limits::default()).unwrap();
        let mut output = vec![1, 2];

        let err = decode_plan(&input, &plan, &mut output, Limits::default()).unwrap_err();

        assert_eq!(err.kind(), ErrorKind::Unsupported);
        assert_eq!(output, [1, 2]);
    }

    #[cfg(feature = "zstd")]
    #[test]
    fn enforces_zstd_output_limit_without_mutating_destination() {
        let expected = b"zstd output larger than configured limits";
        let compressed = zrip::compress(expected, 1).unwrap();
        let mut stored = Vec::new();
        push_var_u64(&mut stored, 1);
        stored.extend_from_slice(&compressed[4..]);
        let input = zstd_serial_frame(&stored, expected.len());
        let plan = parse_frame_plan(&input, Limits::default()).unwrap();
        let mut output = vec![1, 2];
        let limits = Limits {
            max_decoded_bytes: 8,
            max_buffer_bytes: 8,
            ..Limits::default()
        };

        let err = decode_plan(&input, &plan, &mut output, limits).unwrap_err();

        assert_eq!(err.kind(), ErrorKind::LimitExceeded);
        assert_eq!(output, [1, 2]);
    }

    #[cfg(not(feature = "zstd"))]
    #[test]
    fn rejects_zstd_chunk_when_feature_is_disabled() {
        let input = zstd_serial_frame(&[1, 0], 8);
        let plan = parse_frame_plan(&input, Limits::default()).unwrap();
        let mut output = vec![1, 2];

        let err = decode_plan(&input, &plan, &mut output, Limits::default()).unwrap_err();

        assert_eq!(err.kind(), ErrorKind::Unsupported);
        assert_eq!(output, [1, 2]);
    }

    #[cfg(feature = "lz4")]
    #[test]
    fn rejects_malformed_lz4_chunk_without_mutating_destination() {
        let input = lz4_serial_frame(&[0], 8);
        let plan = parse_frame_plan(&input, Limits::default()).unwrap();
        let mut output = vec![1, 2];

        let err = decode_plan(&input, &plan, &mut output, Limits::default()).unwrap_err();

        assert_eq!(err.kind(), ErrorKind::Malformed);
        assert_eq!(output, [1, 2]);
    }

    #[cfg(feature = "lz4")]
    #[test]
    fn enforces_lz4_header_output_limit_without_mutating_destination() {
        let input = lz4_serial_frame(&[0], 4096);
        let plan = parse_frame_plan(&input, Limits::default()).unwrap();
        let mut output = vec![1, 2];
        let limits = Limits {
            max_decoded_bytes: 1024,
            max_buffer_bytes: 1024,
            ..Limits::default()
        };

        let err = decode_plan(&input, &plan, &mut output, limits).unwrap_err();

        assert_eq!(err.kind(), ErrorKind::LimitExceeded);
        assert_eq!(output, [1, 2]);
    }

    #[cfg(not(feature = "lz4"))]
    #[test]
    fn rejects_lz4_chunk_when_feature_is_disabled() {
        let input = lz4_serial_frame(&[0], 8);
        let plan = parse_frame_plan(&input, Limits::default()).unwrap();
        let mut output = vec![1, 2];

        let err = decode_plan(&input, &plan, &mut output, Limits::default()).unwrap_err();

        assert_eq!(err.kind(), ErrorKind::Unsupported);
        assert_eq!(output, [1, 2]);
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
