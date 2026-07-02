use alloc::{vec, vec::Vec};

use ozlrip_core::{Error, ErrorKind, FrameInfo, FrameValueType, Limits, Result};

use crate::standard;

const MAGIC_BASE: u32 = 0xd7b1_a5c0;
const MIN_FORMAT_VERSION: u32 = 8;
const MAX_FORMAT_VERSION: u32 = 26;
const CHUNK_VERSION_MIN: u32 = 21;
const COMMENT_VERSION_MIN: u32 = 22;
const MATERIALIZED_DICT_VERSION_MIN: u32 = 25;
const UNIQUE_ID_BYTES: usize = 32;
const MAX_HEADER_COMMENT_BYTES: u64 = 10_000;

pub(crate) fn inspect_frame(input: &[u8], limits: Limits) -> Result<FrameInfo> {
    Ok(parse_frame_plan(input, limits)?.info)
}

pub(crate) fn parse_frame_plan(input: &[u8], limits: Limits) -> Result<FramePlan> {
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

    let header_bytes = reader.offset();
    let chunk_scan = read_chunks(
        &mut reader,
        format_version,
        flags,
        dictionary_bundle_id.is_some(),
        limits,
    )?;
    if format_version >= CHUNK_VERSION_MIN && !reader.is_empty() {
        return Err(Error::at(ErrorKind::Malformed, reader.offset())
            .with_detail("trailing bytes after OpenZL frame EOF marker"));
    }

    let info = FrameInfo {
        format_version,
        frame_bytes: input.len(),
        header_bytes,
        decoded_bytes: output_sizes.decoded_bytes,
        chunks: chunk_scan.summary.chunks,
        inputs: output_header.outputs,
        output_types: output_header.output_types,
        output_sizes: output_sizes.sizes,
        output_elements: output_sizes.elements,
        transforms: chunk_scan.summary.transforms,
        stored_streams: chunk_scan.summary.stored_streams,
        regenerated_streams: chunk_scan.summary.regenerated_streams,
        has_decoded_checksum: flags.has_decoded_checksum(),
        has_encoded_checksum: flags.has_encoded_checksum(),
        has_comment: flags.has_comment(),
        dictionary_bundle_id,
    };
    let plan = FramePlan {
        info,
        chunks: chunk_scan.chunks,
    };
    validate_frame_plan(&plan)?;
    Ok(plan)
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

fn read_chunks(
    reader: &mut Reader<'_>,
    format_version: u32,
    flags: FrameFlags,
    has_bundle_id: bool,
    limits: Limits,
) -> Result<ChunkScan> {
    let mut summary = ChunkSummary::default();
    let mut chunks = Vec::new();
    if reader.is_empty() {
        return Ok(ChunkScan { summary, chunks });
    }

    loop {
        if format_version >= CHUNK_VERSION_MIN {
            if reader.peek_byte()? == 0 {
                let _ = reader.read_byte()?;
                return Ok(ChunkScan { summary, chunks });
            }
        } else if summary.chunks > 0 {
            return Ok(ChunkScan { summary, chunks });
        }

        let chunk_start = reader.offset();
        let mut chunk = read_chunk_header(reader, format_version, has_bundle_id, limits)?;
        summary.chunks = checked_add(summary.chunks, 1)?;
        check_limit(summary.chunks, limits.max_chunks, ErrorKind::LimitExceeded)?;
        summary.transforms = checked_add(summary.transforms, chunk.transforms())?;
        check_limit(
            summary.transforms,
            limits.max_nodes,
            ErrorKind::LimitExceeded,
        )?;
        summary.stored_streams = checked_add(summary.stored_streams, chunk.stored_streams())?;
        check_limit(
            summary.stored_streams,
            limits.max_streams,
            ErrorKind::LimitExceeded,
        )?;
        summary.regenerated_streams =
            checked_add(summary.regenerated_streams, chunk.regenerated_streams())?;
        check_limit(
            summary.regenerated_streams,
            limits.max_streams,
            ErrorKind::LimitExceeded,
        )?;
        let payload_start = reader.offset();
        chunk.set_payload_start(payload_start)?;
        let payload_bytes = checked_add(chunk.transform_header_bytes, chunk.stored_stream_bytes)?;
        check_limit(
            chunk.transform_header_bytes,
            limits.max_transform_header_bytes,
            ErrorKind::LimitExceeded,
        )?;
        check_limit(
            chunk.stored_stream_bytes,
            limits.max_stored_stream_bytes,
            ErrorKind::LimitExceeded,
        )?;
        let _ = reader.read_slice(payload_bytes)?;

        if flags.has_decoded_checksum() {
            chunk.decoded_checksum = Some(reader.read_u32_le()?);
        }
        if flags.has_encoded_checksum() {
            let checksum_offset = reader.offset();
            chunk.encoded_checksum = Some(reader.read_u32_le()?);
            #[cfg(not(feature = "checksum"))]
            let _ = (chunk_start, checksum_offset);
            #[cfg(feature = "checksum")]
            verify_compressed_checksum(
                reader.bytes,
                chunk_start,
                checksum_offset,
                chunk.encoded_checksum,
            )?;
        }
        chunks.try_reserve_exact(1).map_err(|_| {
            Error::new(ErrorKind::LimitExceeded).with_detail("chunk allocation failed")
        })?;
        chunks.push(chunk);
    }
}

fn validate_frame_plan(plan: &FramePlan) -> Result<()> {
    if plan.info.chunks != plan.chunks.len() {
        return Err(Error::new(ErrorKind::InvalidGraph).with_detail("chunk count mismatch"));
    }

    let mut transforms = 0usize;
    let mut stored_streams = 0usize;
    let mut regenerated_streams = 0usize;
    for chunk in &plan.chunks {
        validate_chunk_plan(chunk, plan.info.output_types.len())?;
        transforms = checked_add(transforms, chunk.transforms())?;
        stored_streams = checked_add(stored_streams, chunk.stored_streams())?;
        regenerated_streams = checked_add(regenerated_streams, chunk.regenerated_streams())?;
    }

    if transforms != plan.info.transforms
        || stored_streams != plan.info.stored_streams
        || regenerated_streams != plan.info.regenerated_streams
    {
        return Err(Error::new(ErrorKind::InvalidGraph).with_detail("chunk summary mismatch"));
    }

    Ok(())
}

fn validate_chunk_plan(chunk: &ChunkPlan, output_count: usize) -> Result<()> {
    let stream_bound = checked_add(chunk.regenerated_streams(), chunk.stored_streams())?;
    if output_count > stream_bound {
        return Err(Error::new(ErrorKind::InvalidGraph)
            .with_detail("chunk has fewer streams than final outputs"));
    }
    let first_final_stream = stream_bound.saturating_sub(output_count);
    let mut stream_cursor = 0usize;
    let mut header_end = 0usize;
    let mut regenerated = 0usize;
    let mut regen_targets = Vec::new();
    regen_targets.try_reserve_exact(stream_bound).map_err(|_| {
        Error::new(ErrorKind::LimitExceeded)
            .with_detail("regen target validation allocation failed")
    })?;
    regen_targets.resize(stream_bound, false);
    for node in &chunk.nodes {
        if node.transform_type == TransformType::Standard && node.transform_id >= 128 {
            return Err(Error::new(ErrorKind::Unsupported)
                .with_detail("standard transform ID is outside the OpenZL range"));
        }
        let shape = validate_known_standard_node_shape(node)?;
        if node.transform_header_start != header_end {
            return Err(Error::new(ErrorKind::InvalidGraph).with_detail("transform header gap"));
        }
        header_end = checked_add(node.transform_header_start, node.transform_header_size)?;
        let variable_inputs = usize::try_from(node.variable_outputs)
            .map_err(|_| Error::new(ErrorKind::LimitExceeded))?;
        if variable_inputs > 0 && !shape.allows_variable_inputs {
            return Err(Error::new(ErrorKind::InvalidGraph)
                .with_detail("node has unexpected variable inputs"));
        }
        let input_count = checked_add(shape.static_inputs, variable_inputs)?;
        let input_end = checked_add(stream_cursor, input_count)?;
        if input_end > first_final_stream {
            return Err(Error::new(ErrorKind::InvalidGraph)
                .with_detail("node input range reaches final output streams"));
        }
        validate_node_output_count(node, shape)?;
        if node.dict_index.is_some() && node.transform_type == TransformType::Custom {
            return Err(Error::new(ErrorKind::Unsupported)
                .with_detail("custom transform dictionaries are unsupported"));
        }
        for &distance in &node.regen_distances {
            let distance =
                usize::try_from(distance).map_err(|_| Error::new(ErrorKind::LimitExceeded))?;
            let target = checked_add(input_end, distance)?;
            if target >= stream_bound {
                return Err(Error::new(ErrorKind::InvalidGraph)
                    .with_detail("regen stream distance is out of bounds"));
            }
            if regen_targets[target] {
                return Err(Error::new(ErrorKind::InvalidGraph)
                    .with_detail("duplicate regen stream distance"));
            }
            regen_targets[target] = true;
            regenerated = checked_add(regenerated, 1)?;
        }
        stream_cursor = input_end;
    }
    if header_end != chunk.transform_header_bytes {
        return Err(
            Error::new(ErrorKind::InvalidGraph).with_detail("transform header size mismatch")
        );
    }
    if regenerated != chunk.regenerated_streams() {
        return Err(
            Error::new(ErrorKind::InvalidGraph).with_detail("regenerated stream count mismatch")
        );
    }
    if sum_usize(&chunk.stored_stream_sizes)? != chunk.stored_stream_bytes {
        return Err(Error::new(ErrorKind::InvalidGraph).with_detail("stored stream size mismatch"));
    }
    if chunk.stored_stream_ranges.len() != chunk.stored_stream_sizes.len() {
        return Err(
            Error::new(ErrorKind::InvalidGraph).with_detail("stored stream range count mismatch")
        );
    }
    let mut expected_start = checked_add(
        chunk.transform_header_range.start,
        chunk.transform_header_range.len,
    )?;
    for (range, &size) in chunk
        .stored_stream_ranges
        .iter()
        .zip(chunk.stored_stream_sizes.iter())
    {
        if range.start != expected_start || range.len != size {
            return Err(
                Error::new(ErrorKind::InvalidGraph).with_detail("stored stream range mismatch")
            );
        }
        expected_start = checked_add(range.start, range.len)?;
    }
    if stream_bound > 0
        && !regen_targets[first_final_stream..]
            .iter()
            .all(|&produced| produced)
    {
        let stored_final_outputs = regen_targets[first_final_stream..]
            .iter()
            .filter(|&&produced| !produced)
            .count();
        if stored_final_outputs > chunk.stored_streams() {
            return Err(Error::new(ErrorKind::InvalidGraph)
                .with_detail("final output stream is not produced"));
        }
    }
    Ok(())
}

fn validate_known_standard_node_shape(node: &NodePlan) -> Result<StandardNodeShape> {
    let Some(id) = node.standard_id() else {
        return Err(Error::new(ErrorKind::Unsupported)
            .with_detail("custom OpenZL transforms are not implemented"));
    };
    let shape = standard_node_shape(id).ok_or_else(|| {
        Error::new(ErrorKind::Unsupported)
            .with_detail("standard transform graph shape is unsupported")
    })?;
    Ok(shape)
}

fn validate_node_output_count(node: &NodePlan, shape: StandardNodeShape) -> Result<()> {
    if node.regen_distances.len() < shape.min_outputs {
        return Err(
            Error::new(ErrorKind::InvalidGraph).with_detail("node has too few output streams")
        );
    }
    if let Some(max_outputs) = shape.max_outputs
        && node.regen_distances.len() > max_outputs
    {
        return Err(
            Error::new(ErrorKind::InvalidGraph).with_detail("node has too many output streams")
        );
    }
    Ok(())
}

#[derive(Clone, Copy)]
struct StandardNodeShape {
    static_inputs: usize,
    allows_variable_inputs: bool,
    min_outputs: usize,
    max_outputs: Option<usize>,
}

const fn fixed_shape(static_inputs: usize, outputs: usize) -> StandardNodeShape {
    StandardNodeShape {
        static_inputs,
        allows_variable_inputs: false,
        min_outputs: outputs,
        max_outputs: Some(outputs),
    }
}

const fn standard_node_shape(id: u32) -> Option<StandardNodeShape> {
    match id {
        standard::DELTA_INT_ID
        | standard::ZIGZAG_ID
        | standard::CONVERT_SERIAL_TO_STRUCT_ID
        | standard::ZSTD_ID
        | standard::BITPACK_SERIAL_ID
        | standard::BITUNPACK_ID
        | standard::RANGE_PACK_ID
        | standard::CONSTANT_SERIAL_ID
        | standard::LZ4_ID => Some(fixed_shape(1, 1)),
        standard::FLATPACK_ID | standard::TRANSPOSE_SPLIT2_ID | standard::SPARSE_NUM_ID => {
            Some(fixed_shape(2, 1))
        }
        standard::TRANSPOSE_SPLIT4_ID => Some(fixed_shape(4, 1)),
        standard::TRANSPOSE_SPLIT8_ID => Some(fixed_shape(8, 1)),
        standard::SPLITN_ID => Some(StandardNodeShape {
            static_inputs: 0,
            allows_variable_inputs: true,
            min_outputs: 1,
            max_outputs: Some(1),
        }),
        standard::CONCAT_SERIAL_ID => Some(StandardNodeShape {
            static_inputs: 2,
            allows_variable_inputs: false,
            min_outputs: 1,
            max_outputs: None,
        }),
        _ => None,
    }
}

fn read_chunk_header(
    reader: &mut Reader<'_>,
    format_version: u32,
    has_bundle_id: bool,
    limits: Limits,
) -> Result<ChunkPlan> {
    let transforms = read_transform_count(reader, format_version)?;
    let stored_streams_u64 = read_count(reader, format_version)?;
    let stored_streams = usize::try_from(stored_streams_u64)
        .map_err(|_| Error::at(ErrorKind::LimitExceeded, reader.offset()))?;
    check_limit(
        transforms,
        runtime_node_limit(format_version),
        ErrorKind::Malformed,
    )?;
    check_limit(
        stored_streams,
        runtime_stream_limit(format_version),
        ErrorKind::Malformed,
    )?;
    check_limit(transforms, limits.max_nodes, ErrorKind::LimitExceeded)?;
    check_limit(stored_streams, limits.max_streams, ErrorKind::LimitExceeded)?;

    if (4..CHUNK_VERSION_MIN).contains(&format_version) {
        let _ = reader.read_byte()?;
    }

    let transform_types = read_transform_types(reader, transforms)?;
    let transform_ids = read_transform_ids(reader, &transform_types, format_version)?;
    let transform_header_sizes = read_transform_header_sizes(reader, transforms)?;
    let transform_header_bytes = sum_u32_as_usize(&transform_header_sizes)?;
    let variable_outputs = read_variable_outputs(reader, transforms)?;
    let regen_counts = read_regen_counts(reader, transforms, format_version)?;

    let dict_indexes = if format_version >= MATERIALIZED_DICT_VERSION_MIN && has_bundle_id {
        read_dict_indexes(reader, transforms)?
    } else {
        vec![None; transforms]
    };

    let regenerated_streams = sum_usize(&regen_counts)?;
    check_limit(
        regenerated_streams,
        runtime_stream_limit(format_version),
        ErrorKind::Malformed,
    )?;
    let distance_bits = bits_needed(checked_add(regenerated_streams, stored_streams)?);
    let regen_distances = read_bitpacked_u32(reader, regenerated_streams, distance_bits)?;

    let stored_stream_sizes = read_stored_stream_sizes(reader, stored_streams, limits)?;
    let stored_stream_bytes = sum_usize(&stored_stream_sizes)?;
    let nodes = build_node_plans(
        &transform_types,
        &transform_ids,
        &transform_header_sizes,
        &variable_outputs,
        &regen_counts,
        &dict_indexes,
        &regen_distances,
    )?;

    Ok(ChunkPlan {
        nodes,
        stored_stream_sizes,
        transform_header_bytes,
        stored_stream_bytes,
        transform_header_range: ByteRange::default(),
        stored_stream_ranges: Vec::new(),
        decoded_checksum: None,
        encoded_checksum: None,
    })
}

fn build_node_plans(
    transform_types: &[TransformType],
    transform_ids: &[u32],
    transform_header_sizes: &[u32],
    variable_outputs: &[u32],
    regen_counts: &[usize],
    dict_indexes: &[Option<u32>],
    regen_distances: &[u32],
) -> Result<Vec<NodePlan>> {
    let transforms = transform_types.len();
    if transform_ids.len() != transforms
        || transform_header_sizes.len() != transforms
        || variable_outputs.len() != transforms
        || regen_counts.len() != transforms
        || dict_indexes.len() != transforms
    {
        return Err(
            Error::new(ErrorKind::InvalidGraph).with_detail("node metadata length mismatch")
        );
    }

    let mut nodes = Vec::new();
    nodes.try_reserve_exact(transforms).map_err(|_| {
        Error::new(ErrorKind::LimitExceeded).with_detail("node plan allocation failed")
    })?;

    let mut header_start = 0usize;
    let mut distance_start = 0usize;
    for index in 0..transforms {
        let header_size = usize::try_from(transform_header_sizes[index])
            .map_err(|_| Error::new(ErrorKind::LimitExceeded))?;
        let distance_end = checked_add(distance_start, regen_counts[index])?;
        let distances = regen_distances
            .get(distance_start..distance_end)
            .ok_or_else(|| {
                Error::new(ErrorKind::InvalidGraph).with_detail("regen distance length mismatch")
            })?
            .to_vec();
        nodes.push(NodePlan {
            transform_type: transform_types[index],
            transform_id: transform_ids[index],
            transform_header_start: header_start,
            transform_header_size: header_size,
            variable_outputs: variable_outputs[index],
            regen_distances: distances,
            dict_index: dict_indexes[index],
        });
        header_start = checked_add(header_start, header_size)?;
        distance_start = distance_end;
    }

    if distance_start != regen_distances.len() {
        return Err(Error::new(ErrorKind::InvalidGraph).with_detail("unused regen distances"));
    }

    Ok(nodes)
}

fn read_transform_count(reader: &mut Reader<'_>, format_version: u32) -> Result<usize> {
    let raw = read_count(reader, format_version)?;
    let adjusted = if format_version >= CHUNK_VERSION_MIN {
        raw.checked_sub(1)
            .ok_or_else(|| Error::at(ErrorKind::Malformed, reader.offset()))?
    } else {
        raw
    };
    usize::try_from(adjusted).map_err(|_| Error::at(ErrorKind::LimitExceeded, reader.offset()))
}

fn read_count(reader: &mut Reader<'_>, format_version: u32) -> Result<u64> {
    if format_version < 9 {
        Ok(u64::from(reader.read_byte()?))
    } else {
        reader.read_var_u64()
    }
}

fn read_transform_types(reader: &mut Reader<'_>, transforms: usize) -> Result<Vec<TransformType>> {
    let flags = read_bitpacked_u32(reader, transforms, 1)?;
    let mut types = Vec::new();
    types.try_reserve_exact(transforms).map_err(|_| {
        Error::new(ErrorKind::LimitExceeded).with_detail("transform type allocation failed")
    })?;
    for flag in flags {
        types.push(match flag {
            0 => TransformType::Standard,
            1 => TransformType::Custom,
            _ => return Err(Error::new(ErrorKind::Malformed).with_detail("invalid transform type")),
        });
    }
    Ok(types)
}

fn read_transform_ids(
    reader: &mut Reader<'_>,
    transform_types: &[TransformType],
    format_version: u32,
) -> Result<Vec<u32>> {
    let standard_count = transform_types
        .iter()
        .filter(|&&kind| kind == TransformType::Standard)
        .count();
    let standard_bits = standard_transform_id_bits(format_version);
    let standard_ids = read_bitpacked_u32(reader, standard_count, standard_bits)?;
    let custom_count = transform_types.len() - standard_count;
    let mut custom_ids = Vec::new();
    custom_ids.try_reserve_exact(custom_count).map_err(|_| {
        Error::new(ErrorKind::LimitExceeded).with_detail("custom transform ID allocation failed")
    })?;
    for _ in 0..custom_count {
        let id = reader.read_var_u64()?;
        custom_ids
            .push(u32::try_from(id).map_err(|_| Error::at(ErrorKind::Malformed, reader.offset()))?);
    }

    let mut standard_index = 0usize;
    let custom_index = 0usize;
    let mut ids = Vec::new();
    ids.try_reserve_exact(transform_types.len()).map_err(|_| {
        Error::new(ErrorKind::LimitExceeded).with_detail("transform ID allocation failed")
    })?;
    for &kind in transform_types {
        match kind {
            TransformType::Standard => {
                let id = standard_ids[standard_index];
                if id >= 128 {
                    return Err(Error::new(ErrorKind::Unsupported)
                        .with_detail("standard transform ID is outside the OpenZL range"));
                }
                standard::validate_transform_id(id, format_version)?;
                ids.push(id);
                standard_index = checked_add(standard_index, 1)?;
            }
            TransformType::Custom => {
                let _ = custom_ids[custom_index];
                return Err(Error::new(ErrorKind::Unsupported)
                    .with_detail("custom OpenZL transforms are not implemented"));
            }
        }
    }
    Ok(ids)
}

fn read_transform_header_sizes(reader: &mut Reader<'_>, transforms: usize) -> Result<Vec<u32>> {
    let mut sizes = read_bitpacked_u32(reader, transforms, 1)?;
    for size in &mut sizes {
        if *size != 0 {
            let decoded = reader.read_var_u64()?;
            *size = u32::try_from(
                decoded
                    .checked_add(1)
                    .ok_or_else(|| Error::at(ErrorKind::IntegerOverflow, reader.offset()))?,
            )
            .map_err(|_| Error::at(ErrorKind::Malformed, reader.offset()))?;
        }
    }
    Ok(sizes)
}

fn read_variable_outputs(reader: &mut Reader<'_>, transforms: usize) -> Result<Vec<u32>> {
    let mut outputs = read_bitpacked_u32(reader, transforms, 1)?;
    for output in &mut outputs {
        if *output != 0 {
            let decoded = reader.read_var_u64()?;
            *output = u32::try_from(
                decoded
                    .checked_add(1)
                    .ok_or_else(|| Error::at(ErrorKind::IntegerOverflow, reader.offset()))?,
            )
            .map_err(|_| Error::at(ErrorKind::Malformed, reader.offset()))?;
        }
    }
    Ok(outputs)
}

fn read_regen_counts(
    reader: &mut Reader<'_>,
    transforms: usize,
    format_version: u32,
) -> Result<Vec<usize>> {
    if format_version < 16 {
        return Ok(vec![1; transforms]);
    }

    let mut counts = read_bitpacked_u32(reader, transforms, 1)?;
    let mut out = Vec::new();
    out.try_reserve_exact(transforms).map_err(|_| {
        Error::new(ErrorKind::LimitExceeded).with_detail("regen count allocation failed")
    })?;
    for count in &mut counts {
        if *count != 0 {
            let decoded = reader.read_var_u64()?;
            *count = u32::try_from(
                decoded
                    .checked_add(2)
                    .ok_or_else(|| Error::at(ErrorKind::IntegerOverflow, reader.offset()))?,
            )
            .map_err(|_| Error::at(ErrorKind::Malformed, reader.offset()))?;
        } else {
            *count = 1;
        }
        let count = usize::try_from(*count)
            .map_err(|_| Error::at(ErrorKind::LimitExceeded, reader.offset()))?;
        check_limit(
            count,
            runtime_node_input_limit(format_version),
            ErrorKind::Malformed,
        )?;
        out.push(count);
    }
    Ok(out)
}

fn read_dict_indexes(reader: &mut Reader<'_>, transforms: usize) -> Result<Vec<Option<u32>>> {
    let flags = read_bitpacked_u32(reader, transforms, 1)?;
    let non_zero = flags.iter().filter(|&&flag| flag != 0).count();
    let mut values = Vec::new();
    if non_zero > 0 {
        let bits = usize::from(reader.read_byte()?);
        if bits > 16 {
            return Err(Error::at(ErrorKind::Malformed, reader.offset())
                .with_detail("dict index bit width is too large"));
        }
        values = read_bitpacked_u32(reader, non_zero, bits)?;
    }

    let mut value_index = 0usize;
    let mut out = Vec::new();
    out.try_reserve_exact(transforms).map_err(|_| {
        Error::new(ErrorKind::LimitExceeded).with_detail("dict index allocation failed")
    })?;
    for flag in flags {
        if flag == 0 {
            out.push(None);
        } else {
            let value = values[value_index];
            if value > 0xffff {
                return Err(Error::new(ErrorKind::Malformed).with_detail("dict index is too large"));
            }
            out.push(Some(value));
            value_index = checked_add(value_index, 1)?;
        }
    }
    Ok(out)
}

fn read_stored_stream_sizes(
    reader: &mut Reader<'_>,
    streams: usize,
    limits: Limits,
) -> Result<Vec<usize>> {
    let mut sizes = Vec::new();
    sizes.try_reserve_exact(streams).map_err(|_| {
        Error::new(ErrorKind::LimitExceeded).with_detail("stored stream size allocation failed")
    })?;
    for _ in 0..streams {
        let size = reader.read_var_u64()?;
        let size = usize::try_from(size)
            .map_err(|_| Error::at(ErrorKind::LimitExceeded, reader.offset()))?;
        check_limit(size, limits.max_buffer_bytes, ErrorKind::LimitExceeded)?;
        sizes.push(size);
    }
    Ok(sizes)
}

fn read_bitpacked_u32(reader: &mut Reader<'_>, count: usize, bits: usize) -> Result<Vec<u32>> {
    if bits > 32 {
        return Err(Error::new(ErrorKind::Malformed).with_detail("bitpacked width is too large"));
    }
    let bytes = bitpacked_bytes(count, bits)?;
    let packed = reader.read_slice(bytes)?;
    let mut out = Vec::new();
    out.try_reserve_exact(count).map_err(|_| {
        Error::new(ErrorKind::LimitExceeded).with_detail("bitpacked value allocation failed")
    })?;
    for index in 0..count {
        out.push(read_packed_value(packed, index, bits)?);
    }
    Ok(out)
}

fn read_packed_value(bytes: &[u8], index: usize, bits: usize) -> Result<u32> {
    if bits == 0 {
        return Ok(0);
    }
    let bit_offset = checked_mul(index, bits)?;
    let mut value = 0u32;
    for bit in 0..bits {
        let absolute = checked_add(bit_offset, bit)?;
        let byte = *bytes
            .get(absolute / 8)
            .ok_or_else(|| Error::new(ErrorKind::Truncated))?;
        let bit_value = (byte >> (absolute % 8)) & 1;
        value |= u32::from(bit_value) << bit;
    }
    Ok(value)
}

fn bitpacked_bytes(count: usize, bits: usize) -> Result<usize> {
    checked_add(checked_mul(count, bits)?, 7).map(|bits| bits / 8)
}

fn bits_needed(max_value: usize) -> usize {
    if max_value <= 1 {
        0
    } else {
        usize::BITS as usize - (max_value - 1).leading_zeros() as usize
    }
}

fn standard_transform_id_bits(format_version: u32) -> usize {
    if format_version < 24 { 6 } else { 7 }
}

fn runtime_node_input_limit(format_version: u32) -> usize {
    if format_version <= 15 {
        1
    } else {
        runtime_input_limit(format_version)
    }
}

fn runtime_node_limit(format_version: u32) -> usize {
    if format_version < 9 {
        256
    } else if format_version < 20 {
        10_000
    } else {
        20_000
    }
}

fn runtime_stream_limit(format_version: u32) -> usize {
    if format_version < 9 {
        256
    } else if format_version < 16 {
        10_000
    } else {
        110_000
    }
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

#[cfg(feature = "checksum")]
fn verify_compressed_checksum(
    input: &[u8],
    start: usize,
    end: usize,
    expected: Option<u32>,
) -> Result<()> {
    let expected = expected.ok_or_else(|| {
        Error::new(ErrorKind::Malformed).with_detail("missing compressed checksum")
    })?;
    let bytes = input
        .get(start..end)
        .ok_or_else(|| Error::at(ErrorKind::Truncated, start))?;
    let actual = (xxhash_rust::xxh3::xxh3_64(bytes) & 0xffff_ffff) as u32;
    if actual != expected {
        return Err(Error::at(ErrorKind::ChecksumMismatch, end)
            .with_detail("OpenZL compressed checksum mismatch"));
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

fn sum_u32_as_usize(values: &[u32]) -> Result<usize> {
    let mut total = 0usize;
    for &value in values {
        let value = usize::try_from(value).map_err(|_| Error::new(ErrorKind::LimitExceeded))?;
        total = checked_add(total, value)?;
    }
    Ok(total)
}

fn sum_usize(values: &[usize]) -> Result<usize> {
    let mut total = 0usize;
    for &value in values {
        total = checked_add(total, value)?;
    }
    Ok(total)
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

#[derive(Debug)]
pub(crate) struct FramePlan {
    pub(crate) info: FrameInfo,
    pub(crate) chunks: Vec<ChunkPlan>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TransformType {
    Standard,
    Custom,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct NodePlan {
    transform_type: TransformType,
    transform_id: u32,
    transform_header_start: usize,
    transform_header_size: usize,
    variable_outputs: u32,
    regen_distances: Vec<u32>,
    dict_index: Option<u32>,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct ChunkSummary {
    chunks: usize,
    transforms: usize,
    stored_streams: usize,
    regenerated_streams: usize,
}

struct ChunkScan {
    summary: ChunkSummary,
    chunks: Vec<ChunkPlan>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ChunkPlan {
    nodes: Vec<NodePlan>,
    stored_stream_sizes: Vec<usize>,
    transform_header_bytes: usize,
    stored_stream_bytes: usize,
    transform_header_range: ByteRange,
    stored_stream_ranges: Vec<ByteRange>,
    pub(crate) decoded_checksum: Option<u32>,
    encoded_checksum: Option<u32>,
}

impl ChunkPlan {
    fn transforms(&self) -> usize {
        self.nodes.len()
    }

    pub(crate) fn has_nodes(&self) -> bool {
        !self.nodes.is_empty()
    }

    pub(crate) fn single_node(&self) -> Option<&NodePlan> {
        match self.nodes.as_slice() {
            [node] => Some(node),
            _ => None,
        }
    }

    pub(crate) fn stored_streams(&self) -> usize {
        self.stored_stream_sizes.len()
    }

    pub(crate) fn stored_stream_range(&self, index: usize) -> Option<ByteRange> {
        self.stored_stream_ranges.get(index).copied()
    }

    pub(crate) const fn transform_header_range(&self) -> ByteRange {
        self.transform_header_range
    }

    fn regenerated_streams(&self) -> usize {
        self.nodes
            .iter()
            .map(|node| node.regen_distances.len())
            .sum()
    }

    fn set_payload_start(&mut self, payload_start: usize) -> Result<()> {
        let transform_header_end = checked_add(payload_start, self.transform_header_bytes)?;
        self.transform_header_range = ByteRange {
            start: payload_start,
            len: self.transform_header_bytes,
        };

        let mut offset = transform_header_end;
        self.stored_stream_ranges.clear();
        self.stored_stream_ranges
            .try_reserve_exact(self.stored_stream_sizes.len())
            .map_err(|_| {
                Error::new(ErrorKind::LimitExceeded)
                    .with_detail("stored stream range allocation failed")
            })?;
        for &size in &self.stored_stream_sizes {
            self.stored_stream_ranges.push(ByteRange {
                start: offset,
                len: size,
            });
            offset = checked_add(offset, size)?;
        }
        Ok(())
    }
}

impl NodePlan {
    pub(crate) const fn standard_id(&self) -> Option<u32> {
        match self.transform_type {
            TransformType::Standard => Some(self.transform_id),
            TransformType::Custom => None,
        }
    }

    pub(crate) const fn variable_outputs(&self) -> u32 {
        self.variable_outputs
    }

    pub(crate) fn regen_distances(&self) -> &[u32] {
        &self.regen_distances
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct ByteRange {
    start: usize,
    len: usize,
}

impl ByteRange {
    pub(crate) const fn len(self) -> usize {
        self.len
    }

    pub(crate) fn as_slice(self, input: &[u8]) -> Result<&[u8]> {
        let end = checked_add(self.start, self.len)?;
        input
            .get(self.start..end)
            .ok_or_else(|| Error::at(ErrorKind::Truncated, self.start))
    }
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

    const fn is_empty(&self) -> bool {
        self.offset >= self.bytes.len()
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
            if index == 9 && payload > 1 {
                return Err(Error::at(ErrorKind::IntegerOverflow, start)
                    .with_detail("u64 varint payload overflows"));
            }
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

    fn push_bitpacked_u32(out: &mut Vec<u8>, values: &[u32], bits: usize) {
        let len = (values.len() * bits).div_ceil(8);
        let start = out.len();
        out.resize(start + len, 0);
        for (index, &value) in values.iter().enumerate() {
            for bit in 0..bits {
                if ((value >> bit) & 1) != 0 {
                    let absolute = index * bits + bit;
                    out[start + absolute / 8] |= 1 << (absolute % 8);
                }
            }
        }
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
    fn rejects_overflowing_u64_varint() {
        let mut input = Vec::new();
        input.extend_from_slice(&magic(21));
        input.push(0);
        input.push(1);
        input.extend_from_slice(&[0xff; 9]);
        input.push(0x02);

        let err = inspect_frame(&input, Limits::default()).unwrap_err();

        assert_eq!(err.kind(), ErrorKind::IntegerOverflow);
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
    fn parses_v21_typed_output_descriptors() {
        let mut input = Vec::new();
        input.extend_from_slice(&magic(21));
        input.push(0);
        input.push(0b1000_0010);
        input.push(4);
        input.push(5);

        let info = inspect_frame(&input, Limits::default()).unwrap();

        assert_eq!(
            info.output_types,
            [FrameValueType::Serial, FrameValueType::Numeric]
        );
        assert_eq!(info.output_sizes, [Some(3), Some(4)]);
        assert_eq!(info.output_elements, [Some(3), None]);
        assert_eq!(info.decoded_bytes, Some(7));
    }

    #[test]
    fn enforces_output_buffer_limit() {
        let mut input = Vec::new();
        input.extend_from_slice(&magic(21));
        input.push(0);
        input.push(1);
        input.push(4);
        let limits = Limits {
            max_buffer_bytes: 2,
            ..Limits::default()
        };

        let err = inspect_frame(&input, limits).unwrap_err();

        assert_eq!(err.kind(), ErrorKind::LimitExceeded);
    }

    #[test]
    fn parses_v21_eof_marker() {
        let mut input = Vec::new();
        input.extend_from_slice(&magic(21));
        input.push(0);
        input.push(1);
        input.push(4);
        input.push(0);

        let info = inspect_frame(&input, Limits::default()).unwrap();

        assert_eq!(info.header_bytes, 7);
        assert_eq!(info.chunks, 0);
    }

    #[test]
    fn rejects_trailing_bytes_after_v21_eof_marker() {
        let mut input = Vec::new();
        input.extend_from_slice(&magic(21));
        input.push(0);
        input.push(1);
        input.push(4);
        input.push(0);
        input.push(99);

        let err = inspect_frame(&input, Limits::default()).unwrap_err();

        assert_eq!(err.kind(), ErrorKind::Malformed);
        assert_eq!(err.offset(), Some(8));
    }

    #[test]
    fn rejects_v21_empty_chunk_without_final_stream() {
        let mut input = Vec::new();
        input.extend_from_slice(&magic(21));
        input.push(0);
        input.push(1);
        input.push(4);
        input.push(1);
        input.push(0);
        input.push(0);

        let err = inspect_frame(&input, Limits::default()).unwrap_err();

        assert_eq!(err.kind(), ErrorKind::InvalidGraph);
    }

    #[test]
    fn parses_v21_standard_transform_chunk() {
        let mut input = Vec::new();
        input.extend_from_slice(&magic(21));
        input.push(0);
        input.push(1);
        input.push(4);
        input.push(2);
        input.push(1);
        input.push(0);
        input.push(22);
        input.push(0);
        input.push(0);
        input.push(0);
        input.push(0);
        input.push(3);
        input.extend_from_slice(&[1, 2, 3]);
        input.push(0);

        let info = inspect_frame(&input, Limits::default()).unwrap();

        assert_eq!(info.chunks, 1);
        assert_eq!(info.transforms, 1);
        assert_eq!(info.stored_streams, 1);
        assert_eq!(info.regenerated_streams, 1);
    }

    #[test]
    fn rejects_reserved_standard_transform_id() {
        let mut input = Vec::new();
        input.extend_from_slice(&magic(21));
        input.push(0);
        input.push(1);
        input.push(4);
        input.push(2);
        input.push(1);
        input.push(0);
        input.push(0);
        input.push(0);
        input.push(0);
        input.push(0);
        input.push(0);
        input.push(3);
        input.extend_from_slice(&[1, 2, 3]);
        input.push(0);

        let err = inspect_frame(&input, Limits::default()).unwrap_err();

        assert_eq!(err.kind(), ErrorKind::Unsupported);
    }

    #[test]
    fn rejects_custom_transform_id() {
        let mut input = Vec::new();
        input.extend_from_slice(&magic(21));
        input.push(0);
        input.push(1);
        input.push(4);
        input.push(2);
        input.push(1);
        input.push(1);
        input.push(1);

        let err = inspect_frame(&input, Limits::default()).unwrap_err();

        assert_eq!(err.kind(), ErrorKind::Unsupported);
    }

    #[test]
    fn enforces_standard_transform_id_min_version() {
        let mut input = Vec::new();
        input.extend_from_slice(&magic(25));
        input.push(0);
        input.push(1);
        input.push(4);
        input.push(2);
        input.push(2);
        input.push(0);
        input.push(66);
        input.push(0);
        input.push(0);
        input.push(0);
        input.push(0);
        input.push(1);
        input.push(2);
        input.extend_from_slice(&[1, 2, 3]);
        input.push(0);

        let err = inspect_frame(&input, Limits::default()).unwrap_err();

        assert_eq!(err.kind(), ErrorKind::Unsupported);

        input[..4].copy_from_slice(&magic(26));
        let info = inspect_frame(&input, Limits::default()).unwrap();
        assert_eq!(info.transforms, 1);
    }

    #[test]
    fn rejects_node_input_count_out_of_bounds() {
        let mut input = Vec::new();
        input.extend_from_slice(&magic(21));
        input.push(0);
        input.push(1);
        input.push(4);
        input.push(2);
        input.push(1);
        input.push(0);
        input.push(22);
        input.push(0);
        input.push(1);
        input.push(2);
        input.push(0);
        input.push(0);
        input.push(3);
        input.extend_from_slice(&[1, 2, 3]);
        input.push(0);

        let err = inspect_frame(&input, Limits::default()).unwrap_err();

        assert_eq!(err.kind(), ErrorKind::InvalidGraph);
    }

    #[test]
    fn rejects_fixed_codec_variable_inputs() {
        let mut input = Vec::new();
        input.extend_from_slice(&magic(24));
        input.push(0);
        input.push(1);
        input.push(4);
        input.push(2);
        input.push(1);
        input.push(0);
        input.push(62);
        input.push(0);
        input.push(1);
        input.push(0);
        input.push(0);
        input.push(0);
        input.push(0);
        input.push(0);

        let err = inspect_frame(&input, Limits::default()).unwrap_err();

        assert_eq!(err.kind(), ErrorKind::InvalidGraph);
    }

    #[test]
    fn rejects_duplicate_regen_stream_distance() {
        let mut input = Vec::new();
        input.extend_from_slice(&magic(21));
        input.push(0);
        input.push(1);
        input.push(4);
        input.push(2);
        input.push(2);
        push_bitpacked_u32(&mut input, &[0], 1);
        push_bitpacked_u32(&mut input, &[55], 6);
        push_bitpacked_u32(&mut input, &[0], 1);
        push_bitpacked_u32(&mut input, &[0], 1);
        push_bitpacked_u32(&mut input, &[1], 1);
        input.push(0);
        push_bitpacked_u32(&mut input, &[0, 0], 2);
        input.push(1);
        input.push(2);
        input.extend_from_slice(&[1, 2, 3]);
        input.push(0);

        let err = inspect_frame(&input, Limits::default()).unwrap_err();

        assert_eq!(err.kind(), ErrorKind::InvalidGraph);
    }

    #[test]
    fn rejects_node_inputs_reaching_final_streams() {
        let mut input = Vec::new();
        input.extend_from_slice(&magic(21));
        input.push(0);
        input.push(1);
        input.push(4);
        input.push(2);
        input.push(1);
        input.push(0);
        input.push(29);
        input.push(0);
        input.push(0);
        input.push(0);
        input.push(0);
        input.push(3);
        input.extend_from_slice(&[1, 2, 3]);
        input.push(0);

        let err = inspect_frame(&input, Limits::default()).unwrap_err();

        assert_eq!(err.kind(), ErrorKind::InvalidGraph);
    }

    #[test]
    fn rejects_duplicate_regen_stream_distance_across_nodes() {
        let mut input = Vec::new();
        input.extend_from_slice(&magic(21));
        input.push(0);
        input.push(1);
        input.push(4);
        input.push(3);
        input.push(1);
        push_bitpacked_u32(&mut input, &[0, 0], 1);
        push_bitpacked_u32(&mut input, &[22, 22], 6);
        push_bitpacked_u32(&mut input, &[0, 0], 1);
        push_bitpacked_u32(&mut input, &[0, 0], 1);
        push_bitpacked_u32(&mut input, &[0, 0], 1);
        push_bitpacked_u32(&mut input, &[1, 0], 2);
        input.push(3);
        input.extend_from_slice(&[1, 2, 3]);
        input.push(0);

        let err = inspect_frame(&input, Limits::default()).unwrap_err();

        assert_eq!(err.kind(), ErrorKind::InvalidGraph);
    }

    #[test]
    fn enforces_transform_header_byte_limit() {
        let mut input = Vec::new();
        input.extend_from_slice(&magic(21));
        input.push(0);
        input.push(1);
        input.push(4);
        input.push(2);
        input.push(1);
        input.push(0);
        input.push(22);
        input.push(1);
        input.push(0);
        input.push(0);
        input.push(0);
        input.push(0);
        input.push(3);
        input.push(99);
        input.extend_from_slice(&[1, 2, 3]);
        input.push(0);
        let limits = Limits {
            max_transform_header_bytes: 0,
            ..Limits::default()
        };

        let err = inspect_frame(&input, limits).unwrap_err();

        assert_eq!(err.kind(), ErrorKind::LimitExceeded);
    }

    #[test]
    fn enforces_stored_stream_buffer_limit() {
        let mut input = Vec::new();
        input.extend_from_slice(&magic(21));
        input.push(0);
        input.push(1);
        input.push(4);
        input.push(1);
        input.push(1);
        input.push(3);
        input.extend_from_slice(&[1, 2, 3]);
        input.push(0);
        let limits = Limits {
            max_buffer_bytes: 2,
            ..Limits::default()
        };

        let err = inspect_frame(&input, limits).unwrap_err();

        assert_eq!(err.kind(), ErrorKind::LimitExceeded);
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
    fn parses_v22_comment() {
        let mut input = Vec::new();
        input.extend_from_slice(&magic(22));
        input.push(1 << 2);
        input.push(1);
        input.push(4);
        input.push(3);
        input.extend_from_slice(b"abc");

        let info = inspect_frame(&input, Limits::default()).unwrap();

        assert!(info.has_comment);
        assert_eq!(info.header_bytes, input.len());
    }

    #[test]
    fn rejects_zero_length_comment() {
        let mut input = Vec::new();
        input.extend_from_slice(&magic(22));
        input.push(1 << 2);
        input.push(1);
        input.push(4);
        input.push(0);

        let err = inspect_frame(&input, Limits::default()).unwrap_err();

        assert_eq!(err.kind(), ErrorKind::Malformed);
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
    fn rejects_all_zero_bundle_id() {
        let mut input = Vec::new();
        input.extend_from_slice(&magic(25));
        input.push(1 << 3);
        input.push(2);
        input.extend_from_slice(&[0, 0]);

        let err = inspect_frame(&input, Limits::default()).unwrap_err();

        assert_eq!(err.kind(), ErrorKind::Malformed);
    }

    #[test]
    fn rejects_oversized_bundle_id() {
        let mut input = Vec::new();
        input.extend_from_slice(&magic(25));
        input.push(1 << 3);
        input.push(33);

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
