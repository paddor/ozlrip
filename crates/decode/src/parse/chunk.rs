use alloc::{vec, vec::Vec};

use crate::standard;
use ozlrip_core::{Error, ErrorKind, Limits, Result};
use smallvec::{SmallVec, smallvec};

use super::header::{FrameFlags, runtime_input_limit};
use super::reader::{
    Reader, bits_needed, check_limit, checked_add, read_bitpacked_single_u32, read_bitpacked_u32,
    read_bitpacked_u32_inline, sum_u32_as_usize, sum_usize,
};
use super::{
    ByteRange, ByteRanges, CHUNK_VERSION_MIN, ChunkPlan, ChunkPlans, MATERIALIZED_DICT_VERSION_MIN,
    MAX_DICTS_PER_BUNDLE, NodePlan, NodePlans, RegenDistances, StoredStreamSizes, TransformType,
};

/// Reads every chunk. Before v21 the checksum flags come from the single
/// chunk's header instead of `flags`; the returned scan holds the flags that
/// applied.
pub(super) fn read_chunks(
    reader: &mut Reader<'_>,
    format_version: u32,
    mut flags: FrameFlags,
    has_bundle_id: bool,
    limits: Limits,
) -> Result<ChunkScan> {
    let mut summary = ChunkSummary::default();
    let mut chunks = ChunkPlans::new();
    loop {
        if format_version >= CHUNK_VERSION_MIN {
            if reader.peek_byte()? == 0 {
                let _ = reader.read_byte()?;
                return Ok(ChunkScan {
                    summary,
                    chunks,
                    flags,
                });
            }
        } else if summary.chunks > 0 {
            return Ok(ChunkScan {
                summary,
                chunks,
                flags,
            });
        }

        let chunk_start = reader.offset();
        let mut chunk =
            read_chunk_header(reader, format_version, &mut flags, has_bundle_id, limits)?;
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
            // Before v21 the compressed checksum covers the whole frame.
            let checksum_start = if format_version >= CHUNK_VERSION_MIN {
                chunk_start
            } else {
                0
            };
            #[cfg(not(feature = "checksum"))]
            let _ = (checksum_start, checksum_offset);
            #[cfg(feature = "checksum")]
            verify_compressed_checksum(
                reader.bytes,
                checksum_start,
                checksum_offset,
                chunk.encoded_checksum,
            )?;
        }
        chunks.push(chunk);
    }
}

pub(super) fn read_chunk_header(
    reader: &mut Reader<'_>,
    format_version: u32,
    flags: &mut FrameFlags,
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
        *flags = FrameFlags::from_byte(reader.read_byte()?, format_version);
    }

    if transforms == 1 {
        return read_single_transform_chunk_header(
            reader,
            stored_streams,
            format_version,
            has_bundle_id,
            limits,
        );
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
        smallvec![None; transforms]
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
        stored_stream_ranges: ByteRanges::new(),
        decoded_checksum: None,
        encoded_checksum: None,
    })
}

pub(super) fn read_single_transform_chunk_header(
    reader: &mut Reader<'_>,
    stored_streams: usize,
    format_version: u32,
    has_bundle_id: bool,
    limits: Limits,
) -> Result<ChunkPlan> {
    let transform_type = match read_bitpacked_single_u32(reader, 1)? {
        0 => TransformType::Standard,
        1 => TransformType::Custom,
        _ => return Err(Error::new(ErrorKind::Malformed).with_detail("invalid transform type")),
    };
    let transform_id = match transform_type {
        TransformType::Standard => {
            let id = read_bitpacked_single_u32(reader, standard_transform_id_bits(format_version))?;
            if id >= 128 {
                return Err(Error::new(ErrorKind::Unsupported)
                    .with_detail("standard transform ID is outside the OpenZL range"));
            }
            standard::validate_transform_id(id, format_version)?;
            id
        }
        TransformType::Custom => {
            let _ = reader.read_var_u64()?;
            return Err(Error::new(ErrorKind::Unsupported)
                .with_detail("custom OpenZL transforms are not implemented"));
        }
    };
    let transform_header_size = read_one_transform_header_size(reader)?;
    let transform_header_bytes =
        usize::try_from(transform_header_size).map_err(|_| Error::new(ErrorKind::LimitExceeded))?;
    let variable_outputs = read_one_variable_output(reader)?;
    let regen_count = read_one_regen_count(reader, format_version)?;
    let dict_index = if format_version >= MATERIALIZED_DICT_VERSION_MIN && has_bundle_id {
        read_one_dict_index(reader)?
    } else {
        None
    };

    check_limit(
        regen_count,
        runtime_stream_limit(format_version),
        ErrorKind::Malformed,
    )?;
    let distance_bits = bits_needed(checked_add(regen_count, stored_streams)?);
    let regen_distances = read_bitpacked_u32_inline::<1>(reader, regen_count, distance_bits)?;
    let stored_stream_sizes = read_stored_stream_sizes(reader, stored_streams, limits)?;
    let stored_stream_bytes = sum_usize(&stored_stream_sizes)?;
    let mut nodes = NodePlans::new();
    nodes.push(NodePlan {
        transform_type,
        transform_id,
        transform_header_start: 0,
        transform_header_size: transform_header_bytes,
        variable_outputs,
        regen_distances,
        dict_index,
    });

    Ok(ChunkPlan {
        nodes,
        stored_stream_sizes,
        transform_header_bytes,
        stored_stream_bytes,
        transform_header_range: ByteRange::default(),
        stored_stream_ranges: ByteRanges::new(),
        decoded_checksum: None,
        encoded_checksum: None,
    })
}

pub(super) fn read_one_transform_header_size(reader: &mut Reader<'_>) -> Result<u32> {
    let mut size = read_bitpacked_single_u32(reader, 1)?;
    if size != 0 {
        let decoded = reader.read_var_u64()?;
        size = read_shifted_u32(decoded, 1, reader.offset(), u64::from(u32::MAX - 1))?;
    }
    Ok(size)
}

pub(super) fn read_one_variable_output(reader: &mut Reader<'_>) -> Result<u32> {
    let mut output = read_bitpacked_single_u32(reader, 1)?;
    if output != 0 {
        let decoded = reader.read_var_u64()?;
        output = u32::try_from(
            decoded
                .checked_add(1)
                .ok_or_else(|| Error::at(ErrorKind::IntegerOverflow, reader.offset()))?,
        )
        .map_err(|_| Error::at(ErrorKind::Malformed, reader.offset()))?;
    }
    Ok(output)
}

pub(super) fn read_one_regen_count(reader: &mut Reader<'_>, format_version: u32) -> Result<usize> {
    if format_version < 16 {
        return Ok(1);
    }
    let mut count = read_bitpacked_single_u32(reader, 1)?;
    if count != 0 {
        let decoded = reader.read_var_u64()?;
        count = u32::try_from(
            decoded
                .checked_add(2)
                .ok_or_else(|| Error::at(ErrorKind::IntegerOverflow, reader.offset()))?,
        )
        .map_err(|_| Error::at(ErrorKind::Malformed, reader.offset()))?;
    } else {
        count = 1;
    }
    let count =
        usize::try_from(count).map_err(|_| Error::at(ErrorKind::LimitExceeded, reader.offset()))?;
    check_limit(
        count,
        runtime_node_input_limit(format_version),
        ErrorKind::Malformed,
    )?;
    Ok(count)
}

pub(super) fn read_one_dict_index(reader: &mut Reader<'_>) -> Result<Option<u32>> {
    if read_bitpacked_single_u32(reader, 1)? == 0 {
        return Ok(None);
    }
    let bits = usize::from(reader.read_byte()?);
    if bits > 16 {
        return Err(Error::at(ErrorKind::Malformed, reader.offset())
            .with_detail("dict index bit width is too large"));
    }
    let value = read_bitpacked_single_u32(reader, bits)?;
    if value > MAX_DICTS_PER_BUNDLE {
        return Err(Error::new(ErrorKind::Malformed).with_detail("dict index is too large"));
    }
    Ok(Some(value))
}

pub(super) fn build_node_plans(
    transform_types: &[TransformType],
    transform_ids: &[u32],
    transform_header_sizes: &[u32],
    variable_outputs: &[u32],
    regen_counts: &[usize],
    dict_indexes: &[Option<u32>],
    regen_distances: &[u32],
) -> Result<NodePlans> {
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

    let mut nodes = NodePlans::new();
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
            .iter()
            .copied()
            .collect::<RegenDistances>();
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

pub(super) fn read_transform_count(reader: &mut Reader<'_>, format_version: u32) -> Result<usize> {
    let raw = read_count(reader, format_version)?;
    let adjusted = if format_version >= CHUNK_VERSION_MIN {
        raw.checked_sub(1)
            .ok_or_else(|| Error::at(ErrorKind::Malformed, reader.offset()))?
    } else {
        raw
    };
    usize::try_from(adjusted).map_err(|_| Error::at(ErrorKind::LimitExceeded, reader.offset()))
}

pub(super) fn read_count(reader: &mut Reader<'_>, format_version: u32) -> Result<u64> {
    if format_version < 9 {
        Ok(u64::from(reader.read_byte()?))
    } else {
        reader.read_var_u64()
    }
}

pub(super) fn read_transform_types(
    reader: &mut Reader<'_>,
    transforms: usize,
) -> Result<Vec<TransformType>> {
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

pub(super) fn read_transform_ids(
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

pub(super) fn read_transform_header_sizes(
    reader: &mut Reader<'_>,
    transforms: usize,
) -> Result<Vec<u32>> {
    let mut sizes = read_bitpacked_u32(reader, transforms, 1)?;
    for size in &mut sizes {
        if *size != 0 {
            let decoded = reader.read_var_u64()?;
            *size = read_shifted_u32(decoded, 1, reader.offset(), u64::from(u32::MAX - 1))?;
        }
    }
    Ok(sizes)
}

pub(super) fn read_variable_outputs(
    reader: &mut Reader<'_>,
    transforms: usize,
) -> Result<Vec<u32>> {
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

pub(super) fn read_regen_counts(
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

pub(super) fn read_dict_indexes(
    reader: &mut Reader<'_>,
    transforms: usize,
) -> Result<SmallVec<[Option<u32>; 2]>> {
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
    let mut out = SmallVec::new();
    out.try_reserve_exact(transforms).map_err(|_| {
        Error::new(ErrorKind::LimitExceeded).with_detail("dict index allocation failed")
    })?;
    for flag in flags {
        if flag == 0 {
            out.push(None);
        } else {
            let value = values[value_index];
            if value > MAX_DICTS_PER_BUNDLE {
                return Err(Error::new(ErrorKind::Malformed).with_detail("dict index is too large"));
            }
            out.push(Some(value));
            value_index = checked_add(value_index, 1)?;
        }
    }
    Ok(out)
}

pub(super) fn read_shifted_u32(raw: u64, shift: u32, offset: usize, max_raw: u64) -> Result<u32> {
    if raw >= max_raw {
        return Err(
            Error::at(ErrorKind::Malformed, offset).with_detail("shifted u32 field is too large")
        );
    }
    u32::try_from(
        raw.checked_add(u64::from(shift))
            .ok_or_else(|| Error::at(ErrorKind::IntegerOverflow, offset))?,
    )
    .map_err(|_| Error::at(ErrorKind::Malformed, offset))
}

pub(super) fn read_stored_stream_sizes(
    reader: &mut Reader<'_>,
    streams: usize,
    limits: Limits,
) -> Result<StoredStreamSizes> {
    let mut sizes = StoredStreamSizes::new();
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

pub(super) fn standard_transform_id_bits(format_version: u32) -> usize {
    if format_version < 24 { 6 } else { 7 }
}

pub(super) fn runtime_node_input_limit(format_version: u32) -> usize {
    if format_version <= 15 {
        1
    } else {
        runtime_input_limit(format_version)
    }
}

pub(super) fn runtime_node_limit(format_version: u32) -> usize {
    if format_version < 9 {
        256
    } else if format_version < 20 {
        10_000
    } else {
        20_000
    }
}

pub(super) fn runtime_stream_limit(format_version: u32) -> usize {
    if format_version < 9 {
        256
    } else if format_version < 16 {
        10_000
    } else {
        110_000
    }
}

#[cfg(feature = "checksum")]
pub(super) fn verify_compressed_checksum(
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

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(super) struct ChunkSummary {
    pub(super) chunks: usize,
    pub(super) transforms: usize,
    pub(super) stored_streams: usize,
    pub(super) regenerated_streams: usize,
}

pub(super) struct ChunkScan {
    pub(super) summary: ChunkSummary,
    pub(super) chunks: ChunkPlans,
    pub(super) flags: FrameFlags,
}
