use alloc::{format, vec::Vec};

use crate::standard;
use ozlrip_core::{Error, ErrorKind, Limits, Result};

use super::reader::{check_limit, checked_add, sum_usize};
use super::{ChunkPlan, FramePlan, NodePlan, TransformType};

pub(super) fn validate_frame_plan(plan: &FramePlan, limits: Limits) -> Result<()> {
    if plan.info.chunks != plan.chunks.len() {
        return Err(Error::new(ErrorKind::InvalidGraph).with_detail("chunk count mismatch"));
    }

    let mut transforms = 0usize;
    let mut stored_streams = 0usize;
    let mut regenerated_streams = 0usize;
    for chunk in &plan.chunks {
        validate_chunk_plan(chunk, plan.info.output_types.len(), limits)?;
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

pub(super) fn validate_chunk_plan(
    chunk: &ChunkPlan,
    output_count: usize,
    limits: Limits,
) -> Result<()> {
    let stream_bound = checked_add(chunk.regenerated_streams(), chunk.stored_streams())?;
    if output_count > stream_bound {
        return Err(Error::new(ErrorKind::InvalidGraph)
            .with_detail("chunk has fewer streams than final outputs"));
    }
    if chunk.nodes.len() == 1 {
        return validate_single_node_chunk_plan(chunk, output_count, stream_bound, limits);
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
    let mut stream_depths = Vec::new();
    stream_depths.try_reserve_exact(stream_bound).map_err(|_| {
        Error::new(ErrorKind::LimitExceeded)
            .with_detail("stream depth validation allocation failed")
    })?;
    stream_depths.resize(stream_bound, 0usize);
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
        let input_depth = stream_depths[stream_cursor..input_end]
            .iter()
            .copied()
            .max()
            .unwrap_or(0);
        let output_depth = checked_add(input_depth, 1)?;
        check_limit(
            output_depth,
            limits.max_graph_depth,
            ErrorKind::LimitExceeded,
        )?;
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
            stream_depths[target] = output_depth;
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

pub(super) fn validate_single_node_chunk_plan(
    chunk: &ChunkPlan,
    output_count: usize,
    stream_bound: usize,
    limits: Limits,
) -> Result<()> {
    let first_final_stream = stream_bound.saturating_sub(output_count);
    let node = &chunk.nodes[0];
    if node.transform_type == TransformType::Standard && node.transform_id >= 128 {
        return Err(Error::new(ErrorKind::Unsupported)
            .with_detail("standard transform ID is outside the OpenZL range"));
    }
    let shape = validate_known_standard_node_shape(node)?;
    if node.transform_header_start != 0 {
        return Err(Error::new(ErrorKind::InvalidGraph).with_detail("transform header gap"));
    }
    if node.transform_header_size != chunk.transform_header_bytes {
        return Err(
            Error::new(ErrorKind::InvalidGraph).with_detail("transform header size mismatch")
        );
    }
    let variable_inputs =
        usize::try_from(node.variable_outputs).map_err(|_| Error::new(ErrorKind::LimitExceeded))?;
    if variable_inputs > 0 && !shape.allows_variable_inputs {
        return Err(
            Error::new(ErrorKind::InvalidGraph).with_detail("node has unexpected variable inputs")
        );
    }
    let input_count = checked_add(shape.static_inputs, variable_inputs)?;
    if input_count > first_final_stream {
        return Err(Error::new(ErrorKind::InvalidGraph)
            .with_detail("node input range reaches final output streams"));
    }
    check_limit(1, limits.max_graph_depth, ErrorKind::LimitExceeded)?;
    validate_node_output_count(node, shape)?;
    if node.dict_index.is_some() && node.transform_type == TransformType::Custom {
        return Err(Error::new(ErrorKind::Unsupported)
            .with_detail("custom transform dictionaries are unsupported"));
    }

    let mut regenerated = 0usize;
    let mut produced_final_outputs = 0usize;
    for &distance in &node.regen_distances {
        let distance =
            usize::try_from(distance).map_err(|_| Error::new(ErrorKind::LimitExceeded))?;
        let target = checked_add(input_count, distance)?;
        if target >= stream_bound {
            return Err(Error::new(ErrorKind::InvalidGraph)
                .with_detail("regen stream distance is out of bounds"));
        }
        if target >= first_final_stream {
            produced_final_outputs = checked_add(produced_final_outputs, 1)?;
        }
        regenerated = checked_add(regenerated, 1)?;
    }
    if node.regen_distances.len() == 2 && node.regen_distances[0] == node.regen_distances[1] {
        return Err(
            Error::new(ErrorKind::InvalidGraph).with_detail("duplicate regen stream distance")
        );
    }
    if node.regen_distances.len() > 2 {
        for index in 1..node.regen_distances.len() {
            if node.regen_distances[..index].contains(&node.regen_distances[index]) {
                return Err(Error::new(ErrorKind::InvalidGraph)
                    .with_detail("duplicate regen stream distance"));
            }
        }
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
    let stored_final_outputs = output_count.saturating_sub(produced_final_outputs);
    if stored_final_outputs > chunk.stored_streams() {
        return Err(
            Error::new(ErrorKind::InvalidGraph).with_detail("final output stream is not produced")
        );
    }
    Ok(())
}

pub(super) fn validate_known_standard_node_shape(node: &NodePlan) -> Result<StandardNodeShape> {
    let Some(id) = node.standard_id() else {
        return Err(Error::new(ErrorKind::Unsupported)
            .with_detail("custom OpenZL transforms are not implemented"));
    };
    let shape = standard_node_shape(id).ok_or_else(|| {
        Error::new(ErrorKind::Unsupported).with_detail(format!(
            "standard transform graph shape is unsupported: id={id}"
        ))
    })?;
    Ok(shape)
}

pub(super) fn validate_node_output_count(node: &NodePlan, shape: StandardNodeShape) -> Result<()> {
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
pub(super) struct StandardNodeShape {
    pub(super) static_inputs: usize,
    pub(super) allows_variable_inputs: bool,
    pub(super) min_outputs: usize,
    pub(super) max_outputs: Option<usize>,
}

pub(super) const fn fixed_shape(static_inputs: usize, outputs: usize) -> StandardNodeShape {
    StandardNodeShape {
        static_inputs,
        allows_variable_inputs: false,
        min_outputs: outputs,
        max_outputs: Some(outputs),
    }
}

pub(super) const fn standard_node_shape(id: u32) -> Option<StandardNodeShape> {
    match id {
        standard::DELTA_INT_ID
        | standard::TRANSPOSE_ID
        | standard::DIVIDE_BY_ID
        | standard::ZIGZAG_ID
        | standard::CONVERT_STRUCT_TO_NUM_LE_ID
        | standard::CONVERT_NUM_TO_STRUCT_LE_ID
        | standard::CONVERT_SERIAL_TO_NUM_LE_ID
        | standard::CONVERT_NUM_TO_SERIAL_LE_ID
        | standard::CONVERT_STRING_TO_SERIAL_ID
        | standard::CONVERT_SERIAL_TO_STRUCT_ID
        | standard::CONVERT_STRUCT_TO_SERIAL_ID
        | standard::CONVERT_STRUCT_TO_NUM_BE_ID
        | standard::CONVERT_SERIAL_TO_NUM_BE_ID
        | standard::FSE_DEPRECATED_ID
        | standard::HUFFMAN_DEPRECATED_ID
        | standard::HUFFMAN_FIXED_DEPRECATED_ID
        | standard::ROLZ_DEPRECATED_ID
        | standard::FASTLZ_DEPRECATED_ID
        | standard::ZSTD_ID
        | standard::ZSTD_FIXED_ID
        | standard::BITPACK_SERIAL_ID
        | standard::BITPACK_INT_ID
        | standard::BITUNPACK_ID
        | standard::RANGE_PACK_ID
        | standard::CONSTANT_SERIAL_ID
        | standard::CONSTANT_FIXED_ID
        | standard::PARSE_INT_ID
        | standard::FSE_NCOUNT_ID
        | standard::LZ4_ID => Some(fixed_shape(1, 1)),
        standard::FLATPACK_ID
        | standard::FLOAT_DECONSTRUCT_ID
        | standard::FSE_V2_ID
        | standard::HUFFMAN_V2_ID
        | standard::HUFFMAN_STRUCT_V2_ID
        | standard::MERGE_SORTED_ID
        | standard::QUANTIZE_OFFSETS_ID
        | standard::QUANTIZE_LENGTHS_ID
        | standard::PARTITION_ID
        | standard::TOKENIZE_FIXED_ID
        | standard::TOKENIZE_NUMERIC_ID
        | standard::TOKENIZE_STRING_ID
        | standard::PREFIX_ID
        | standard::SENTINEL_ID
        | standard::TRANSPOSE_SPLIT2_ID
        | standard::PIVCO_HUFFMAN_ID
        | standard::SPARSE_NUM_ID
        | standard::SEPARATE_STRING_COMPONENTS_ID => Some(fixed_shape(2, 1)),
        standard::MUX_LENGTHS_ID => Some(fixed_shape(2, 2)),
        standard::TRANSPOSE_SPLIT4_ID | standard::LZ_ID => Some(fixed_shape(4, 1)),
        standard::FIELD_LZ_ID => Some(fixed_shape(5, 1)),
        standard::TRANSPOSE_SPLIT8_ID => Some(fixed_shape(8, 1)),
        standard::DISPATCH_STRING_ID => Some(StandardNodeShape {
            static_inputs: 1,
            allows_variable_inputs: true,
            min_outputs: 1,
            max_outputs: Some(1),
        }),
        standard::SPLITN_ID
        | standard::SPLITN_STRUCT_ID
        | standard::SPLITN_NUM_ID
        | standard::SPLIT_BY_STRUCT_ID
        | standard::TRANSPOSE_SPLIT_ID
        | standard::BIT_SPLIT_ID => Some(StandardNodeShape {
            static_inputs: 0,
            allows_variable_inputs: true,
            min_outputs: 1,
            max_outputs: Some(1),
        }),
        standard::CONCAT_SERIAL_ID
        | standard::CONCAT_NUM_ID
        | standard::CONCAT_STRUCT_ID
        | standard::CONCAT_STRING_ID => Some(StandardNodeShape {
            static_inputs: 2,
            allows_variable_inputs: false,
            min_outputs: 1,
            max_outputs: None,
        }),
        standard::DEDUP_NUM_ID | standard::INTERLEAVE_STRING_ID => Some(StandardNodeShape {
            static_inputs: 1,
            allows_variable_inputs: false,
            min_outputs: 1,
            max_outputs: None,
        }),
        standard::DISPATCH_N_BY_TAG_ID => Some(StandardNodeShape {
            static_inputs: 2,
            allows_variable_inputs: true,
            min_outputs: 1,
            max_outputs: Some(1),
        }),
        _ => None,
    }
}
