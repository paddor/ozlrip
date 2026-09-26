use alloc::{format, vec::Vec};

use crate::standard;
use ozlrip_core::{Error, ErrorKind, Result};
use smallvec::SmallVec;

#[derive(Clone)]
pub(super) struct ChunkExecutionPlan {
    pub(super) nodes: Vec<NodeExecutionPlan>,
    pub(super) regen_targets: Vec<bool>,
}

#[derive(Clone)]
pub(super) struct NodeExecutionPlan {
    pub(super) standard_id: u32,
    pub(super) input_start: usize,
    pub(super) input_count: usize,
    pub(super) output_targets: SmallVec<[usize; 2]>,
    pub(super) variable_inputs: u32,
    pub(super) dict_index: Option<u32>,
    pub(super) header_start: usize,
    pub(super) header_size: usize,
}

pub(super) fn build_chunk_execution_plan(
    chunk: &crate::parse::ChunkPlan,
) -> Result<ChunkExecutionPlan> {
    let total_streams = chunk
        .stored_streams()
        .checked_add(chunk.regenerated_streams())
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
    let mut regen_targets = Vec::new();
    regen_targets
        .try_reserve_exact(total_streams)
        .map_err(|_| {
            Error::new(ErrorKind::LimitExceeded).with_detail("regen target allocation failed")
        })?;
    regen_targets.resize(total_streams, false);

    let mut nodes = Vec::new();
    nodes.try_reserve_exact(chunk.transforms()).map_err(|_| {
        Error::new(ErrorKind::LimitExceeded).with_detail("node execution allocation failed")
    })?;
    let mut stream_cursor = 0usize;
    for node in chunk.nodes() {
        let standard_id = node.standard_id().ok_or_else(|| {
            Error::new(ErrorKind::Unsupported).with_detail("custom graph execution is unsupported")
        })?;
        // Checked here so every execution path, including direct-append
        // tails and shortcuts, rejects unsupported dictionary use.
        if node.dict_index().is_some() && standard_id != standard::ZSTD_ID {
            return Err(Error::new(ErrorKind::Unsupported)
                .with_detail("only zstd dictionary-backed transforms are implemented"));
        }
        let variable_inputs = usize::try_from(node.variable_outputs()).map_err(|_| {
            Error::new(ErrorKind::LimitExceeded).with_detail("node input count is too large")
        })?;
        let input_count = if standard_id == standard::SPARSE_NUM_ID {
            2usize
                .checked_add(variable_inputs)
                .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?
        } else {
            standard_node_input_count(standard_id, variable_inputs)?
        };
        let input_end = stream_cursor
            .checked_add(input_count)
            .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
        let mut output_targets = SmallVec::<[usize; 2]>::new();
        output_targets
            .try_reserve_exact(node.regen_distances().len())
            .map_err(|_| {
                Error::new(ErrorKind::LimitExceeded)
                    .with_detail("node output target allocation failed")
            })?;
        for &distance in node.regen_distances() {
            let distance = usize::try_from(distance).map_err(|_| {
                Error::new(ErrorKind::LimitExceeded).with_detail("regen distance is too large")
            })?;
            let output_target = input_end
                .checked_add(distance)
                .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
            let target = regen_targets.get_mut(output_target).ok_or_else(|| {
                Error::new(ErrorKind::InvalidGraph).with_detail(format!(
                    "regen stream distance is out of bounds: id={standard_id} input_end={input_end} distance={distance} target={output_target} streams={total_streams}"
                ))
            })?;
            if *target {
                return Err(Error::new(ErrorKind::InvalidGraph)
                    .with_detail("duplicate regen stream distance"));
            }
            *target = true;
            output_targets.push(output_target);
        }
        nodes.push(NodeExecutionPlan {
            standard_id,
            input_start: stream_cursor,
            input_count,
            output_targets,
            variable_inputs: node.variable_outputs(),
            dict_index: node.dict_index(),
            header_start: node.transform_header_start(),
            header_size: node.transform_header_size(),
        });
        stream_cursor = input_end;
    }

    Ok(ChunkExecutionPlan {
        nodes,
        regen_targets,
    })
}

pub(super) fn standard_node_input_count(standard_id: u32, variable_inputs: usize) -> Result<usize> {
    let static_inputs: usize = match standard_id {
        standard::SPLITN_ID
        | standard::SPLITN_STRUCT_ID
        | standard::SPLITN_NUM_ID
        | standard::SPLIT_BY_STRUCT_ID
        | standard::TRANSPOSE_SPLIT_ID
        | standard::BIT_SPLIT_ID => 0,
        standard::CONCAT_SERIAL_ID
        | standard::CONCAT_NUM_ID
        | standard::CONCAT_STRUCT_ID
        | standard::CONCAT_STRING_ID
        | standard::DISPATCH_N_BY_TAG_ID
        | standard::FLOAT_DECONSTRUCT_ID
        | standard::FLATPACK_ID
        | standard::SENTINEL_ID
        | standard::SEPARATE_STRING_COMPONENTS_ID
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
        | standard::TRANSPOSE_SPLIT2_ID
        | standard::PIVCO_HUFFMAN_ID
        | standard::MUX_LENGTHS_ID => 2,
        standard::TRANSPOSE_SPLIT4_ID | standard::LZ_ID => 4,
        standard::FIELD_LZ_ID => 5,
        standard::TRANSPOSE_SPLIT8_ID => 8,
        standard::DISPATCH_STRING_ID
        | standard::FSE_DEPRECATED_ID
        | standard::HUFFMAN_DEPRECATED_ID
        | standard::HUFFMAN_FIXED_DEPRECATED_ID
        | standard::ROLZ_DEPRECATED_ID
        | standard::FASTLZ_DEPRECATED_ID
        | standard::LZ4_ID
        | standard::ZSTD_ID
        | standard::ZSTD_FIXED_ID
        | standard::BITPACK_SERIAL_ID
        | standard::BITPACK_INT_ID
        | standard::CONSTANT_SERIAL_ID
        | standard::CONSTANT_FIXED_ID
        | standard::CONVERT_STRUCT_TO_NUM_LE_ID
        | standard::CONVERT_NUM_TO_STRUCT_LE_ID
        | standard::CONVERT_SERIAL_TO_NUM_LE_ID
        | standard::CONVERT_NUM_TO_SERIAL_LE_ID
        | standard::CONVERT_STRUCT_TO_NUM_BE_ID
        | standard::CONVERT_SERIAL_TO_NUM_BE_ID
        | standard::CONVERT_STRING_TO_SERIAL_ID
        | standard::CONVERT_SERIAL_TO_STRUCT_ID
        | standard::CONVERT_STRUCT_TO_SERIAL_ID
        | standard::ZIGZAG_ID
        | standard::TRANSPOSE_ID
        | standard::DEDUP_NUM_ID
        | standard::DELTA_INT_ID
        | standard::DIVIDE_BY_ID
        | standard::INTERLEAVE_STRING_ID
        | standard::PARSE_INT_ID
        | standard::BITUNPACK_ID
        | standard::RANGE_PACK_ID
        | standard::FSE_NCOUNT_ID => 1,
        _ => {
            return Err(Error::new(ErrorKind::Unsupported)
                .with_detail("standard transform graph execution is not implemented yet"));
        }
    };
    static_inputs
        .checked_add(variable_inputs)
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))
}
