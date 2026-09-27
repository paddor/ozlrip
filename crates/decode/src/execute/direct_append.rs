use alloc::vec::Vec;

use crate::standard;
use ozlrip_core::{Error, ErrorKind, Limits, Result};

use super::layout_nodes::{append_split_by_struct_output, split_by_struct_output_len};
use super::node::{
    byte_preserving_conversion_output_width, is_byte_preserving_conversion, node_header,
};
use super::plan::{ChunkExecutionPlan, NodeExecutionPlan};
use super::streams::{StreamInput, StreamSlot};

#[derive(Clone, Copy)]
pub(super) struct DirectAppendChunk<'a> {
    pub(super) chunk: &'a crate::parse::ChunkPlan,
    pub(super) execution: &'a ChunkExecutionPlan,
}

#[derive(Clone, Copy)]
pub(super) struct DirectAppendTail {
    pub(super) start: usize,
    pub(super) kind: DirectAppendKind,
}

#[derive(Clone, Copy)]
pub(super) enum DirectAppendKind {
    Lz,
    FieldLz,
    Zstd,
    DispatchStringToSerial,
    SplitByStructToSplitN,
}

pub(super) fn direct_append_tail(plan: &ChunkExecutionPlan) -> Option<DirectAppendTail> {
    field_lz_append_tail_start(plan)
        .or_else(|| zstd_append_tail_start(plan))
        .or_else(|| dispatch_string_to_serial_append_tail(plan))
        .or_else(|| split_by_struct_to_splitn_append_tail(plan))
        .or_else(|| lz_append_tail_start(plan))
}

pub(super) fn lz_append_tail_start(plan: &ChunkExecutionPlan) -> Option<DirectAppendTail> {
    let final_stream = plan.regen_targets.len().checked_sub(1)?;
    for (index, node) in plan.nodes.iter().enumerate() {
        if node.standard_id != standard::LZ_ID || node.output_targets.len() != 1 {
            continue;
        }
        let mut next_input = node.output_targets[0];
        for tail in &plan.nodes[index + 1..] {
            if !is_byte_preserving_conversion(tail.standard_id)
                || tail.input_count != 1
                || tail.input_start != next_input
                || tail.output_targets.len() != 1
            {
                return None;
            }
            next_input = tail.output_targets[0];
        }
        if next_input == final_stream {
            return Some(DirectAppendTail {
                start: index,
                kind: DirectAppendKind::Lz,
            });
        }
    }
    None
}

pub(super) fn field_lz_append_tail_start(plan: &ChunkExecutionPlan) -> Option<DirectAppendTail> {
    let final_stream = plan.regen_targets.len().checked_sub(1)?;
    for (index, node) in plan.nodes.iter().enumerate() {
        if node.standard_id != standard::FIELD_LZ_ID || node.output_targets.len() != 1 {
            continue;
        }
        let mut next_input = node.output_targets[0];
        for tail in &plan.nodes[index + 1..] {
            if !is_byte_preserving_conversion(tail.standard_id)
                || tail.input_count != 1
                || tail.input_start != next_input
                || tail.output_targets.len() != 1
            {
                return None;
            }
            next_input = tail.output_targets[0];
        }
        if next_input == final_stream {
            return Some(DirectAppendTail {
                start: index,
                kind: DirectAppendKind::FieldLz,
            });
        }
    }
    None
}

pub(super) fn zstd_append_tail_start(plan: &ChunkExecutionPlan) -> Option<DirectAppendTail> {
    let final_stream = plan.regen_targets.len().checked_sub(1)?;
    for (index, node) in plan.nodes.iter().enumerate() {
        if node.standard_id != standard::ZSTD_ID || node.output_targets.len() != 1 {
            continue;
        }
        let mut next_input = node.output_targets[0];
        for tail in &plan.nodes[index + 1..] {
            if !is_byte_preserving_conversion(tail.standard_id)
                || tail.input_count != 1
                || tail.input_start != next_input
                || tail.output_targets.len() != 1
            {
                return None;
            }
            next_input = tail.output_targets[0];
        }
        if next_input == final_stream {
            return Some(DirectAppendTail {
                start: index,
                kind: DirectAppendKind::Zstd,
            });
        }
    }
    None
}

pub(super) fn dispatch_string_to_serial_append_tail(
    plan: &ChunkExecutionPlan,
) -> Option<DirectAppendTail> {
    let final_stream = plan.regen_targets.len().checked_sub(1)?;
    for (index, node) in plan.nodes.iter().enumerate() {
        if node.standard_id != standard::DISPATCH_STRING_ID || node.output_targets.len() != 1 {
            continue;
        }
        let [tail] = &plan.nodes[index + 1..] else {
            continue;
        };
        if tail.standard_id == standard::CONVERT_STRING_TO_SERIAL_ID
            && tail.input_count == 1
            && tail.input_start == node.output_targets[0]
            && tail.output_targets.as_slice() == [final_stream]
        {
            return Some(DirectAppendTail {
                start: index,
                kind: DirectAppendKind::DispatchStringToSerial,
            });
        }
    }
    None
}

pub(super) fn split_by_struct_to_splitn_append_tail(
    plan: &ChunkExecutionPlan,
) -> Option<DirectAppendTail> {
    let final_stream = plan.regen_targets.len().checked_sub(1)?;
    let [split_by_struct, splitn] = plan
        .nodes
        .as_slice()
        .get(plan.nodes.len().checked_sub(2)?..)?
    else {
        return None;
    };
    if split_by_struct.standard_id != standard::SPLIT_BY_STRUCT_ID
        || split_by_struct.output_targets.len() != 1
        || !matches!(
            splitn.standard_id,
            standard::SPLITN_ID | standard::SPLITN_STRUCT_ID
        )
        || splitn.output_targets.as_slice() != [final_stream]
    {
        return None;
    }
    let split_output = split_by_struct.output_targets[0];
    let input_end = splitn.input_start.checked_add(splitn.input_count)?;
    if !(splitn.input_start..input_end).contains(&split_output) {
        return None;
    }
    Some(DirectAppendTail {
        start: plan.nodes.len() - 2,
        kind: DirectAppendKind::SplitByStructToSplitN,
    })
}

pub(super) fn validate_direct_append_tail(
    tail: &[NodeExecutionPlan],
    transform_headers: &[u8],
    mut element_width: usize,
    bytes: &[u8],
    limits: Limits,
) -> Result<()> {
    for node in tail {
        let header = node_header(transform_headers, node.header_start, node.header_size)?;
        let input = StreamInput {
            bytes,
            element_width,
            string_lengths: None,
        };
        let Some(output_width) = byte_preserving_conversion_output_width(
            node.standard_id,
            node.input_count,
            input,
            header,
            limits,
        )?
        else {
            return Err(Error::new(ErrorKind::InvalidGraph)
                .with_detail("direct-append tail contains a non-conversion node"));
        };
        element_width = output_width;
    }
    Ok(())
}

pub(super) fn validate_string_to_serial_tail(
    tail: &[NodeExecutionPlan],
    transform_headers: &[u8],
) -> Result<()> {
    let [node] = tail else {
        return Err(Error::new(ErrorKind::InvalidGraph)
            .with_detail("direct string append tail is malformed"));
    };
    let header = node_header(transform_headers, node.header_start, node.header_size)?;
    if node.standard_id != standard::CONVERT_STRING_TO_SERIAL_ID || !header.is_empty() {
        return Err(Error::new(ErrorKind::InvalidGraph)
            .with_detail("direct string append tail is malformed"));
    }
    Ok(())
}

pub(super) fn append_split_by_struct_to_final_splitn(
    streams: &[StreamSlot<'_>],
    split_by_struct_inputs: &[StreamInput<'_>],
    split_by_struct: &NodeExecutionPlan,
    tail: &[NodeExecutionPlan],
    transform_headers: &[u8],
    limits: Limits,
    dst: &mut Vec<u8>,
) -> Result<()> {
    let [splitn] = tail else {
        return Err(Error::new(ErrorKind::InvalidGraph)
            .with_detail("direct split_by_struct tail is malformed"));
    };
    let splitn_header = node_header(transform_headers, splitn.header_start, splitn.header_size)?;
    if !splitn_header.is_empty() {
        return Err(
            Error::new(ErrorKind::Unsupported).with_detail("splitn headers are unsupported")
        );
    }
    let [split_output] = split_by_struct.output_targets.as_slice() else {
        return Err(Error::new(ErrorKind::InvalidGraph)
            .with_detail("split_by_struct output count does not match graph"));
    };
    let input_end = splitn
        .input_start
        .checked_add(splitn.input_count)
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
    let mut total_len = 0usize;
    for stream_index in (splitn.input_start..input_end).rev() {
        let len = if stream_index == *split_output {
            split_by_struct_output_len(split_by_struct_inputs)?
        } else {
            let input = streams
                .get(stream_index)
                .ok_or_else(|| {
                    Error::new(ErrorKind::InvalidGraph)
                        .with_detail("node input range is out of bounds")
                })?
                .as_input()?;
            // splitn inputs share one width, and split_by_struct outputs bytes.
            if input.element_width != 1 {
                return Err(Error::new(ErrorKind::InvalidType)
                    .with_detail("splitn input widths must match"));
            }
            input.bytes.len()
        };
        total_len = total_len
            .checked_add(len)
            .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
    }
    if total_len > limits.max_decoded_bytes || total_len > limits.max_buffer_bytes {
        return Err(
            Error::new(ErrorKind::LimitExceeded).with_detail("decoded output limit exceeded")
        );
    }
    dst.try_reserve_exact(total_len).map_err(|_| {
        Error::new(ErrorKind::LimitExceeded).with_detail("splitn allocation failed")
    })?;
    for stream_index in (splitn.input_start..input_end).rev() {
        if stream_index == *split_output {
            append_split_by_struct_output(split_by_struct_inputs, limits, dst)?;
        } else {
            let input = streams
                .get(stream_index)
                .ok_or_else(|| {
                    Error::new(ErrorKind::InvalidGraph)
                        .with_detail("node input range is out of bounds")
                })?
                .as_input()?;
            dst.extend_from_slice(input.bytes);
        }
    }
    Ok(())
}
