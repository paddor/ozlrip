use alloc::vec::Vec;

use crate::standard;
use ozlrip_core::{Error, ErrorKind, Limits, Result};

use super::conversion::{byte_preserving_conversion_output_width, is_byte_preserving_conversion};
use super::header::require_empty_header;
use super::layout_nodes::append_split_by_struct_output;
use super::output::check_output_len;
use super::plan::{ChunkExecutionPlan, NodeExecutionPlan};
use super::slots::StreamSlot;
use super::split_struct::split_by_struct_output_len;
use super::streams::StreamInput;

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
    conversion_chain_tail(plan, standard::FIELD_LZ_ID, DirectAppendKind::FieldLz)
        .or_else(|| conversion_chain_tail(plan, standard::ZSTD_ID, DirectAppendKind::Zstd))
        .or_else(|| dispatch_string_to_serial_append_tail(plan))
        .or_else(|| split_by_struct_to_splitn_append_tail(plan))
        .or_else(|| conversion_chain_tail(plan, standard::LZ_ID, DirectAppendKind::Lz))
}

/// Matches the first node with `standard_id` and one output when only
/// single-input byte-preserving conversions follow it, chained from its
/// output to the chunk's final stream.
fn conversion_chain_tail(
    plan: &ChunkExecutionPlan,
    standard_id: u32,
    kind: DirectAppendKind,
) -> Option<DirectAppendTail> {
    let final_stream = plan.regen_targets.len().checked_sub(1)?;
    for (index, node) in plan.nodes.iter().enumerate() {
        if node.standard_id != standard_id || node.output_targets.len() != 1 {
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
            return Some(DirectAppendTail { start: index, kind });
        }
    }
    None
}

fn dispatch_string_to_serial_append_tail(plan: &ChunkExecutionPlan) -> Option<DirectAppendTail> {
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

fn split_by_struct_to_splitn_append_tail(plan: &ChunkExecutionPlan) -> Option<DirectAppendTail> {
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
        let header = node.header(transform_headers)?;
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
    if node.standard_id != standard::CONVERT_STRING_TO_SERIAL_ID {
        return Err(Error::new(ErrorKind::InvalidGraph)
            .with_detail("direct string append tail is malformed"));
    }
    // Same error as the general conversion path.
    let header = node.header(transform_headers)?;
    require_empty_header(header, "convert_string_to_serial headers are unsupported")?;
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
    let splitn_header = splitn.header(transform_headers)?;
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
    check_output_len(total_len, limits)?;
    dst.try_reserve_exact(total_len).map_err(|_| {
        Error::new(ErrorKind::AllocationFailed).with_detail("splitn allocation failed")
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
