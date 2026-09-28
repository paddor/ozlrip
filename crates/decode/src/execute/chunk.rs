//! Running one chunk's transform graph: node by node into stream slots, or
//! with its last node appending straight to the caller's output.

use alloc::vec::Vec;

use ozlrip_core::{Error, ErrorKind, Limits, Result};
use smallvec::SmallVec;

use crate::parse::ChunkPlan;
use crate::standard;

use super::conversion::{byte_preserving_conversion_output_width, is_byte_preserving_conversion};
use super::direct_append::{
    DirectAppendChunk, DirectAppendKind, append_split_by_struct_to_final_splitn,
    direct_append_tail, validate_direct_append_tail, validate_string_to_serial_tail,
};
use super::dispatch::decode_dispatch_string_node_to_serial_output;
use super::header::require_empty_header;
use super::lz_nodes::{decode_field_lz_node_to_output, decode_lz_node_to_output};
use super::node::{execute_standard_node, one_typed, single_input, single_stream};
use super::numeric_nodes::decode_dedup_num_node;
use super::output::{DecodedChunk, check_output_len};
use super::plan::{ChunkExecutionPlan, NodeExecutionPlan};
use super::runtime::{DecodeRuntime, StandardNodeContext};
use super::sparse_num;
use super::streams::{
    LiveBytes, StreamSlot, collect_node_inputs, initialize_stream_slots,
    move_stream_to_single_output, recycle_consumed_owned_streams, single_execution_input,
};
use super::zstd::decode_zstd_chunk_to_output;

pub(super) fn decode_transform_chunk_with_plan<'a>(
    input: &'a [u8],
    chunk: &ChunkPlan,
    plan: &ChunkExecutionPlan,
    format_version: u32,
    limits: Limits,
    dictionary_bundle_id: Option<&[u8]>,
    runtime: &mut DecodeRuntime<'_>,
) -> Result<DecodedChunk<'a>> {
    let mut streams = run_chunk(
        input,
        chunk,
        plan,
        format_version,
        limits,
        dictionary_bundle_id,
        runtime,
    )?;
    let final_index = streams.len().checked_sub(1).ok_or_else(|| {
        Error::new(ErrorKind::InvalidGraph).with_detail("transform chunk has no output stream")
    })?;
    match streams.swap_remove(final_index) {
        StreamSlot::Borrowed(stream) => Ok(DecodedChunk::Borrowed(stream.bytes)),
        StreamSlot::Owned(stream) => Ok(DecodedChunk::Owned(stream.bytes)),
        StreamSlot::Empty => {
            Err(Error::new(ErrorKind::InvalidGraph).with_detail("final output stream is missing"))
        }
    }
}

/// Runs a chunk's nodes and returns every stream slot: the stored streams
/// and the streams the nodes regenerated.
pub(super) fn run_chunk<'a>(
    input: &'a [u8],
    chunk: &ChunkPlan,
    plan: &ChunkExecutionPlan,
    format_version: u32,
    limits: Limits,
    dictionary_bundle_id: Option<&[u8]>,
    runtime: &mut DecodeRuntime<'_>,
) -> Result<Vec<StreamSlot<'a>>> {
    let mut streams = initialize_stream_slots(input, chunk, &plan.regen_targets)?;
    let mut live = LiveBytes::new(limits);
    let transform_headers = chunk.transform_header_range().as_slice(input)?;
    let mut ctx = StandardNodeContext {
        format_version,
        limits,
        scratch: &mut *runtime.scratch,
        dictionary_bundle_id,
        dict_store: &mut *runtime.dict_store,
        #[cfg(feature = "zstd")]
        zstd: &mut *runtime.zstd,
    };

    for node in &plan.nodes {
        let header = node.header(transform_headers)?;
        execute_node(&mut streams, node, header, &mut ctx, &mut live)?;
    }
    Ok(streams)
}

/// Executes one node: the splitn and conversion shortcuts, or a node decoder
/// whose outputs fill their stream slots. Consumed owned inputs go back to
/// the scratch pool.
fn execute_node(
    streams: &mut [StreamSlot<'_>],
    node: &NodeExecutionPlan,
    header: &[u8],
    ctx: &mut StandardNodeContext<'_>,
    live: &mut LiveBytes,
) -> Result<()> {
    if try_execute_single_input_splitn_node(streams, node, header, ctx.limits, live)? {
        return Ok(());
    }
    if try_execute_byte_preserving_conversion_node(streams, node, header, ctx.limits, live)? {
        return Ok(());
    }

    let inputs = collect_node_inputs(streams, node.input_start, node.input_count)?;
    let outputs = if node.standard_id == standard::SPARSE_NUM_ID {
        one_typed(sparse_num::decode_node(&inputs, header, ctx.limits))?
    } else if node.standard_id == standard::DEDUP_NUM_ID {
        SmallVec::from_vec(decode_dedup_num_node(
            single_stream(&inputs)?,
            header,
            node.output_targets.len(),
            ctx.limits,
        )?)
    } else {
        execute_standard_node(
            node.standard_id,
            &inputs,
            node.variable_inputs,
            node.output_targets.len(),
            node.dict_index,
            header,
            ctx,
        )?
    };
    drop(inputs);
    recycle_consumed_owned_streams(
        streams,
        node.input_start,
        node.input_count,
        ctx.scratch,
        live,
    )?;
    if outputs.len() != node.output_targets.len() {
        return Err(Error::new(ErrorKind::InvalidGraph)
            .with_detail("node output count does not match graph"));
    }
    for (output, &output_target) in outputs.into_iter().zip(node.output_targets.iter()) {
        let target = streams.get_mut(output_target).ok_or_else(|| {
            Error::new(ErrorKind::InvalidGraph).with_detail("node output target is out of bounds")
        })?;
        if !matches!(target, StreamSlot::Empty) {
            return Err(Error::new(ErrorKind::InvalidGraph)
                .with_detail("node output overwrites an existing stream"));
        }
        live.add(&output)?;
        *target = StreamSlot::Owned(output);
    }
    Ok(())
}

/// `max_output` caps what the tail may append; it is the rest of the frame's
/// declared output.
#[expect(
    clippy::too_many_arguments,
    reason = "direct-append decode needs the chunk, frame context, output cap and runtime"
)]
pub(super) fn decode_transform_chunk_appending(
    input: &[u8],
    chunk: DirectAppendChunk<'_>,
    format_version: u32,
    limits: Limits,
    max_output: usize,
    dst: &mut Vec<u8>,
    dictionary_bundle_id: Option<&[u8]>,
    runtime: &mut DecodeRuntime<'_>,
) -> Result<usize> {
    let plan = chunk.execution;
    let chunk = chunk.chunk;
    let append_tail = direct_append_tail(plan).ok_or_else(|| {
        Error::new(ErrorKind::InvalidGraph).with_detail("chunk is not direct-appendable")
    })?;
    let mut streams = initialize_stream_slots(input, chunk, &plan.regen_targets)?;
    let mut live = LiveBytes::new(limits);
    let transform_headers = chunk.transform_header_range().as_slice(input)?;
    let mut ctx = StandardNodeContext {
        format_version,
        limits,
        scratch: &mut *runtime.scratch,
        dictionary_bundle_id,
        dict_store: &mut *runtime.dict_store,
        #[cfg(feature = "zstd")]
        zstd: &mut *runtime.zstd,
    };

    for (node_index, node) in plan.nodes.iter().enumerate() {
        let header = node.header(transform_headers)?;
        if node_index == append_tail.start {
            let inputs = collect_node_inputs(&streams, node.input_start, node.input_count)?;
            let output_start = dst.len();
            let element_width = match append_tail.kind {
                DirectAppendKind::Lz => {
                    decode_lz_node_to_output(&inputs, header, limits, dst, output_start)?;
                    1
                }
                DirectAppendKind::FieldLz => {
                    decode_field_lz_node_to_output(&inputs, header, limits, dst, output_start)?
                }
                DirectAppendKind::Zstd => {
                    decode_zstd_chunk_to_output(
                        single_input(&inputs)?,
                        header,
                        node.dict_index,
                        &mut ctx,
                        max_output,
                        dst,
                    )?;
                    1
                }
                DirectAppendKind::DispatchStringToSerial => {
                    decode_dispatch_string_node_to_serial_output(
                        &inputs,
                        node.variable_inputs,
                        header,
                        format_version,
                        limits,
                        dst,
                    )?;
                    1
                }
                DirectAppendKind::SplitByStructToSplitN => {
                    append_split_by_struct_to_final_splitn(
                        &streams,
                        &inputs,
                        node,
                        &plan.nodes[node_index + 1..],
                        transform_headers,
                        limits,
                        dst,
                    )?;
                    1
                }
            };
            drop(inputs);
            match append_tail.kind {
                DirectAppendKind::Lz | DirectAppendKind::FieldLz | DirectAppendKind::Zstd => {
                    validate_direct_append_tail(
                        &plan.nodes[node_index + 1..],
                        transform_headers,
                        element_width,
                        &dst[output_start..],
                        limits,
                    )?;
                }
                DirectAppendKind::DispatchStringToSerial => validate_string_to_serial_tail(
                    &plan.nodes[node_index + 1..],
                    transform_headers,
                )?,
                DirectAppendKind::SplitByStructToSplitN => {}
            }
            for slot in streams {
                if let StreamSlot::Owned(stream) = slot {
                    ctx.scratch.recycle_owned_stream(stream);
                }
            }
            return Ok(dst.len() - output_start);
        }
        execute_node(&mut streams, node, header, &mut ctx, &mut live)?;
    }

    Err(Error::new(ErrorKind::InvalidGraph).with_detail("direct-append tail was not executed"))
}

fn try_execute_single_input_splitn_node(
    streams: &mut [StreamSlot<'_>],
    node: &NodeExecutionPlan,
    header: &[u8],
    limits: Limits,
    live: &mut LiveBytes,
) -> Result<bool> {
    if !matches!(
        node.standard_id,
        standard::SPLITN_ID | standard::SPLITN_STRUCT_ID | standard::SPLITN_NUM_ID
    ) || node.input_count != 1
    {
        return Ok(false);
    }
    require_empty_header(header, "splitn headers are unsupported")?;

    let input = single_execution_input(streams, node.input_start)?;
    if input.element_width == 0 {
        return Err(Error::new(ErrorKind::InvalidType).with_detail("splitn element width is zero"));
    }
    if !input.bytes.len().is_multiple_of(input.element_width) {
        return Err(
            Error::new(ErrorKind::Malformed).with_detail("splitn input has partial element")
        );
    }
    check_output_len(input.bytes.len(), limits)?;
    let output_width = if node.standard_id == standard::SPLITN_ID {
        1
    } else {
        input.element_width
    };
    move_stream_to_single_output(streams, node, output_width, live)
}

fn try_execute_byte_preserving_conversion_node(
    streams: &mut [StreamSlot<'_>],
    node: &NodeExecutionPlan,
    header: &[u8],
    limits: Limits,
    live: &mut LiveBytes,
) -> Result<bool> {
    if !is_byte_preserving_conversion(node.standard_id) {
        return Ok(false);
    }
    let Some(output_width) = byte_preserving_conversion_output_width(
        node.standard_id,
        node.input_count,
        single_execution_input(streams, node.input_start)?,
        header,
        limits,
    )?
    else {
        return Ok(false);
    };
    move_stream_to_single_output(streams, node, output_width, live)
}
