use alloc::{format, vec, vec::Vec};

use crate::{dict::DictionaryStore, parse::FramePlan, standard};
use ozlrip_core::{Error, ErrorKind, FrameValueType, Limits, Result};
use smallvec::{SmallVec, smallvec};

mod dispatch;
mod entropy;
mod fast_bitpack;
mod fast_bitreader;
mod fast_csv;
mod fast_delta;
mod fast_dispatch;
mod fast_field_lz;
mod fast_lengths;
mod fast_lz;
mod fast_partition;
mod fast_split_struct;
mod fast_tokenize;
mod fast_transpose;
mod fast_zigzag;
mod lz_nodes;
mod numeric_nodes;
mod output;
mod parse_int;
mod partition;
mod plan_cache;
mod runtime;
mod zstd;

use dispatch::{
    decode_dispatch_n_by_tag_node, decode_dispatch_string_node,
    decode_dispatch_string_node_to_serial_output,
};
use entropy::{decode_fse_ncount_node, decode_fse_v2_node, decode_huffman_v2_node};
use lz_nodes::{
    decode_field_lz_node, decode_field_lz_node_to_output, decode_lz_node, decode_lz_node_to_output,
};
use numeric_nodes::{
    decode_bitpack_int_chunk, decode_bitpack_serial_chunk, decode_bitunpack_serial8_chunk,
    decode_byte_preserving_conversion_chunk, decode_constant_fixed_chunk,
    decode_constant_serial_chunk, decode_delta_node, decode_divide_by_node,
    decode_num_to_struct_le_chunk, decode_numeric_to_serial_le_chunk,
    decode_range_pack_serial8_chunk, decode_serial_to_num_be_chunk,
    decode_serial_to_numeric_le_chunk, decode_serial_to_struct_chunk,
    decode_struct_to_num_be_chunk, decode_zigzag_numeric_chunk,
};
#[cfg(feature = "checksum")]
use output::verify_decoded_checksum;
use output::{DecodedChunk, DecodedOutput, check_output_size};
use partition::{QUANTIZE_LENGTHS, QUANTIZE_OFFSETS, decode_partition_node, decode_quantize_node};
pub(crate) use plan_cache::{
    ChunkExecutionPlans, DirectAppendChunkPlans, prepare_chunk_execution_plans,
    prepare_direct_append_chunk_plans,
};
pub(crate) use runtime::{DecodeRuntime, DecodeScratch};
#[cfg(feature = "zstd")]
pub(crate) use zstd::decode_single_zstd_frame_with_context;
use zstd::{decode_zstd_chunk, decode_zstd_chunk_to_output, try_decode_single_zstd_into_dst};

#[cfg(test)]
mod convert_be_corpus;
#[cfg(test)]
mod parse_int_corpus;
#[cfg(test)]
mod sparse_num_corpus;

#[cfg(test)]
pub(crate) fn decode_plan(
    input: &[u8],
    plan: &FramePlan,
    dst: &mut Vec<u8>,
    limits: Limits,
) -> Result<usize> {
    #[cfg(feature = "zstd")]
    let mut zstd = zrip::DecompressContext::new();
    let mut dict_store = DictionaryStore::new();
    let mut scratch = DecodeScratch::new();
    let mut runtime = DecodeRuntime::new(
        &mut scratch,
        &mut dict_store,
        #[cfg(feature = "zstd")]
        &mut zstd,
    );
    decode_plan_with_context(input, plan, dst, limits, &mut runtime)
}

pub(crate) fn decode_plan_with_context(
    input: &[u8],
    plan: &FramePlan,
    dst: &mut Vec<u8>,
    limits: Limits,
    runtime: &mut DecodeRuntime<'_>,
) -> Result<usize> {
    decode_plan_with_execution_mode(
        input,
        plan,
        PlanExecutionMode::ComputeDirectAppend,
        dst,
        limits,
        runtime,
    )
}

pub(crate) fn decode_plan_with_cached_direct_append_plans(
    input: &[u8],
    plan: &FramePlan,
    direct_append_plans: &DirectAppendChunkPlans,
    dst: &mut Vec<u8>,
    limits: Limits,
    runtime: &mut DecodeRuntime<'_>,
) -> Result<usize> {
    decode_plan_with_execution_mode(
        input,
        plan,
        PlanExecutionMode::UseDirectAppend(direct_append_plans),
        dst,
        limits,
        runtime,
    )
}

pub(crate) fn decode_plan_with_cached_chunk_execution_plans(
    input: &[u8],
    plan: &FramePlan,
    chunk_execution_plans: &ChunkExecutionPlans,
    dst: &mut Vec<u8>,
    limits: Limits,
    runtime: &mut DecodeRuntime<'_>,
) -> Result<usize> {
    decode_plan_with_execution_mode(
        input,
        plan,
        PlanExecutionMode::UseChunkPlans(chunk_execution_plans),
        dst,
        limits,
        runtime,
    )
}

#[derive(Clone, Copy)]
enum PlanExecutionMode<'a> {
    ComputeDirectAppend,
    UseDirectAppend(&'a DirectAppendChunkPlans),
    UseChunkPlans(&'a ChunkExecutionPlans),
}

fn decode_plan_with_execution_mode(
    input: &[u8],
    plan: &FramePlan,
    mode: PlanExecutionMode<'_>,
    dst: &mut Vec<u8>,
    limits: Limits,
    runtime: &mut DecodeRuntime<'_>,
) -> Result<usize> {
    if let Some(written) = try_decode_single_zstd_into_dst(
        input,
        plan,
        dst,
        limits,
        #[cfg(feature = "zstd")]
        runtime.zstd,
    )? {
        return Ok(written);
    }
    if let PlanExecutionMode::UseDirectAppend(chunk_plans) = mode {
        return decode_plan_appending_to_dst_with_rollback(
            input,
            plan,
            chunk_plans,
            dst,
            limits,
            runtime,
        );
    }
    if matches!(mode, PlanExecutionMode::ComputeDirectAppend)
        && let Some(written) = try_decode_plan_appending_to_dst(input, plan, dst, limits, runtime)?
    {
        return Ok(written);
    }
    let chunk_execution_plans = match mode {
        PlanExecutionMode::UseChunkPlans(plans) => Some(plans),
        PlanExecutionMode::ComputeDirectAppend | PlanExecutionMode::UseDirectAppend(_) => None,
    };
    let decoded = collect_decoded_output(input, plan, limits, chunk_execution_plans, runtime)?;
    let mut chunks = decoded.chunks;
    if dst.is_empty() && chunks.len() == 1 {
        match chunks.pop().expect("single decoded chunk exists") {
            DecodedChunk::Owned(bytes) => {
                let written = bytes.len();
                *dst = bytes;
                return Ok(written);
            }
            borrowed @ DecodedChunk::Borrowed(_) => chunks.push(borrowed),
        }
    }
    dst.try_reserve_exact(decoded.total_len).map_err(|_| {
        Error::new(ErrorKind::LimitExceeded).with_detail("output allocation failed")
    })?;
    for chunk in chunks {
        dst.extend_from_slice(chunk.as_slice());
    }
    Ok(decoded.total_len)
}

fn try_decode_plan_appending_to_dst(
    input: &[u8],
    plan: &FramePlan,
    dst: &mut Vec<u8>,
    limits: Limits,
    runtime: &mut DecodeRuntime<'_>,
) -> Result<Option<usize>> {
    if plan.info.output_types.as_slice() != [FrameValueType::Serial] {
        return Ok(None);
    }
    let Some(chunk_plans) = prepare_direct_append_chunk_plans(plan)? else {
        return Ok(None);
    };
    decode_plan_appending_to_dst_with_rollback(input, plan, &chunk_plans, dst, limits, runtime)
        .map(Some)
}

fn decode_plan_appending_to_dst_with_rollback(
    input: &[u8],
    plan: &FramePlan,
    chunk_plans: &DirectAppendChunkPlans,
    dst: &mut Vec<u8>,
    limits: Limits,
    runtime: &mut DecodeRuntime<'_>,
) -> Result<usize> {
    if let Some(expected) = plan.info.output_sizes.first().and_then(|size| *size) {
        let expected = usize::try_from(expected).map_err(|_| {
            Error::new(ErrorKind::LimitExceeded).with_detail("decoded output size is too large")
        })?;
        dst.try_reserve_exact(expected).map_err(|_| {
            Error::new(ErrorKind::LimitExceeded).with_detail("output allocation failed")
        })?;
    }

    let start_len = dst.len();
    let result =
        decode_plan_appending_to_dst(input, plan, &chunk_plans.chunk_plans, dst, limits, runtime);
    match result {
        Ok(written) => Ok(written),
        Err(err) => {
            dst.truncate(start_len);
            Err(err)
        }
    }
}

fn decode_plan_appending_to_dst(
    input: &[u8],
    plan: &FramePlan,
    chunk_plans: &[Option<ChunkExecutionPlan>],
    dst: &mut Vec<u8>,
    limits: Limits,
    runtime: &mut DecodeRuntime<'_>,
) -> Result<usize> {
    let start_len = dst.len();
    let mut total_len = 0usize;
    if chunk_plans.len() != plan.chunks.len() {
        return Err(
            Error::new(ErrorKind::InvalidGraph).with_detail("chunk execution plan count mismatch")
        );
    }
    for (chunk, chunk_plan) in plan.chunks.iter().zip(chunk_plans.iter()) {
        let chunk_start = dst.len();
        if chunk.has_nodes() {
            if let Some(chunk_plan) = chunk_plan.as_ref() {
                decode_transform_chunk_appending(
                    input,
                    DirectAppendChunk {
                        chunk,
                        execution: chunk_plan,
                    },
                    plan.info.format_version,
                    limits,
                    dst,
                    plan.info.dictionary_bundle_id.as_deref(),
                    runtime,
                )?;
            } else {
                let decoded = decode_transform_chunk(
                    input,
                    chunk,
                    plan.info.format_version,
                    limits,
                    plan.info.dictionary_bundle_id.as_deref(),
                    runtime,
                )?;
                let decoded = decoded.as_slice();
                dst.try_reserve_exact(decoded.len()).map_err(|_| {
                    Error::new(ErrorKind::LimitExceeded).with_detail("output allocation failed")
                })?;
                dst.extend_from_slice(decoded);
            }
        } else {
            let stored = stored_only_chunk(input, chunk)?;
            dst.extend_from_slice(stored);
        }
        let decoded = &dst[chunk_start..];
        total_len = total_len
            .checked_add(decoded.len())
            .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
        #[cfg(not(feature = "checksum"))]
        let _ = chunk.decoded_checksum;
        #[cfg(feature = "checksum")]
        verify_decoded_checksum(decoded, chunk.decoded_checksum)?;
    }
    check_output_size(total_len, input.len(), plan, limits)?;
    Ok(dst.len() - start_len)
}

fn collect_decoded_output<'a>(
    input: &'a [u8],
    plan: &FramePlan,
    limits: Limits,
    chunk_execution_plans: Option<&ChunkExecutionPlans>,
    runtime: &mut DecodeRuntime<'_>,
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
    let cached_chunk_plans = if let Some(plans) = chunk_execution_plans {
        if plans.chunk_plans.len() != plan.chunks.len() {
            return Err(Error::new(ErrorKind::InvalidGraph)
                .with_detail("chunk execution plan count mismatch"));
        }
        Some(plans.chunk_plans.as_slice())
    } else {
        None
    };
    for (chunk_index, chunk) in plan.chunks.iter().enumerate() {
        let decoded = if chunk.has_nodes() {
            if let Some(chunk_plans) = cached_chunk_plans {
                let chunk_plan = chunk_plans[chunk_index].as_ref().ok_or_else(|| {
                    Error::new(ErrorKind::InvalidGraph)
                        .with_detail("chunk execution plan is missing")
                })?;
                decode_transform_chunk_with_plan(
                    input,
                    chunk,
                    chunk_plan,
                    plan.info.format_version,
                    limits,
                    plan.info.dictionary_bundle_id.as_deref(),
                    runtime,
                )?
            } else {
                decode_transform_chunk(
                    input,
                    chunk,
                    plan.info.format_version,
                    limits,
                    plan.info.dictionary_bundle_id.as_deref(),
                    runtime,
                )?
            }
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

fn decode_transform_chunk<'a>(
    input: &'a [u8],
    chunk: &crate::parse::ChunkPlan,
    format_version: u32,
    limits: Limits,
    dictionary_bundle_id: Option<&[u8]>,
    runtime: &mut DecodeRuntime<'_>,
) -> Result<DecodedChunk<'a>> {
    let plan = build_chunk_execution_plan(chunk)?;
    decode_transform_chunk_with_plan(
        input,
        chunk,
        &plan,
        format_version,
        limits,
        dictionary_bundle_id,
        runtime,
    )
}

fn decode_transform_chunk_with_plan<'a>(
    input: &'a [u8],
    chunk: &crate::parse::ChunkPlan,
    plan: &ChunkExecutionPlan,
    format_version: u32,
    limits: Limits,
    dictionary_bundle_id: Option<&[u8]>,
    runtime: &mut DecodeRuntime<'_>,
) -> Result<DecodedChunk<'a>> {
    let mut streams = initialize_stream_slots(input, chunk, &plan.regen_targets)?;
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
        let header = node_header(transform_headers, node.header_start, node.header_size)?;
        if try_execute_single_input_splitn_node(&mut streams, node, header, limits)? {
            continue;
        }
        if try_execute_byte_preserving_conversion_node(&mut streams, node, header, limits)? {
            continue;
        }

        let inputs = collect_node_inputs(&streams, node.input_start, node.input_count)?;
        let outputs = if node.standard_id == standard::SPARSE_NUM_ID {
            one_typed(sparse_num::decode_node(&inputs, header, ctx.limits))?
        } else {
            execute_standard_node(
                node.standard_id,
                &inputs,
                node.variable_inputs,
                node.dict_index,
                header,
                &mut ctx,
            )?
        };
        drop(inputs);
        recycle_consumed_owned_streams(
            &mut streams,
            node.input_start,
            node.input_count,
            ctx.scratch,
        )?;
        if outputs.len() != node.output_targets.len() {
            return Err(Error::new(ErrorKind::InvalidGraph)
                .with_detail("node output count does not match graph"));
        }
        for (output, &output_target) in outputs.into_iter().zip(node.output_targets.iter()) {
            let target = streams.get_mut(output_target).ok_or_else(|| {
                Error::new(ErrorKind::InvalidGraph)
                    .with_detail("node output target is out of bounds")
            })?;
            if !matches!(target, StreamSlot::Empty) {
                return Err(Error::new(ErrorKind::InvalidGraph)
                    .with_detail("node output overwrites an existing stream"));
            }
            *target = StreamSlot::Owned(output);
        }
    }

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

fn decode_transform_chunk_appending(
    input: &[u8],
    chunk: DirectAppendChunk<'_>,
    format_version: u32,
    limits: Limits,
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
        let header = node_header(transform_headers, node.header_start, node.header_size)?;
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
            return Ok(dst.len() - output_start);
        }
        if try_execute_single_input_splitn_node(&mut streams, node, header, limits)? {
            continue;
        }
        if try_execute_byte_preserving_conversion_node(&mut streams, node, header, limits)? {
            continue;
        }

        let inputs = collect_node_inputs(&streams, node.input_start, node.input_count)?;
        let outputs = if node.standard_id == standard::SPARSE_NUM_ID {
            one_typed(sparse_num::decode_node(&inputs, header, ctx.limits))?
        } else {
            execute_standard_node(
                node.standard_id,
                &inputs,
                node.variable_inputs,
                node.dict_index,
                header,
                &mut ctx,
            )?
        };
        drop(inputs);
        recycle_consumed_owned_streams(
            &mut streams,
            node.input_start,
            node.input_count,
            ctx.scratch,
        )?;
        if outputs.len() != node.output_targets.len() {
            return Err(Error::new(ErrorKind::InvalidGraph)
                .with_detail("node output count does not match graph"));
        }
        for (output, &output_target) in outputs.into_iter().zip(node.output_targets.iter()) {
            let target = streams.get_mut(output_target).ok_or_else(|| {
                Error::new(ErrorKind::InvalidGraph)
                    .with_detail("node output target is out of bounds")
            })?;
            if !matches!(target, StreamSlot::Empty) {
                return Err(Error::new(ErrorKind::InvalidGraph)
                    .with_detail("node output overwrites an existing stream"));
            }
            *target = StreamSlot::Owned(output);
        }
    }

    Err(Error::new(ErrorKind::InvalidGraph).with_detail("direct-append tail was not executed"))
}

#[derive(Clone, Copy)]
struct DirectAppendChunk<'a> {
    chunk: &'a crate::parse::ChunkPlan,
    execution: &'a ChunkExecutionPlan,
}

#[derive(Clone, Copy)]
struct DirectAppendTail {
    start: usize,
    kind: DirectAppendKind,
}

#[derive(Clone, Copy)]
enum DirectAppendKind {
    Lz,
    FieldLz,
    Zstd,
    DispatchStringToSerial,
    SplitByStructToSplitN,
}

fn direct_append_tail(plan: &ChunkExecutionPlan) -> Option<DirectAppendTail> {
    field_lz_append_tail_start(plan)
        .or_else(|| zstd_append_tail_start(plan))
        .or_else(|| dispatch_string_to_serial_append_tail(plan))
        .or_else(|| split_by_struct_to_splitn_append_tail(plan))
        .or_else(|| lz_append_tail_start(plan))
}

fn lz_append_tail_start(plan: &ChunkExecutionPlan) -> Option<DirectAppendTail> {
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

fn field_lz_append_tail_start(plan: &ChunkExecutionPlan) -> Option<DirectAppendTail> {
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

fn zstd_append_tail_start(plan: &ChunkExecutionPlan) -> Option<DirectAppendTail> {
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

fn validate_direct_append_tail(
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

fn validate_string_to_serial_tail(
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

fn append_split_by_struct_to_final_splitn(
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
            streams
                .get(stream_index)
                .ok_or_else(|| {
                    Error::new(ErrorKind::InvalidGraph)
                        .with_detail("node input range is out of bounds")
                })?
                .as_input()?
                .bytes
                .len()
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

fn try_execute_single_input_splitn_node(
    streams: &mut [StreamSlot<'_>],
    node: &NodeExecutionPlan,
    header: &[u8],
    limits: Limits,
) -> Result<bool> {
    if !matches!(
        node.standard_id,
        standard::SPLITN_ID | standard::SPLITN_STRUCT_ID | standard::SPLITN_NUM_ID
    ) || node.input_count != 1
    {
        return Ok(false);
    }
    if !header.is_empty() {
        return Err(
            Error::new(ErrorKind::Unsupported).with_detail("splitn headers are unsupported")
        );
    }

    let input = single_execution_input(streams, node.input_start)?;
    if input.element_width == 0 {
        return Err(Error::new(ErrorKind::InvalidType).with_detail("splitn element width is zero"));
    }
    if !input.bytes.len().is_multiple_of(input.element_width) {
        return Err(
            Error::new(ErrorKind::Malformed).with_detail("splitn input has partial element")
        );
    }
    if input.bytes.len() > limits.max_decoded_bytes || input.bytes.len() > limits.max_buffer_bytes {
        return Err(
            Error::new(ErrorKind::LimitExceeded).with_detail("decoded output limit exceeded")
        );
    }
    let output_width = if node.standard_id == standard::SPLITN_ID {
        1
    } else {
        input.element_width
    };
    move_stream_to_single_output(streams, node, output_width)
}

fn try_execute_byte_preserving_conversion_node(
    streams: &mut [StreamSlot<'_>],
    node: &NodeExecutionPlan,
    header: &[u8],
    limits: Limits,
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
    move_stream_to_single_output(streams, node, output_width)
}

fn move_stream_to_single_output(
    streams: &mut [StreamSlot<'_>],
    node: &NodeExecutionPlan,
    output_width: usize,
) -> Result<bool> {
    let [output_target] = node.output_targets.as_slice() else {
        return Err(Error::new(ErrorKind::InvalidGraph)
            .with_detail("node output count does not match graph"));
    };
    if !matches!(streams.get(*output_target), Some(StreamSlot::Empty)) {
        return Err(Error::new(ErrorKind::InvalidGraph)
            .with_detail("node output overwrites an existing stream"));
    }

    let input_slot = streams
        .get_mut(node.input_start)
        .ok_or_else(|| Error::new(ErrorKind::InvalidGraph).with_detail("node input is missing"))?;
    let converted = match core::mem::replace(input_slot, StreamSlot::Empty) {
        StreamSlot::Borrowed(mut stream) => {
            stream.element_width = output_width;
            StreamSlot::Borrowed(stream)
        }
        StreamSlot::Owned(mut stream) => {
            stream.element_width = output_width;
            stream.string_lengths = None;
            StreamSlot::Owned(stream)
        }
        StreamSlot::Empty => {
            return Err(
                Error::new(ErrorKind::InvalidGraph).with_detail("node input stream is missing")
            );
        }
    };
    streams[*output_target] = converted;
    Ok(true)
}

fn is_byte_preserving_conversion(standard_id: u32) -> bool {
    matches!(
        standard_id,
        standard::CONVERT_SERIAL_TO_STRUCT_ID
            | standard::CONVERT_STRUCT_TO_SERIAL_ID
            | standard::CONVERT_STRING_TO_SERIAL_ID
            | standard::CONVERT_STRUCT_TO_NUM_LE_ID
            | standard::CONVERT_NUM_TO_STRUCT_LE_ID
            | standard::CONVERT_SERIAL_TO_NUM_LE_ID
            | standard::CONVERT_NUM_TO_SERIAL_LE_ID
    )
}

fn single_execution_input<'a>(
    streams: &'a [StreamSlot<'a>],
    input_start: usize,
) -> Result<StreamInput<'a>> {
    streams
        .get(input_start)
        .ok_or_else(|| Error::new(ErrorKind::InvalidGraph).with_detail("node input is missing"))?
        .as_input()
}

fn byte_preserving_conversion_output_width(
    standard_id: u32,
    input_count: usize,
    input: StreamInput<'_>,
    header: &[u8],
    limits: Limits,
) -> Result<Option<usize>> {
    let output_width = match standard_id {
        standard::CONVERT_SERIAL_TO_STRUCT_ID => {
            if !header.is_empty() {
                return Err(Error::new(ErrorKind::Unsupported)
                    .with_detail("conversion headers are unsupported"));
            }
            input.element_width
        }
        standard::CONVERT_STRUCT_TO_SERIAL_ID => {
            let element_width = read_single_conversion_width(header)?;
            if !input.bytes.len().is_multiple_of(element_width) {
                return Err(Error::new(ErrorKind::Malformed)
                    .with_detail("serial stream size is not a multiple of struct width"));
            }
            element_width
        }
        standard::CONVERT_STRUCT_TO_NUM_LE_ID | standard::CONVERT_NUM_TO_STRUCT_LE_ID => {
            if !header.is_empty() {
                return Err(Error::new(ErrorKind::Unsupported)
                    .with_detail("convert_num_to_struct_le headers are unsupported"));
            }
            input.element_width
        }
        standard::CONVERT_STRING_TO_SERIAL_ID => {
            if !header.is_empty() {
                return Err(Error::new(ErrorKind::Malformed)
                    .with_detail("convert_string_to_serial header must be empty"));
            }
            if input.element_width != 1 {
                return Err(Error::new(ErrorKind::InvalidType)
                    .with_detail("convert_string_to_serial input must be byte strings"));
            }
            let lengths = input.string_lengths.ok_or_else(|| {
                Error::new(ErrorKind::InvalidType)
                    .with_detail("convert_string_to_serial input is missing string lengths")
            })?;
            if checked_sum_u32(lengths)? != input.bytes.len() {
                return Err(Error::new(ErrorKind::Malformed)
                    .with_detail("convert_string_to_serial lengths do not sum to content size"));
            }
            1
        }
        standard::CONVERT_SERIAL_TO_NUM_LE_ID => {
            if !header.is_empty() {
                return Err(Error::new(ErrorKind::Unsupported)
                    .with_detail("convert_serial_to_num_le headers are unsupported"));
            }
            1
        }
        standard::CONVERT_NUM_TO_SERIAL_LE_ID => {
            let int_size = read_conversion_int_size(header, "convert_num_to_serial_le")?;
            if !input.bytes.len().is_multiple_of(int_size) {
                return Err(Error::new(ErrorKind::Malformed)
                    .with_detail("serial stream size is not a multiple of integer width"));
            }
            int_size
        }
        _ => return Ok(None),
    };
    if input_count != 1 {
        return Err(Error::new(ErrorKind::InvalidGraph)
            .with_detail("single-input transform received the wrong input count"));
    }
    if input.bytes.len() > limits.max_decoded_bytes || input.bytes.len() > limits.max_buffer_bytes {
        return Err(
            Error::new(ErrorKind::LimitExceeded).with_detail("decoded output limit exceeded")
        );
    }
    Ok(Some(output_width))
}

fn read_single_conversion_width(header: &[u8]) -> Result<usize> {
    let mut offset = 0usize;
    let element_width = read_var_u64(header, &mut offset)?;
    if offset != header.len() {
        return Err(Error::new(ErrorKind::Malformed)
            .with_detail("convert_struct_to_serial header has trailing bytes"));
    }
    let element_width = usize::try_from(element_width).map_err(|_| {
        Error::new(ErrorKind::LimitExceeded).with_detail("conversion element width is too large")
    })?;
    if element_width == 0 {
        return Err(Error::new(ErrorKind::Malformed)
            .with_detail("conversion element width must be nonzero"));
    }
    Ok(element_width)
}

fn read_conversion_int_size(header: &[u8], transform: &'static str) -> Result<usize> {
    let [int_log] = header else {
        return Err(Error::new(ErrorKind::Malformed)
            .with_detail(format!("{transform} header is malformed")));
    };
    if *int_log > 3 {
        return Err(Error::new(ErrorKind::Malformed)
            .with_detail(format!("{transform} integer width is invalid")));
    }
    1usize
        .checked_shl(u32::from(*int_log))
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))
}

fn validate_conversion_numeric_width(element_width: usize) -> Result<()> {
    match element_width {
        1 | 2 | 4 | 8 => Ok(()),
        _ => Err(Error::new(ErrorKind::InvalidType)
            .with_detail("conversion numeric width is unsupported")),
    }
}

#[derive(Clone)]
struct ChunkExecutionPlan {
    nodes: Vec<NodeExecutionPlan>,
    regen_targets: Vec<bool>,
}

#[derive(Clone)]
struct NodeExecutionPlan {
    standard_id: u32,
    input_start: usize,
    input_count: usize,
    output_targets: SmallVec<[usize; 2]>,
    variable_inputs: u32,
    dict_index: Option<u32>,
    header_start: usize,
    header_size: usize,
}

fn build_chunk_execution_plan(chunk: &crate::parse::ChunkPlan) -> Result<ChunkExecutionPlan> {
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

fn standard_node_input_count(standard_id: u32, variable_inputs: usize) -> Result<usize> {
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
        | standard::DISPATCH_N_BY_TAG_ID
        | standard::FLATPACK_ID
        | standard::SENTINEL_ID
        | standard::SEPARATE_STRING_COMPONENTS_ID
        | standard::FSE_V2_ID
        | standard::HUFFMAN_V2_ID
        | standard::QUANTIZE_OFFSETS_ID
        | standard::QUANTIZE_LENGTHS_ID
        | standard::PARTITION_ID
        | standard::TOKENIZE_FIXED_ID
        | standard::TOKENIZE_NUMERIC_ID
        | standard::TRANSPOSE_SPLIT2_ID
        | standard::PIVCO_HUFFMAN_ID
        | standard::MUX_LENGTHS_ID => 2,
        standard::TRANSPOSE_SPLIT4_ID | standard::LZ_ID => 4,
        standard::FIELD_LZ_ID => 5,
        standard::TRANSPOSE_SPLIT8_ID => 8,
        standard::DISPATCH_STRING_ID
        | standard::LZ4_ID
        | standard::ZSTD_ID
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
        | standard::DELTA_INT_ID
        | standard::DIVIDE_BY_ID
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

fn initialize_stream_slots<'a>(
    input: &'a [u8],
    chunk: &crate::parse::ChunkPlan,
    regen_targets: &[bool],
) -> Result<Vec<StreamSlot<'a>>> {
    let mut streams = Vec::new();
    streams
        .try_reserve_exact(regen_targets.len())
        .map_err(|_| {
            Error::new(ErrorKind::LimitExceeded).with_detail("stream table allocation failed")
        })?;
    streams.resize_with(regen_targets.len(), || StreamSlot::Empty);

    let mut stored_index = 0usize;
    for (stream_index, is_regen_target) in regen_targets.iter().copied().enumerate() {
        if is_regen_target {
            continue;
        }
        let range = chunk.stored_stream_range(stored_index).ok_or_else(|| {
            Error::new(ErrorKind::InvalidGraph).with_detail("stored stream slot is missing")
        })?;
        streams[stream_index] = StreamSlot::Borrowed(BorrowedStream {
            bytes: range.as_slice(input)?,
            element_width: 1,
        });
        stored_index = stored_index
            .checked_add(1)
            .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
    }
    if stored_index != chunk.stored_streams() {
        return Err(Error::new(ErrorKind::InvalidGraph)
            .with_detail("stored stream count does not match stream slots"));
    }
    Ok(streams)
}

fn collect_node_inputs<'a>(
    streams: &'a [StreamSlot<'a>],
    input_start: usize,
    input_count: usize,
) -> Result<SmallVec<[StreamInput<'a>; 8]>> {
    let input_end = input_start
        .checked_add(input_count)
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
    let input_slots = streams.get(input_start..input_end).ok_or_else(|| {
        Error::new(ErrorKind::InvalidGraph).with_detail("node input range is out of bounds")
    })?;
    let mut inputs = SmallVec::<[StreamInput<'a>; 8]>::new();
    inputs.try_reserve_exact(input_count).map_err(|_| {
        Error::new(ErrorKind::LimitExceeded).with_detail("node input allocation failed")
    })?;
    for slot in input_slots.iter().rev() {
        inputs.push(slot.as_input()?);
    }
    Ok(inputs)
}

fn node_header(headers: &[u8], start: usize, len: usize) -> Result<&[u8]> {
    let end = start
        .checked_add(len)
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
    headers.get(start..end).ok_or_else(|| {
        Error::new(ErrorKind::InvalidGraph).with_detail("node header is out of bounds")
    })
}

struct StandardNodeContext<'a> {
    format_version: u32,
    limits: Limits,
    scratch: &'a mut DecodeScratch,
    #[cfg_attr(not(feature = "zstd"), allow(dead_code))]
    dictionary_bundle_id: Option<&'a [u8]>,
    #[cfg_attr(not(feature = "zstd"), allow(dead_code))]
    dict_store: &'a mut DictionaryStore,
    #[cfg(feature = "zstd")]
    zstd: &'a mut zrip::DecompressContext,
}

fn execute_standard_node(
    standard_id: u32,
    inputs: &[StreamInput<'_>],
    variable_inputs: u32,
    dict_index: Option<u32>,
    header: &[u8],
    ctx: &mut StandardNodeContext<'_>,
) -> Result<SmallVec<[OwnedStream; 2]>> {
    if dict_index.is_some() && standard_id != standard::ZSTD_ID {
        return Err(Error::new(ErrorKind::Unsupported)
            .with_detail("only zstd dictionary-backed transforms are implemented"));
    }

    match standard_id {
        standard::CONCAT_SERIAL_ID | standard::CONCAT_NUM_ID | standard::CONCAT_STRUCT_ID => {
            decode_concat_node(inputs, header, ctx.limits).map(SmallVec::from_vec)
        }
        standard::SPLITN_ID => one_serial(decode_splitn_node(
            inputs,
            variable_inputs,
            header,
            ctx.limits,
        )),
        standard::SPLITN_STRUCT_ID | standard::SPLITN_NUM_ID => one_typed(
            decode_splitn_typed_node(inputs, variable_inputs, header, ctx.limits),
        ),
        standard::SPLIT_BY_STRUCT_ID => one_typed(decode_split_by_struct_node(
            inputs,
            variable_inputs,
            header,
            ctx.limits,
        )),
        standard::FLATPACK_ID => one_serial(decode_flatpack_node(inputs, header, ctx.limits)),
        standard::SEPARATE_STRING_COMPONENTS_ID => one_typed(
            decode_separate_string_components_node(inputs, header, ctx.limits),
        ),
        standard::CONVERT_STRING_TO_SERIAL_ID => one_serial(decode_string_to_serial_node(
            single_stream(inputs)?,
            header,
            ctx.limits,
        )),
        standard::DISPATCH_STRING_ID => one_typed(decode_dispatch_string_node(
            inputs,
            variable_inputs,
            header,
            ctx.format_version,
            ctx.limits,
        )),
        standard::DISPATCH_N_BY_TAG_ID => one_serial(decode_dispatch_n_by_tag_node(
            inputs,
            variable_inputs,
            header,
            ctx.format_version,
            ctx.limits,
        )),
        standard::SENTINEL_ID => one_typed(decode_sentinel_node(inputs, header, ctx.limits)),
        id if is_transpose_split(id) => one_typed(decode_transpose_split_node(
            inputs,
            variable_inputs,
            header,
            ctx.limits,
            ctx.scratch,
        )),
        standard::LZ4_ID => one_serial(decode_lz4_chunk(single_input(inputs)?, header, ctx.limits)),
        standard::ZSTD_ID => one_serial(decode_zstd_chunk(
            single_input(inputs)?,
            header,
            dict_index,
            ctx,
        )),
        standard::BITPACK_SERIAL_ID => one_serial(decode_bitpack_serial_chunk(
            single_input(inputs)?,
            header,
            ctx.limits,
            ctx.scratch,
        )),
        standard::BITPACK_INT_ID => one_typed(decode_bitpack_int_chunk(
            single_input(inputs)?,
            header,
            ctx.limits,
            ctx.scratch,
        )),
        standard::CONSTANT_SERIAL_ID => one_serial(decode_constant_serial_chunk(
            single_input(inputs)?,
            header,
            ctx.limits,
        )),
        standard::CONSTANT_FIXED_ID => one_typed(decode_constant_fixed_chunk(
            single_stream(inputs)?,
            header,
            ctx.limits,
        )),
        standard::CONVERT_SERIAL_TO_STRUCT_ID => one_typed(
            decode_byte_preserving_conversion_chunk(single_stream(inputs)?, header, ctx.limits),
        ),
        standard::CONVERT_STRUCT_TO_SERIAL_ID => one_typed(decode_serial_to_struct_chunk(
            single_stream(inputs)?,
            header,
            ctx.limits,
        )),
        standard::CONVERT_STRUCT_TO_NUM_LE_ID | standard::CONVERT_NUM_TO_STRUCT_LE_ID => one_typed(
            decode_num_to_struct_le_chunk(single_stream(inputs)?, header, ctx.limits),
        ),
        standard::CONVERT_STRUCT_TO_NUM_BE_ID => one_typed(decode_struct_to_num_be_chunk(
            single_stream(inputs)?,
            header,
            ctx.limits,
        )),
        standard::CONVERT_SERIAL_TO_NUM_BE_ID => one_typed(decode_serial_to_num_be_chunk(
            single_stream(inputs)?,
            header,
            ctx.limits,
        )),
        standard::CONVERT_SERIAL_TO_NUM_LE_ID => one_serial(decode_numeric_to_serial_le_chunk(
            single_stream(inputs)?,
            header,
            ctx.limits,
        )),
        standard::CONVERT_NUM_TO_SERIAL_LE_ID => one_typed(decode_serial_to_numeric_le_chunk(
            single_stream(inputs)?,
            header,
            ctx.limits,
        )),
        standard::MUX_LENGTHS_ID => {
            decode_mux_lengths_node(inputs, header, ctx.limits).map(SmallVec::from_vec)
        }
        standard::LZ_ID => one_serial(decode_lz_node(inputs, header, ctx.limits)),
        standard::FIELD_LZ_ID => one_typed(decode_field_lz_node(
            inputs,
            header,
            ctx.limits,
            ctx.scratch,
        )),
        standard::ZIGZAG_ID => one_typed(decode_zigzag_numeric_chunk(
            single_stream(inputs)?,
            header,
            ctx.limits,
        )),
        standard::DELTA_INT_ID => one_typed(decode_delta_node(
            single_stream(inputs)?,
            header,
            ctx.limits,
            ctx.scratch,
        )),
        standard::DIVIDE_BY_ID => one_typed(decode_divide_by_node(
            single_stream(inputs)?,
            header,
            ctx.limits,
        )),
        standard::BITUNPACK_ID => one_serial(decode_bitunpack_serial8_chunk(
            single_input(inputs)?,
            header,
            ctx.limits,
        )),
        standard::BIT_SPLIT_ID => one_typed(decode_bitsplit_node(
            inputs,
            variable_inputs,
            header,
            ctx.limits,
        )),
        standard::RANGE_PACK_ID => one_serial(decode_range_pack_serial8_chunk(
            single_input(inputs)?,
            header,
            ctx.limits,
        )),
        standard::PARSE_INT_ID => one_typed(parse_int::decode_node(
            single_stream(inputs)?,
            header,
            ctx.limits,
        )),
        standard::FSE_NCOUNT_ID => one_typed(decode_fse_ncount_node(
            single_stream(inputs)?,
            header,
            ctx.limits,
        )),
        standard::FSE_V2_ID => one_serial(decode_fse_v2_node(inputs, header, ctx.limits)),
        standard::HUFFMAN_V2_ID => one_serial(decode_huffman_v2_node(inputs, header, ctx.limits)),
        standard::PIVCO_HUFFMAN_ID => {
            one_serial(pivco_huffman::decode_node(inputs, header, ctx.limits))
        }
        standard::QUANTIZE_OFFSETS_ID => one_typed(decode_quantize_node(
            inputs,
            header,
            ctx.limits,
            &QUANTIZE_OFFSETS,
        )),
        standard::QUANTIZE_LENGTHS_ID => one_typed(decode_quantize_node(
            inputs,
            header,
            ctx.limits,
            &QUANTIZE_LENGTHS,
        )),
        standard::PARTITION_ID => one_typed(decode_partition_node(inputs, header, ctx.limits)),
        standard::TOKENIZE_FIXED_ID | standard::TOKENIZE_NUMERIC_ID => {
            one_typed(decode_tokenize_fixed_node(inputs, header, ctx.limits))
        }
        _ => Err(Error::new(ErrorKind::Unsupported)
            .with_detail("standard transform graph execution is not implemented yet")),
    }
}

fn one_serial(result: Result<Vec<u8>>) -> Result<SmallVec<[OwnedStream; 2]>> {
    Ok(smallvec![OwnedStream::serial(result?)])
}

fn one_typed(result: Result<OwnedStream>) -> Result<SmallVec<[OwnedStream; 2]>> {
    Ok(smallvec![result?])
}

fn single_input<'a>(inputs: &[StreamInput<'a>]) -> Result<&'a [u8]> {
    Ok(single_stream(inputs)?.bytes)
}

fn single_stream<'a>(inputs: &[StreamInput<'a>]) -> Result<StreamInput<'a>> {
    match inputs {
        [input] => Ok(*input),
        _ => Err(Error::new(ErrorKind::InvalidGraph)
            .with_detail("single-input transform received the wrong input count")),
    }
}

enum StreamSlot<'a> {
    Empty,
    Borrowed(BorrowedStream<'a>),
    Owned(OwnedStream),
}

impl<'a> StreamSlot<'a> {
    fn as_input(&'a self) -> Result<StreamInput<'a>> {
        match self {
            Self::Borrowed(stream) => Ok(StreamInput {
                bytes: stream.bytes,
                element_width: stream.element_width,
                string_lengths: None,
            }),
            Self::Owned(stream) => Ok(StreamInput {
                bytes: &stream.bytes,
                element_width: stream.element_width,
                string_lengths: stream.string_lengths.as_deref(),
            }),
            Self::Empty => {
                Err(Error::new(ErrorKind::InvalidGraph).with_detail("node input stream is missing"))
            }
        }
    }
}

fn recycle_consumed_owned_streams(
    streams: &mut [StreamSlot<'_>],
    input_start: usize,
    input_count: usize,
    scratch: &mut DecodeScratch,
) -> Result<()> {
    let input_end = input_start
        .checked_add(input_count)
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
    let input_slots = streams.get_mut(input_start..input_end).ok_or_else(|| {
        Error::new(ErrorKind::InvalidGraph).with_detail("node input range is out of bounds")
    })?;
    for slot in input_slots {
        if let StreamSlot::Owned(stream) = core::mem::replace(slot, StreamSlot::Empty) {
            scratch.recycle_owned_stream(stream);
        }
    }
    Ok(())
}

#[derive(Clone, Copy)]
struct BorrowedStream<'a> {
    bytes: &'a [u8],
    element_width: usize,
}

#[derive(Clone, Copy)]
struct StreamInput<'a> {
    bytes: &'a [u8],
    element_width: usize,
    string_lengths: Option<&'a [u32]>,
}

#[derive(Debug)]
struct OwnedStream {
    bytes: Vec<u8>,
    element_width: usize,
    string_lengths: Option<Vec<u32>>,
    recyclable: bool,
}

impl OwnedStream {
    fn serial(bytes: Vec<u8>) -> Self {
        Self {
            bytes,
            element_width: 1,
            string_lengths: None,
            recyclable: false,
        }
    }

    fn typed(bytes: Vec<u8>, element_width: usize) -> Self {
        Self {
            bytes,
            element_width,
            string_lengths: None,
            recyclable: false,
        }
    }

    fn pooled(bytes: Vec<u8>, element_width: usize) -> Self {
        Self {
            bytes,
            element_width,
            string_lengths: None,
            recyclable: true,
        }
    }
}

fn decode_concat_node(
    inputs: &[StreamInput<'_>],
    header: &[u8],
    limits: Limits,
) -> Result<Vec<OwnedStream>> {
    if !header.is_empty() {
        return Err(Error::new(ErrorKind::Unsupported)
            .with_detail("concat transform headers are unsupported"));
    }
    let [sizes, concatenated] = inputs else {
        return Err(Error::new(ErrorKind::InvalidGraph)
            .with_detail("concat input count does not match node shape"));
    };
    let output_count = concat_size_count(sizes)?;
    if concatenated.element_width == 0 {
        return Err(Error::new(ErrorKind::InvalidType).with_detail("concat element width is zero"));
    }
    if !concatenated
        .bytes
        .len()
        .is_multiple_of(concatenated.element_width)
    {
        return Err(
            Error::new(ErrorKind::Malformed).with_detail("concat input has partial element")
        );
    }
    if output_count == 0 {
        return Err(Error::new(ErrorKind::Malformed).with_detail("concat size table is empty"));
    }

    let total_elements = numeric_element_count(concatenated.bytes, concatenated.element_width)?;
    let mut consumed_elements = 0usize;
    let mut consumed_bytes = 0usize;
    let mut outputs = Vec::new();
    outputs.try_reserve_exact(output_count).map_err(|_| {
        Error::new(ErrorKind::LimitExceeded).with_detail("concat output allocation failed")
    })?;

    for output_index in 0..output_count {
        let output_elements = read_concat_size(sizes, output_index)?;
        let output_bytes = output_elements
            .checked_mul(concatenated.element_width)
            .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
        if output_bytes > limits.max_decoded_bytes || output_bytes > limits.max_buffer_bytes {
            return Err(
                Error::new(ErrorKind::LimitExceeded).with_detail("decoded output limit exceeded")
            );
        }
        let next_elements = consumed_elements
            .checked_add(output_elements)
            .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
        let next_bytes = consumed_bytes
            .checked_add(output_bytes)
            .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
        if next_elements > total_elements || next_bytes > concatenated.bytes.len() {
            return Err(Error::new(ErrorKind::Malformed).with_detail("concat size exceeds input"));
        }
        let mut output = Vec::new();
        output.try_reserve_exact(output_bytes).map_err(|_| {
            Error::new(ErrorKind::LimitExceeded).with_detail("concat allocation failed")
        })?;
        output.extend_from_slice(&concatenated.bytes[consumed_bytes..next_bytes]);
        outputs.push(OwnedStream {
            bytes: output,
            element_width: concatenated.element_width,
            string_lengths: None,
            recyclable: false,
        });
        consumed_elements = next_elements;
        consumed_bytes = next_bytes;
    }

    if consumed_elements != total_elements || consumed_bytes != concatenated.bytes.len() {
        return Err(
            Error::new(ErrorKind::Malformed).with_detail("concat sizes do not consume input")
        );
    }
    Ok(outputs)
}

fn concat_size_count(sizes: &StreamInput<'_>) -> Result<usize> {
    match sizes.element_width {
        1 | 4 => numeric_element_count(sizes.bytes, 4),
        _ => {
            Err(Error::new(ErrorKind::InvalidType).with_detail("concat sizes width is unsupported"))
        }
    }
}

fn read_concat_size(sizes: &StreamInput<'_>, index: usize) -> Result<usize> {
    match sizes.element_width {
        1 | 4 => read_usize_numeric_element(sizes.bytes, 4, index),
        _ => {
            Err(Error::new(ErrorKind::InvalidType).with_detail("concat sizes width is unsupported"))
        }
    }
}

fn is_transpose_split(id: u32) -> bool {
    id == standard::TRANSPOSE_SPLIT_ID || transpose_split_width(Some(id)).is_some()
}

fn transpose_split_width(id: Option<u32>) -> Option<usize> {
    match id {
        Some(standard::TRANSPOSE_SPLIT2_ID) => Some(2),
        Some(standard::TRANSPOSE_SPLIT4_ID) => Some(4),
        Some(standard::TRANSPOSE_SPLIT8_ID) => Some(8),
        _ => None,
    }
}

fn decode_transpose_split_node(
    inputs: &[StreamInput<'_>],
    variable_inputs: u32,
    header: &[u8],
    limits: Limits,
    scratch: &mut DecodeScratch,
) -> Result<OwnedStream> {
    if !header.is_empty() {
        return Err(Error::new(ErrorKind::Unsupported)
            .with_detail("transpose_split transform headers are unsupported"));
    }
    if variable_inputs != 0
        && usize::try_from(variable_inputs).is_ok_and(|count| count != inputs.len())
    {
        return Err(Error::new(ErrorKind::InvalidGraph)
            .with_detail("transpose_split variable input count does not match inputs"));
    }
    let Some(first) = inputs.first() else {
        return Err(Error::new(ErrorKind::InvalidGraph)
            .with_detail("transpose_split input count does not match width"));
    };
    let width = inputs.len();
    let lane_len = first.bytes.len();
    let output_len = lane_len.checked_mul(width).ok_or_else(|| {
        Error::new(ErrorKind::IntegerOverflow).with_detail("transpose size overflowed")
    })?;
    if output_len > limits.max_decoded_bytes || output_len > limits.max_buffer_bytes {
        return Err(
            Error::new(ErrorKind::LimitExceeded).with_detail("decoded output limit exceeded")
        );
    }
    for lane in inputs {
        if lane.bytes.len() != lane_len {
            return Err(Error::new(ErrorKind::Malformed)
                .with_detail("transpose_split lanes have different sizes"));
        }
    }
    let mut output = scratch.take_byte_buffer(output_len, "transpose allocation failed")?;
    fast_transpose::write_transpose_split_output(inputs, output_len, &mut output);
    Ok(OwnedStream::pooled(output, width))
}

fn decode_flatpack_node(
    inputs: &[StreamInput<'_>],
    header: &[u8],
    limits: Limits,
) -> Result<Vec<u8>> {
    if !header.is_empty() {
        return Err(Error::new(ErrorKind::Unsupported)
            .with_detail("flatpack transform headers are unsupported"));
    }
    let [alphabet, packed] = inputs else {
        return Err(Error::new(ErrorKind::InvalidGraph)
            .with_detail("flatpack input count does not match node shape"));
    };
    decode_flatpack_serial(alphabet.bytes, packed.bytes, limits)
}

fn decode_separate_string_components_node(
    inputs: &[StreamInput<'_>],
    header: &[u8],
    limits: Limits,
) -> Result<OwnedStream> {
    if !header.is_empty() {
        return Err(Error::new(ErrorKind::Malformed)
            .with_detail("separate_string_components header must be empty"));
    }
    let [content, field_sizes] = inputs else {
        return Err(Error::new(ErrorKind::InvalidGraph)
            .with_detail("separate_string_components input count does not match node shape"));
    };
    if content.element_width != 1 {
        return Err(Error::new(ErrorKind::InvalidType)
            .with_detail("separate_string_components content must be serial bytes"));
    }
    validate_numeric_stream_width(field_sizes.element_width, "string field sizes")?;
    let field_count = numeric_element_count(field_sizes.bytes, field_sizes.element_width)?;
    let (string_lengths, total) = decode_string_component_lengths(field_sizes, field_count)?;
    if total != content.bytes.len() {
        return Err(Error::new(ErrorKind::Malformed)
            .with_detail("string field sizes do not sum to content size"));
    }
    if content.bytes.len() > limits.max_decoded_bytes
        || content.bytes.len() > limits.max_buffer_bytes
    {
        return Err(
            Error::new(ErrorKind::LimitExceeded).with_detail("decoded output limit exceeded")
        );
    }
    let mut output = Vec::new();
    output.try_reserve_exact(content.bytes.len()).map_err(|_| {
        Error::new(ErrorKind::LimitExceeded).with_detail("string component allocation failed")
    })?;
    output.extend_from_slice(content.bytes);
    Ok(OwnedStream {
        bytes: output,
        element_width: 1,
        string_lengths: Some(string_lengths),
        recyclable: false,
    })
}

fn decode_string_component_lengths(
    field_sizes: &StreamInput<'_>,
    field_count: usize,
) -> Result<(Vec<u32>, usize)> {
    let mut string_lengths = Vec::new();
    string_lengths.try_reserve_exact(field_count).map_err(|_| {
        Error::new(ErrorKind::LimitExceeded).with_detail("string length allocation failed")
    })?;
    let mut total = 0usize;
    match field_sizes.element_width {
        1 => {
            fast_lengths::decode_u8_lengths(field_sizes.bytes, &mut string_lengths, &mut total)?;
        }
        2 => {
            for size in field_sizes.bytes.chunks_exact(2) {
                let size = u16::from_le_bytes([size[0], size[1]]);
                total = total
                    .checked_add(usize::from(size))
                    .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
                string_lengths.push(u32::from(size));
            }
        }
        4 => {
            for size in field_sizes.bytes.chunks_exact(4) {
                let size = u32::from_le_bytes([size[0], size[1], size[2], size[3]]);
                let size_usize = usize::try_from(size).map_err(|_| {
                    Error::new(ErrorKind::LimitExceeded)
                        .with_detail("string field size is too large")
                })?;
                total = total
                    .checked_add(size_usize)
                    .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
                string_lengths.push(size);
            }
        }
        8 => {
            for index in 0..field_count {
                let size = read_usize_numeric_element(
                    field_sizes.bytes,
                    field_sizes.element_width,
                    index,
                )?;
                total = total
                    .checked_add(size)
                    .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
                string_lengths.push(u32::try_from(size).map_err(|_| {
                    Error::new(ErrorKind::LimitExceeded)
                        .with_detail("string field size is too large")
                })?);
            }
        }
        _ => unreachable!("validate_numeric_stream_width accepted only supported widths"),
    }
    Ok((string_lengths, total))
}

fn decode_string_to_serial_node(
    input: StreamInput<'_>,
    header: &[u8],
    limits: Limits,
) -> Result<Vec<u8>> {
    if !header.is_empty() {
        return Err(Error::new(ErrorKind::Malformed)
            .with_detail("convert_string_to_serial header must be empty"));
    }
    if input.element_width != 1 {
        return Err(Error::new(ErrorKind::InvalidType)
            .with_detail("convert_string_to_serial input must be byte strings"));
    }
    let lengths = input.string_lengths.ok_or_else(|| {
        Error::new(ErrorKind::InvalidType)
            .with_detail("convert_string_to_serial input is missing string lengths")
    })?;
    if checked_sum_u32(lengths)? != input.bytes.len() {
        return Err(Error::new(ErrorKind::Malformed)
            .with_detail("convert_string_to_serial lengths do not sum to content size"));
    }
    if input.bytes.len() > limits.max_decoded_bytes || input.bytes.len() > limits.max_buffer_bytes {
        return Err(
            Error::new(ErrorKind::LimitExceeded).with_detail("decoded output limit exceeded")
        );
    }
    let mut output = Vec::new();
    output.try_reserve_exact(input.bytes.len()).map_err(|_| {
        Error::new(ErrorKind::LimitExceeded).with_detail("conversion allocation failed")
    })?;
    output.extend_from_slice(input.bytes);
    Ok(output)
}

fn decode_sentinel_node(
    inputs: &[StreamInput<'_>],
    header: &[u8],
    limits: Limits,
) -> Result<OwnedStream> {
    let [values, exceptions] = inputs else {
        return Err(Error::new(ErrorKind::InvalidGraph)
            .with_detail("sentinel input count does not match node shape"));
    };
    validate_numeric_stream_width(values.element_width, "sentinel values")?;
    validate_numeric_stream_width(exceptions.element_width, "sentinel exceptions")?;
    if values.element_width > exceptions.element_width {
        return Err(Error::new(ErrorKind::Malformed)
            .with_detail("sentinel values width exceeds output width"));
    }
    let max_value = max_numeric_value(values.element_width)?;
    let sentinel =
        if header.is_empty() {
            max_value
        } else {
            let mut offset = 0usize;
            let value = read_var_u64(header, &mut offset)?;
            if offset != header.len() {
                return Err(Error::new(ErrorKind::Malformed)
                    .with_detail("sentinel header has trailing bytes"));
            }
            if value > max_value {
                return Err(Error::new(ErrorKind::Malformed)
                    .with_detail("sentinel value exceeds values width"));
            }
            value
        };
    let value_count = numeric_element_count(values.bytes, values.element_width)?;
    let exception_count = numeric_element_count(exceptions.bytes, exceptions.element_width)?;
    let output_len = value_count
        .checked_mul(exceptions.element_width)
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
    if output_len > limits.max_decoded_bytes || output_len > limits.max_buffer_bytes {
        return Err(
            Error::new(ErrorKind::LimitExceeded).with_detail("decoded output limit exceeded")
        );
    }
    let mut output = Vec::new();
    output.try_reserve_exact(output_len).map_err(|_| {
        Error::new(ErrorKind::LimitExceeded).with_detail("sentinel allocation failed")
    })?;
    output.resize(output_len, 0);
    let mut exception_index = 0usize;
    for value_index in 0..value_count {
        let value = read_numeric_element(values.bytes, values.element_width, value_index)?;
        let output_offset = value_index
            .checked_mul(exceptions.element_width)
            .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
        if value == sentinel {
            if exception_index >= exception_count {
                return Err(Error::new(ErrorKind::Malformed)
                    .with_detail("sentinel exception stream is exhausted"));
            }
            let exception =
                read_numeric_element(exceptions.bytes, exceptions.element_width, exception_index)?;
            write_numeric_element(
                &mut output[output_offset..],
                exceptions.element_width,
                exception,
            );
            exception_index = exception_index
                .checked_add(1)
                .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
        } else {
            write_numeric_element(
                &mut output[output_offset..],
                exceptions.element_width,
                value,
            );
        }
    }
    if exception_index != exception_count {
        return Err(Error::new(ErrorKind::Malformed)
            .with_detail("sentinel exception stream was not fully consumed"));
    }
    Ok(OwnedStream {
        bytes: output,
        element_width: exceptions.element_width,
        string_lengths: None,
        recyclable: false,
    })
}

fn max_numeric_value(element_width: usize) -> Result<u64> {
    match element_width {
        1 => Ok(u64::from(u8::MAX)),
        2 => Ok(u64::from(u16::MAX)),
        4 => Ok(u64::from(u32::MAX)),
        8 => Ok(u64::MAX),
        _ => Err(Error::new(ErrorKind::InvalidType).with_detail("numeric width is unsupported")),
    }
}

fn decode_flatpack_serial(alphabet: &[u8], packed: &[u8], limits: Limits) -> Result<Vec<u8>> {
    if alphabet.len() > 256 {
        return Err(Error::new(ErrorKind::Malformed).with_detail("flatpack alphabet is too large"));
    }
    if alphabet.is_empty() || packed.is_empty() {
        return Ok(Vec::new());
    }
    let bits = flatpack_bits(alphabet.len());
    let output_len = flatpack_output_len(bits, packed)?;
    if output_len > limits.max_decoded_bytes || output_len > limits.max_buffer_bytes {
        return Err(
            Error::new(ErrorKind::LimitExceeded).with_detail("decoded output limit exceeded")
        );
    }
    let mut output = Vec::new();
    output.try_reserve_exact(output_len).map_err(|_| {
        Error::new(ErrorKind::LimitExceeded).with_detail("flatpack allocation failed")
    })?;

    let mask = (1usize << bits) - 1;
    let mut packed_index = 0usize;
    let mut available_bits = 0usize;
    let mut state = 0usize;
    while output.len() < output_len {
        if available_bits < bits {
            let byte = *packed.get(packed_index).ok_or_else(|| {
                Error::new(ErrorKind::Malformed).with_detail("flatpack input is truncated")
            })?;
            packed_index += 1;
            state |= usize::from(byte) << available_bits;
            available_bits += 8;
        }
        let symbol_index = state & mask;
        let symbol = *alphabet.get(symbol_index).ok_or_else(|| {
            Error::new(ErrorKind::Malformed).with_detail("flatpack symbol index is out of bounds")
        })?;
        output.push(symbol);
        state >>= bits;
        available_bits -= bits;
    }
    if packed_index < packed.len() {
        state |= usize::from(packed[packed_index]) << available_bits;
        packed_index += 1;
        available_bits += 8;
    }
    if packed_index != packed.len() || state != 1 || available_bits > 8 {
        return Err(Error::new(ErrorKind::Malformed).with_detail("flatpack sentinel is malformed"));
    }
    Ok(output)
}

fn flatpack_bits(alphabet_len: usize) -> usize {
    if alphabet_len <= 1 {
        alphabet_len
    } else {
        usize::BITS as usize - (alphabet_len - 1).leading_zeros() as usize
    }
}

fn flatpack_output_len(bits: usize, packed: &[u8]) -> Result<usize> {
    let last = u32::from(
        *packed.last().ok_or_else(|| {
            Error::new(ErrorKind::Malformed).with_detail("flatpack input is empty")
        })? | 1,
    );
    let padding_bits = ((last << 24).leading_zeros() as usize)
        .checked_add(1)
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
    let packed_bits = packed
        .len()
        .checked_mul(8)
        .ok_or_else(|| {
            Error::new(ErrorKind::IntegerOverflow).with_detail("flatpack size overflowed")
        })?
        .checked_sub(padding_bits)
        .ok_or_else(|| {
            Error::new(ErrorKind::Malformed).with_detail("flatpack padding is malformed")
        })?;
    Ok(packed_bits / bits)
}

fn decode_splitn_node(
    inputs: &[StreamInput<'_>],
    variable_inputs: u32,
    header: &[u8],
    limits: Limits,
) -> Result<Vec<u8>> {
    Ok(decode_splitn_typed_node(inputs, variable_inputs, header, limits)?.bytes)
}

fn decode_splitn_typed_node(
    inputs: &[StreamInput<'_>],
    variable_inputs: u32,
    header: &[u8],
    limits: Limits,
) -> Result<OwnedStream> {
    let input_count = usize::try_from(variable_inputs)
        .map_err(|_| Error::new(ErrorKind::LimitExceeded).with_detail("too many splitn inputs"))?;
    if inputs.len() != input_count {
        return Err(Error::new(ErrorKind::InvalidGraph)
            .with_detail("splitn input count does not match node shape"));
    }
    if input_count == 0 {
        let element_width = splitn_empty_element_width(header)?;
        return Ok(OwnedStream {
            bytes: Vec::new(),
            element_width,
            string_lengths: None,
            recyclable: false,
        });
    }
    if !header.is_empty() {
        return Err(
            Error::new(ErrorKind::Unsupported).with_detail("splitn headers are unsupported")
        );
    }
    let element_width = inputs[0].element_width;
    if element_width == 0 {
        return Err(Error::new(ErrorKind::InvalidType).with_detail("splitn element width is zero"));
    }

    let mut total_len = 0usize;
    for input in inputs {
        if input.element_width != element_width {
            return Err(
                Error::new(ErrorKind::InvalidType).with_detail("splitn input widths must match")
            );
        }
        if !input.bytes.len().is_multiple_of(element_width) {
            return Err(
                Error::new(ErrorKind::Malformed).with_detail("splitn input has partial element")
            );
        }
        total_len = total_len.checked_add(input.bytes.len()).ok_or_else(|| {
            Error::new(ErrorKind::IntegerOverflow).with_detail("splitn size overflowed")
        })?;
    }
    if total_len > limits.max_decoded_bytes || total_len > limits.max_buffer_bytes {
        return Err(
            Error::new(ErrorKind::LimitExceeded).with_detail("decoded output limit exceeded")
        );
    }

    let mut output = Vec::new();
    output.try_reserve_exact(total_len).map_err(|_| {
        Error::new(ErrorKind::LimitExceeded).with_detail("splitn allocation failed")
    })?;
    for input in inputs {
        output.extend_from_slice(input.bytes);
    }
    Ok(OwnedStream {
        bytes: output,
        element_width,
        string_lengths: None,
        recyclable: false,
    })
}

fn splitn_empty_element_width(header: &[u8]) -> Result<usize> {
    if header.is_empty() {
        return Ok(1);
    }
    let mut offset = 0usize;
    let element_width = read_var_u64(header, &mut offset)?;
    if offset != header.len() {
        return Err(Error::new(ErrorKind::Malformed).with_detail("unexpected splitn header bytes"));
    }
    if element_width == 0 {
        return Err(
            Error::new(ErrorKind::Malformed).with_detail("splitn element width must be nonzero")
        );
    }
    usize::try_from(element_width)
        .map_err(|_| Error::new(ErrorKind::LimitExceeded).with_detail("splitn width is too large"))
}

fn decode_split_by_struct_node(
    inputs: &[StreamInput<'_>],
    variable_inputs: u32,
    header: &[u8],
    limits: Limits,
) -> Result<OwnedStream> {
    if !header.is_empty() {
        return Err(Error::new(ErrorKind::Unsupported)
            .with_detail("split_by_struct headers are unsupported"));
    }
    let input_count = usize::try_from(variable_inputs).map_err(|_| {
        Error::new(ErrorKind::LimitExceeded).with_detail("too many split_by_struct inputs")
    })?;
    if inputs.len() != input_count {
        return Err(Error::new(ErrorKind::InvalidGraph)
            .with_detail("split_by_struct input count does not match node shape"));
    }
    let output_len = split_by_struct_output_len(inputs)?;
    if output_len > limits.max_decoded_bytes || output_len > limits.max_buffer_bytes {
        return Err(
            Error::new(ErrorKind::LimitExceeded).with_detail("decoded output limit exceeded")
        );
    }
    let mut output = Vec::new();
    output.try_reserve_exact(output_len).map_err(|_| {
        Error::new(ErrorKind::LimitExceeded).with_detail("split_by_struct allocation failed")
    })?;
    append_split_by_struct_output(inputs, limits, &mut output)?;
    Ok(OwnedStream {
        bytes: output,
        element_width: 1,
        string_lengths: None,
        recyclable: false,
    })
}

fn split_by_struct_output_len(inputs: &[StreamInput<'_>]) -> Result<usize> {
    let Some(first) = inputs.first() else {
        return Err(Error::new(ErrorKind::Malformed).with_detail("split_by_struct requires inputs"));
    };
    if first.element_width == 0 {
        return Err(
            Error::new(ErrorKind::InvalidType).with_detail("split_by_struct field width is zero")
        );
    }
    if !first.bytes.len().is_multiple_of(first.element_width) {
        return Err(Error::new(ErrorKind::Malformed)
            .with_detail("split_by_struct input has partial element"));
    }

    let element_count = first.bytes.len() / first.element_width;
    let mut struct_width = 0usize;
    for input in inputs {
        if input.element_width == 0 {
            return Err(Error::new(ErrorKind::InvalidType)
                .with_detail("split_by_struct field width is zero"));
        }
        if !input.bytes.len().is_multiple_of(input.element_width) {
            return Err(Error::new(ErrorKind::Malformed)
                .with_detail("split_by_struct input has partial element"));
        }
        if input.bytes.len() / input.element_width != element_count {
            return Err(Error::new(ErrorKind::Malformed)
                .with_detail("split_by_struct inputs have mismatched element counts"));
        }
        struct_width = struct_width
            .checked_add(input.element_width)
            .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
    }
    let output_len = element_count
        .checked_mul(struct_width)
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
    Ok(output_len)
}

fn append_split_by_struct_output(
    inputs: &[StreamInput<'_>],
    limits: Limits,
    output: &mut Vec<u8>,
) -> Result<()> {
    let output_len = split_by_struct_output_len(inputs)?;
    if output_len > limits.max_decoded_bytes || output_len > limits.max_buffer_bytes {
        return Err(
            Error::new(ErrorKind::LimitExceeded).with_detail("decoded output limit exceeded")
        );
    }
    let required_capacity = output
        .len()
        .checked_add(output_len)
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
    if output.capacity() < required_capacity {
        output
            .try_reserve_exact(required_capacity - output.len())
            .map_err(|_| {
                Error::new(ErrorKind::LimitExceeded)
                    .with_detail("split_by_struct allocation failed")
            })?;
    }
    fast_split_struct::append_split_by_struct_output(inputs, output);
    Ok(())
}

fn decode_mux_lengths_node(
    inputs: &[StreamInput<'_>],
    header: &[u8],
    limits: Limits,
) -> Result<Vec<OwnedStream>> {
    let [muxed_lengths, long_lengths] = inputs else {
        return Err(Error::new(ErrorKind::InvalidGraph)
            .with_detail("mux_lengths input count does not match node shape"));
    };
    let [header_byte] = header else {
        return Err(Error::new(ErrorKind::Malformed).with_detail("mux_lengths header is malformed"));
    };
    if muxed_lengths.element_width != 1 {
        return Err(Error::new(ErrorKind::InvalidType)
            .with_detail("mux_lengths muxed input must be serial bytes"));
    }
    let element_width = long_lengths.element_width;
    if !matches!(element_width, 1 | 2 | 4 | 8) {
        return Err(Error::new(ErrorKind::InvalidType)
            .with_detail("mux_lengths long-length width is unsupported"));
    }
    if !long_lengths.bytes.len().is_multiple_of(element_width) {
        return Err(Error::new(ErrorKind::Malformed)
            .with_detail("mux_lengths long-length stream has partial element"));
    }
    let split_point = usize::from(header_byte & 0x0f);
    if split_point > 8 {
        return Err(
            Error::new(ErrorKind::Malformed).with_detail("mux_lengths split point is invalid")
        );
    }
    let match_length_bias = u64::from(header_byte >> 4);
    let ll_mask = if split_point == 64 {
        u64::MAX
    } else {
        (1u64 << split_point) - 1
    };
    let ml_mask = (1u64 << (8 - split_point)) - 1;
    let ml_max = match_length_bias
        .checked_add(ml_mask)
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
    let output_len = muxed_lengths
        .bytes
        .len()
        .checked_mul(element_width)
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
    if output_len > limits.max_decoded_bytes || output_len > limits.max_buffer_bytes {
        return Err(
            Error::new(ErrorKind::LimitExceeded).with_detail("decoded output limit exceeded")
        );
    }

    if element_width == 2 {
        return decode_mux_lengths_u16(
            muxed_lengths.bytes,
            long_lengths.bytes,
            split_point,
            ll_mask,
            match_length_bias,
            ml_max,
            output_len,
        );
    }

    let mut literal_lengths = Vec::new();
    literal_lengths.try_reserve_exact(output_len).map_err(|_| {
        Error::new(ErrorKind::LimitExceeded).with_detail("mux_lengths allocation failed")
    })?;
    literal_lengths.resize(output_len, 0);
    let mut match_lengths = Vec::new();
    match_lengths.try_reserve_exact(output_len).map_err(|_| {
        Error::new(ErrorKind::LimitExceeded).with_detail("mux_lengths allocation failed")
    })?;
    match_lengths.resize(output_len, 0);

    let mut long_pos = 0usize;
    let long_count = long_lengths.bytes.len() / element_width;
    for (index, &mux) in muxed_lengths.bytes.iter().enumerate() {
        let mux = u64::from(mux);
        let mut literal = mux & ll_mask;
        let mut matched = match_length_bias + (mux >> split_point);

        if literal == ll_mask {
            literal = literal.wrapping_add(read_numeric_element(
                long_lengths.bytes,
                element_width,
                long_pos,
            )?);
            long_pos = checked_next_long_pos(long_pos, long_count)?;
        }
        if matched == ml_max {
            matched = matched.wrapping_add(read_numeric_element(
                long_lengths.bytes,
                element_width,
                long_pos,
            )?);
            long_pos = checked_next_long_pos(long_pos, long_count)?;
        }

        let offset = index
            .checked_mul(element_width)
            .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
        write_numeric_element(&mut literal_lengths[offset..], element_width, literal);
        write_numeric_element(&mut match_lengths[offset..], element_width, matched);
    }
    if long_pos != long_count {
        return Err(Error::new(ErrorKind::Malformed)
            .with_detail("mux_lengths long-length stream was not fully consumed"));
    }

    Ok(vec![
        OwnedStream {
            bytes: literal_lengths,
            element_width,
            string_lengths: None,
            recyclable: false,
        },
        OwnedStream {
            bytes: match_lengths,
            element_width,
            string_lengths: None,
            recyclable: false,
        },
    ])
}

#[expect(
    clippy::cast_possible_truncation,
    reason = "validated mux length streams fit the u16 output width"
)]
fn decode_mux_lengths_u16(
    muxed_lengths: &[u8],
    long_lengths: &[u8],
    split_point: usize,
    ll_mask: u64,
    match_length_bias: u64,
    ml_max: u64,
    output_len: usize,
) -> Result<Vec<OwnedStream>> {
    let mut literal_lengths = Vec::new();
    literal_lengths.try_reserve_exact(output_len).map_err(|_| {
        Error::new(ErrorKind::LimitExceeded).with_detail("mux_lengths allocation failed")
    })?;
    literal_lengths.resize(output_len, 0);
    let mut match_lengths = Vec::new();
    match_lengths.try_reserve_exact(output_len).map_err(|_| {
        Error::new(ErrorKind::LimitExceeded).with_detail("mux_lengths allocation failed")
    })?;
    match_lengths.resize(output_len, 0);

    let mut long_lengths = long_lengths.chunks_exact(2);
    for ((literal_out, match_out), &mux) in literal_lengths
        .chunks_exact_mut(2)
        .zip(match_lengths.chunks_exact_mut(2))
        .zip(muxed_lengths)
    {
        let mux = u64::from(mux);
        let mut literal = mux & ll_mask;
        let mut matched = match_length_bias + (mux >> split_point);

        if literal == ll_mask {
            literal = literal.wrapping_add(read_next_u16_long_length(&mut long_lengths)?);
        }
        if matched == ml_max {
            matched = matched.wrapping_add(read_next_u16_long_length(&mut long_lengths)?);
        }

        literal_out.copy_from_slice(&(literal as u16).to_le_bytes());
        match_out.copy_from_slice(&(matched as u16).to_le_bytes());
    }
    if long_lengths.next().is_some() {
        return Err(Error::new(ErrorKind::Malformed)
            .with_detail("mux_lengths long-length stream was not fully consumed"));
    }

    Ok(vec![
        OwnedStream {
            bytes: literal_lengths,
            element_width: 2,
            string_lengths: None,
            recyclable: false,
        },
        OwnedStream {
            bytes: match_lengths,
            element_width: 2,
            string_lengths: None,
            recyclable: false,
        },
    ])
}

#[inline]
fn read_next_u16_long_length(long_lengths: &mut core::slice::ChunksExact<'_, u8>) -> Result<u64> {
    let bytes = long_lengths.next().ok_or_else(|| {
        Error::new(ErrorKind::Malformed).with_detail("mux_lengths long-length stream is exhausted")
    })?;
    Ok(u64::from(u16::from_le_bytes([bytes[0], bytes[1]])))
}

fn checked_next_long_pos(long_pos: usize, long_count: usize) -> Result<usize> {
    if long_pos >= long_count {
        return Err(Error::new(ErrorKind::Malformed)
            .with_detail("mux_lengths long-length stream is exhausted"));
    }
    long_pos
        .checked_add(1)
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))
}

#[inline]
fn read_numeric_element(bytes: &[u8], element_width: usize, index: usize) -> Result<u64> {
    let start = index
        .checked_mul(element_width)
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
    let element = bytes.get(start..start + element_width).ok_or_else(|| {
        Error::new(ErrorKind::Malformed).with_detail("numeric stream is truncated")
    })?;
    let mut value = [0u8; 8];
    value[..element_width].copy_from_slice(element);
    Ok(u64::from_le_bytes(value))
}

#[expect(
    clippy::cast_possible_truncation,
    clippy::inline_always,
    reason = "profiled numeric decode paths pay measurable call overhead"
)]
#[inline(always)]
fn write_numeric_element(dst: &mut [u8], element_width: usize, value: u64) {
    match element_width {
        1 => dst[0] = value as u8,
        2 => dst[..2].copy_from_slice(&(value as u16).to_le_bytes()),
        4 => dst[..4].copy_from_slice(&(value as u32).to_le_bytes()),
        8 => dst[..8].copy_from_slice(&value.to_le_bytes()),
        _ => dst[..element_width].copy_from_slice(&value.to_le_bytes()[..element_width]),
    }
}

fn validate_numeric_stream_width(element_width: usize, name: &str) -> Result<()> {
    if matches!(element_width, 1 | 2 | 4 | 8) {
        Ok(())
    } else {
        Err(Error::new(ErrorKind::InvalidType).with_detail(format!("{name} width is unsupported")))
    }
}

fn numeric_element_count(bytes: &[u8], element_width: usize) -> Result<usize> {
    if !bytes.len().is_multiple_of(element_width) {
        return Err(
            Error::new(ErrorKind::Malformed).with_detail("numeric stream has partial element")
        );
    }
    Ok(bytes.len() / element_width)
}

#[expect(
    clippy::inline_always,
    reason = "profiled CSV dispatch/tag hot path benefits from inlining this leaf"
)]
#[inline(always)]
fn read_usize_numeric_element(bytes: &[u8], element_width: usize, index: usize) -> Result<usize> {
    let start = index
        .checked_mul(element_width)
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
    let value = match element_width {
        1 => usize::from(*bytes.get(start).ok_or_else(|| {
            Error::new(ErrorKind::Malformed).with_detail("numeric stream is truncated")
        })?),
        2 => usize::from(read_u16_element(bytes, index)?),
        4 => usize::try_from(read_u32_element(bytes, index)?).map_err(|_| {
            Error::new(ErrorKind::LimitExceeded).with_detail("numeric value is too large")
        })?,
        8 => {
            let element = bytes.get(start..start + 8).ok_or_else(|| {
                Error::new(ErrorKind::Malformed).with_detail("numeric stream is truncated")
            })?;
            u64::from_le_bytes([
                element[0], element[1], element[2], element[3], element[4], element[5], element[6],
                element[7],
            ])
            .try_into()
            .map_err(|_| {
                Error::new(ErrorKind::LimitExceeded).with_detail("numeric value is too large")
            })?
        }
        _ => {
            return Err(
                Error::new(ErrorKind::InvalidType).with_detail("numeric width is unsupported")
            );
        }
    };
    Ok(value)
}

#[inline]
fn read_u16_element(bytes: &[u8], index: usize) -> Result<u16> {
    let start = index
        .checked_mul(2)
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
    let element = bytes.get(start..start + 2).ok_or_else(|| {
        Error::new(ErrorKind::Malformed).with_detail("numeric stream is truncated")
    })?;
    Ok(u16::from_le_bytes([element[0], element[1]]))
}

#[inline]
fn read_u32_element(bytes: &[u8], index: usize) -> Result<u32> {
    let start = index
        .checked_mul(4)
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
    let element = bytes.get(start..start + 4).ok_or_else(|| {
        Error::new(ErrorKind::Malformed).with_detail("numeric stream is truncated")
    })?;
    Ok(u32::from_le_bytes([
        element[0], element[1], element[2], element[3],
    ]))
}

fn decode_bitsplit_node(
    inputs: &[StreamInput<'_>],
    variable_inputs: u32,
    header: &[u8],
    limits: Limits,
) -> Result<OwnedStream> {
    let (&output_width, stored_widths) = header.split_first().ok_or_else(|| {
        Error::new(ErrorKind::Malformed).with_detail("bitsplit header is missing output width")
    })?;
    let output_width = usize::from(output_width);
    validate_numeric_stream_width(output_width, "bitsplit output")?;

    let mut bit_widths = Vec::new();
    bit_widths.try_reserve_exact(inputs.len()).map_err(|_| {
        Error::new(ErrorKind::LimitExceeded).with_detail("bitsplit width allocation failed")
    })?;
    let mut stored_sum = 0usize;
    for &width in stored_widths {
        if width == 0 {
            return Err(Error::new(ErrorKind::Malformed).with_detail("bitsplit width is zero"));
        }
        let width = usize::from(width);
        stored_sum = stored_sum
            .checked_add(width)
            .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
        bit_widths.push(width);
    }

    let output_bits = output_width
        .checked_mul(8)
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
    if stored_sum > output_bits {
        return Err(
            Error::new(ErrorKind::Malformed).with_detail("bitsplit widths exceed output width")
        );
    }
    if inputs.len() == stored_widths.len() + 1 {
        let last_width = output_bits
            .checked_sub(stored_sum)
            .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
        if last_width == 0 {
            return Err(
                Error::new(ErrorKind::Malformed).with_detail("bitsplit inferred width is zero")
            );
        }
        bit_widths.push(last_width);
    } else if inputs.len() != stored_widths.len() {
        return Err(Error::new(ErrorKind::InvalidGraph)
            .with_detail("bitsplit input count does not match header"));
    }
    if bit_widths.is_empty() {
        return Err(Error::new(ErrorKind::Malformed).with_detail("bitsplit has no bit widths"));
    }
    if usize::try_from(variable_inputs).is_ok_and(|count| count != inputs.len()) {
        return Err(Error::new(ErrorKind::InvalidGraph)
            .with_detail("bitsplit variable input count does not match inputs"));
    }

    let first = inputs
        .first()
        .ok_or_else(|| Error::new(ErrorKind::InvalidGraph).with_detail("bitsplit has no inputs"))?;
    let element_count = numeric_element_count(first.bytes, first.element_width)?;
    for (input, &bit_width) in inputs.iter().zip(bit_widths.iter()) {
        validate_numeric_stream_width(input.element_width, "bitsplit input")?;
        if numeric_element_count(input.bytes, input.element_width)? != element_count {
            return Err(
                Error::new(ErrorKind::Malformed).with_detail("bitsplit input counts do not match")
            );
        }
        if bit_width > input.element_width * 8 {
            return Err(
                Error::new(ErrorKind::Malformed).with_detail("bitsplit width exceeds input width")
            );
        }
        if input.element_width != bitsplit_element_width(bit_width)? {
            return Err(Error::new(ErrorKind::InvalidType)
                .with_detail("bitsplit input width does not match bit width"));
        }
    }

    let output_len = element_count
        .checked_mul(output_width)
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
    if output_len > limits.max_decoded_bytes || output_len > limits.max_buffer_bytes {
        return Err(
            Error::new(ErrorKind::LimitExceeded).with_detail("decoded output limit exceeded")
        );
    }
    let mut output = Vec::new();
    output.try_reserve_exact(output_len).map_err(|_| {
        Error::new(ErrorKind::LimitExceeded).with_detail("bitsplit allocation failed")
    })?;
    output.resize(output_len, 0);

    for element in 0..element_count {
        let mut value = 0u64;
        let mut bit_pos = 0usize;
        for (input, &bit_width) in inputs.iter().zip(bit_widths.iter()) {
            let part = read_numeric_element(input.bytes, input.element_width, element)?;
            value |= part << bit_pos;
            bit_pos = bit_pos
                .checked_add(bit_width)
                .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
        }
        let output_offset = element
            .checked_mul(output_width)
            .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
        write_numeric_element(&mut output[output_offset..], output_width, value);
    }

    Ok(OwnedStream::typed(output, output_width))
}

fn bitsplit_element_width(bit_width: usize) -> Result<usize> {
    match bit_width {
        1..=8 => Ok(1),
        9..=16 => Ok(2),
        17..=32 => Ok(4),
        33..=64 => Ok(8),
        _ => Err(Error::new(ErrorKind::Malformed).with_detail("bitsplit bit width is unsupported")),
    }
}

fn checked_sum_u32(values: &[u32]) -> Result<usize> {
    let mut total = 0usize;
    for &value in values {
        let value = usize::try_from(value)
            .map_err(|_| Error::new(ErrorKind::LimitExceeded).with_detail("value is too large"))?;
        total = total
            .checked_add(value)
            .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
    }
    Ok(total)
}

fn require_numeric_width(stream: &StreamInput<'_>, expected: usize, name: &str) -> Result<()> {
    if stream.element_width != expected {
        return Err(
            Error::new(ErrorKind::InvalidType).with_detail(format!("{name} width is unsupported"))
        );
    }
    numeric_element_count(stream.bytes, expected)?;
    Ok(())
}

fn decode_tokenize_fixed_node(
    inputs: &[StreamInput<'_>],
    header: &[u8],
    limits: Limits,
) -> Result<OwnedStream> {
    if !header.is_empty() {
        return Err(Error::new(ErrorKind::Unsupported)
            .with_detail("tokenize_fixed headers are unsupported"));
    }
    let [alphabet, indices] = inputs else {
        return Err(Error::new(ErrorKind::InvalidGraph)
            .with_detail("tokenize_fixed input count does not match node shape"));
    };
    let element_width = alphabet.element_width;
    if element_width == 0 || !alphabet.bytes.len().is_multiple_of(element_width) {
        return Err(Error::new(ErrorKind::Malformed)
            .with_detail("tokenize_fixed alphabet has partial element"));
    }
    validate_numeric_stream_width(indices.element_width, "tokenize_fixed indices")?;
    let alphabet_size = alphabet.bytes.len() / element_width;
    let output_elements = numeric_element_count(indices.bytes, indices.element_width)?;
    let output_len = output_elements
        .checked_mul(element_width)
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
    if output_len > limits.max_decoded_bytes || output_len > limits.max_buffer_bytes {
        return Err(
            Error::new(ErrorKind::LimitExceeded).with_detail("decoded output limit exceeded")
        );
    }
    if alphabet_size == 0 && output_elements != 0 {
        return Err(
            Error::new(ErrorKind::Malformed).with_detail("tokenize_fixed alphabet is empty")
        );
    }

    let mut output = Vec::new();
    output.try_reserve_exact(output_len).map_err(|_| {
        Error::new(ErrorKind::LimitExceeded).with_detail("tokenize allocation failed")
    })?;
    fast_tokenize::decode_tokenize_indices(
        alphabet.bytes,
        alphabet_size,
        element_width,
        indices.bytes,
        indices.element_width,
        &mut output,
    )?;
    Ok(OwnedStream {
        bytes: output,
        element_width,
        string_lengths: None,
        recyclable: false,
    })
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

mod pivco_huffman;
mod sparse_num;

#[cfg(test)]
mod tests;
