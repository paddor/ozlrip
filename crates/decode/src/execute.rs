use alloc::vec::Vec;

#[cfg(test)]
use crate::dict::DictionaryStore;
use crate::{parse::FramePlan, standard};
use ozlrip_core::{Error, ErrorKind, Limits, Result};

use crate::info::FrameValueType;
use smallvec::SmallVec;

mod direct_append;
mod dispatch;
mod entropy;
mod fast_bitpack;
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
mod layout_nodes;
mod lz4;
mod lz_nodes;
mod node;
mod numeric;
mod numeric_nodes;
mod output;
mod parse_int;
mod partition;
mod plan;
mod runtime;
mod streams;
mod string_nodes;
mod zstd;

use direct_append::{
    DirectAppendChunk, DirectAppendKind, append_split_by_struct_to_final_splitn,
    direct_append_tail, validate_direct_append_tail, validate_string_to_serial_tail,
};
use dispatch::{
    decode_dispatch_n_by_tag_node, decode_dispatch_string_node,
    decode_dispatch_string_node_to_serial_output,
};
use entropy::{
    decode_fse_deprecated_node, decode_fse_ncount_node, decode_fse_v2_node,
    decode_huffman_deprecated_node, decode_huffman_fixed_deprecated_node,
    decode_huffman_struct_v2_node, decode_huffman_v2_node,
};
use lz_nodes::{
    decode_fastlz_deprecated_node, decode_field_lz_node, decode_field_lz_node_to_output,
    decode_lz_node, decode_lz_node_to_output, decode_rolz_deprecated_node,
};
use node::{
    StandardNodeContext, execute_standard_node, node_header, one_typed, read_conversion_int_size,
    single_input, single_stream, try_execute_byte_preserving_conversion_node,
    try_execute_single_input_splitn_node, validate_conversion_numeric_width,
};
use numeric::{
    checked_sum_u32, max_numeric_value, numeric_element_count, read_usize_numeric_element,
    read_var_u64, require_numeric_width, validate_numeric_stream_width,
};
use numeric_nodes::{
    decode_bitpack_int_chunk, decode_bitpack_serial_chunk, decode_bitunpack_serial8_chunk,
    decode_byte_preserving_conversion_chunk, decode_constant_fixed_chunk,
    decode_constant_serial_chunk, decode_dedup_num_node, decode_delta_node, decode_divide_by_node,
    decode_num_to_struct_le_chunk, decode_numeric_to_serial_le_chunk,
    decode_range_pack_serial8_chunk, decode_serial_to_num_be_chunk,
    decode_serial_to_numeric_le_chunk, decode_serial_to_struct_chunk,
    decode_struct_to_num_be_chunk, decode_zigzag_numeric_chunk,
};
#[cfg(feature = "checksum")]
use output::verify_decoded_checksum;
use output::{DecodedChunk, OutputBudget};
use partition::{QUANTIZE_LENGTHS, QUANTIZE_OFFSETS, decode_partition_node, decode_quantize_node};
use plan::{ChunkExecutionPlan, build_chunk_execution_plan};
pub(crate) use runtime::{DecodeRuntime, DecodeScratch};
use streams::{
    LiveBytes, OwnedStream, StreamInput, StreamSlot, collect_node_inputs, initialize_stream_slots,
    recycle_consumed_owned_streams,
};
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
    let mut zstd = zrip_decode::context::DecompressContext::new();
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
    if plan.info.output_types.as_slice() != [FrameValueType::Serial] {
        return Err(Error::new(ErrorKind::Unsupported)
            .with_detail("only single serial stored-output frames are implemented"));
    }
    let start_len = dst.len();
    let result = decode_serial_chunks(input, plan, dst, limits, runtime);
    if result.is_err() {
        dst.truncate(start_len);
    }
    result
}

/// Decodes each chunk of a single-serial-output frame and appends it to
/// `dst`. Each chunk's execution plan is built once; chunks whose graph ends
/// in a direct-append tail write straight into `dst`.
fn decode_serial_chunks(
    input: &[u8],
    plan: &FramePlan,
    dst: &mut Vec<u8>,
    limits: Limits,
    runtime: &mut DecodeRuntime<'_>,
) -> Result<usize> {
    let start_len = dst.len();
    let mut budget = OutputBudget::for_output(plan, 0, input.len(), limits)?;
    let single_chunk = plan.chunks.len() == 1;
    for chunk in &plan.chunks {
        let chunk_start = dst.len();
        if chunk.has_nodes() {
            let execution = build_chunk_execution_plan(chunk)?;
            if direct_append_tail(&execution).is_some() {
                budget.reserve(dst)?;
                decode_transform_chunk_appending(
                    input,
                    DirectAppendChunk {
                        chunk,
                        execution: &execution,
                    },
                    plan.info.format_version,
                    limits,
                    budget.remaining(),
                    dst,
                    plan.info.dictionary_bundle_id.as_deref(),
                    runtime,
                )?;
            } else {
                let decoded = decode_transform_chunk_with_plan(
                    input,
                    chunk,
                    &execution,
                    plan.info.format_version,
                    limits,
                    plan.info.dictionary_bundle_id.as_deref(),
                    runtime,
                )?;
                append_decoded_chunk(dst, decoded, single_chunk, &mut budget, runtime.scratch)?;
            }
        } else {
            let stored = stored_only_chunk(input, chunk)?;
            append_decoded_chunk(
                dst,
                DecodedChunk::Borrowed(stored),
                single_chunk,
                &mut budget,
                runtime.scratch,
            )?;
        }
        let decoded = &dst[chunk_start..];
        // Charge the chunk before checking it, so an overrun is reported as
        // such instead of as a later chunk's checksum failure.
        budget.consume(decoded.len())?;
        #[cfg(not(feature = "checksum"))]
        let _ = chunk.decoded_checksum;
        #[cfg(feature = "checksum")]
        verify_decoded_checksum(decoded, chunk.decoded_checksum)?;
    }
    budget.finish()?;
    Ok(dst.len() - start_len)
}

/// Appends one decoded chunk. A single-chunk frame whose output is an owned
/// buffer moves it into an empty `dst` that is too small to hold it, instead
/// of copying; the displaced allocation goes back to the scratch pool.
fn append_decoded_chunk(
    dst: &mut Vec<u8>,
    decoded: DecodedChunk<'_>,
    single_chunk: bool,
    budget: &mut OutputBudget,
    scratch: &mut DecodeScratch,
) -> Result<()> {
    if let DecodedChunk::Owned(bytes) = decoded {
        if single_chunk && dst.is_empty() && dst.capacity() < bytes.len() {
            let displaced = core::mem::replace(dst, bytes);
            if displaced.capacity() > 0 {
                scratch.recycle_byte_buffer(displaced);
            }
            return Ok(());
        }
        return append_slice(dst, &bytes, budget);
    }
    append_slice(dst, decoded.as_slice(), budget)
}

fn append_slice(dst: &mut Vec<u8>, bytes: &[u8], budget: &mut OutputBudget) -> Result<()> {
    budget.reserve(dst)?;
    dst.try_reserve(bytes.len()).map_err(|_| {
        Error::new(ErrorKind::LimitExceeded).with_detail("output allocation failed")
    })?;
    dst.extend_from_slice(bytes);
    Ok(())
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
        let header = node_header(transform_headers, node.header_start, node.header_size)?;
        if try_execute_single_input_splitn_node(&mut streams, node, header, limits, &mut live)? {
            continue;
        }
        if try_execute_byte_preserving_conversion_node(
            &mut streams,
            node,
            header,
            limits,
            &mut live,
        )? {
            continue;
        }

        let inputs = collect_node_inputs(&streams, node.input_start, node.input_count)?;
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
                &mut ctx,
            )?
        };
        drop(inputs);
        recycle_consumed_owned_streams(
            &mut streams,
            node.input_start,
            node.input_count,
            ctx.scratch,
            &mut live,
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
            live.add(&output)?;
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

/// `max_output` caps what the tail may append; it is the rest of the frame's
/// declared output.
#[expect(
    clippy::too_many_arguments,
    reason = "direct-append decode needs the chunk, frame context, output cap and runtime"
)]
fn decode_transform_chunk_appending(
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
            return Ok(dst.len() - output_start);
        }
        if try_execute_single_input_splitn_node(&mut streams, node, header, limits, &mut live)? {
            continue;
        }
        if try_execute_byte_preserving_conversion_node(
            &mut streams,
            node,
            header,
            limits,
            &mut live,
        )? {
            continue;
        }

        let inputs = collect_node_inputs(&streams, node.input_start, node.input_count)?;
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
                &mut ctx,
            )?
        };
        drop(inputs);
        recycle_consumed_owned_streams(
            &mut streams,
            node.input_start,
            node.input_count,
            ctx.scratch,
            &mut live,
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
            live.add(&output)?;
            *target = StreamSlot::Owned(output);
        }
    }

    Err(Error::new(ErrorKind::InvalidGraph).with_detail("direct-append tail was not executed"))
}

mod pivco_huffman;
mod sparse_num;

#[cfg(test)]
mod tests;
