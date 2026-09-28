use alloc::vec::Vec;

#[cfg(test)]
use crate::dict::DictionaryStore;
use crate::parse::FramePlan;
use ozlrip_core::{Error, ErrorKind, Limits, Result};

use crate::info::FrameValueType;

mod chunk;
mod codecs;
mod direct_append;
mod dispatch;
mod elements;
mod entropy;
mod header;
mod layout;
mod lz;
mod node;
mod numeric;
mod output;
mod outputs;
mod plan;
mod runtime;
mod slots;
mod streams;
mod strings;

use chunk::{decode_transform_chunk_appending, decode_transform_chunk_with_plan};
use codecs::try_decode_single_zstd_into_dst;
#[cfg(feature = "zstd")]
pub(crate) use codecs::{decode_single_zstd_frame_with_context, zstd_context};
use direct_append::{DirectAppendChunk, direct_append_tail};
use output::{DecodedChunk, OutputBudget, verify_decoded_checksum};
pub(crate) use outputs::{DecodedOutput, decode_outputs_with_context};
use plan::build_chunk_execution_plan;
pub(crate) use runtime::{DecodeRuntime, DecodeScratch};

#[cfg(test)]
pub(crate) fn decode_plan(
    input: &[u8],
    plan: &FramePlan,
    dst: &mut Vec<u8>,
    limits: Limits,
) -> Result<usize> {
    #[cfg(feature = "zstd")]
    let mut zstd = None;
    let mut dict_store = DictionaryStore::new();
    let mut scratch = DecodeScratch::new();
    let mut runtime = DecodeRuntime::new(
        &mut scratch,
        &mut dict_store,
        #[cfg(feature = "zstd")]
        &mut zstd,
    );
    decode_plan_with_context(input, plan, dst, limits, true, &mut runtime)
}

/// Decodes a parsed frame into `dst`. `verify_content` checks each chunk's
/// decoded content checksum.
pub(crate) fn decode_plan_with_context(
    input: &[u8],
    plan: &FramePlan,
    dst: &mut Vec<u8>,
    limits: Limits,
    verify_content: bool,
    runtime: &mut DecodeRuntime<'_>,
) -> Result<usize> {
    if let Some(written) = try_decode_single_zstd_into_dst(
        input,
        plan,
        dst,
        limits,
        verify_content,
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
    let result = decode_serial_chunks(input, plan, dst, limits, verify_content, runtime);
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
    verify_content: bool,
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
        if verify_content {
            verify_decoded_checksum(decoded, chunk.decoded_checksum)?;
        }
    }
    budget.finish()?;
    Ok(dst.len() - start_len)
}

/// Decodes each chunk of a single-serial-output frame and passes its bytes
/// to `sink`, in frame order. Chunks decode into one buffer that the next
/// chunk reuses, so decoded memory peaks at one chunk.
pub(crate) fn decode_chunks_with_context(
    input: &[u8],
    plan: &FramePlan,
    limits: Limits,
    verify_content: bool,
    runtime: &mut DecodeRuntime<'_>,
    sink: &mut dyn FnMut(&[u8]) -> Result<()>,
) -> Result<usize> {
    if plan.info.output_types.as_slice() != [FrameValueType::Serial] {
        return Err(Error::new(ErrorKind::Unsupported)
            .with_detail("only single serial output frames decode in chunks"));
    }
    let mut buffer = runtime
        .scratch
        .take_byte_buffer(0, "chunk allocation failed")?;
    let result = stream_serial_chunks(
        input,
        plan,
        limits,
        verify_content,
        runtime,
        &mut buffer,
        sink,
    );
    runtime.scratch.recycle_byte_buffer(buffer);
    result
}

fn stream_serial_chunks(
    input: &[u8],
    plan: &FramePlan,
    limits: Limits,
    verify_content: bool,
    runtime: &mut DecodeRuntime<'_>,
    buffer: &mut Vec<u8>,
    sink: &mut dyn FnMut(&[u8]) -> Result<()>,
) -> Result<usize> {
    let mut budget = OutputBudget::for_output(plan, 0, input.len(), limits)?;
    let mut total = 0usize;
    for chunk in &plan.chunks {
        buffer.clear();
        let mut owned = None;
        let decoded = if chunk.has_nodes() {
            let execution = build_chunk_execution_plan(chunk)?;
            if direct_append_tail(&execution).is_some() {
                decode_transform_chunk_appending(
                    input,
                    DirectAppendChunk {
                        chunk,
                        execution: &execution,
                    },
                    plan.info.format_version,
                    limits,
                    budget.remaining(),
                    buffer,
                    plan.info.dictionary_bundle_id.as_deref(),
                    runtime,
                )?;
                buffer.as_slice()
            } else {
                match decode_transform_chunk_with_plan(
                    input,
                    chunk,
                    &execution,
                    plan.info.format_version,
                    limits,
                    plan.info.dictionary_bundle_id.as_deref(),
                    runtime,
                )? {
                    DecodedChunk::Borrowed(bytes) => bytes,
                    DecodedChunk::Owned(bytes) => owned.insert(bytes).as_slice(),
                }
            }
        } else {
            stored_only_chunk(input, chunk)?
        };
        budget.consume(decoded.len())?;
        if verify_content {
            verify_decoded_checksum(decoded, chunk.decoded_checksum)?;
        }
        sink(decoded)?;
        total += decoded.len();
        if let Some(bytes) = owned {
            runtime.scratch.recycle_byte_buffer(bytes);
        }
    }
    budget.finish()?;
    Ok(total)
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
        let appended = append_slice(dst, &bytes, budget);
        scratch.recycle_byte_buffer(bytes);
        return appended;
    }
    append_slice(dst, decoded.as_slice(), budget)
}

fn append_slice(dst: &mut Vec<u8>, bytes: &[u8], budget: &mut OutputBudget) -> Result<()> {
    budget.reserve(dst)?;
    dst.try_reserve(bytes.len()).map_err(|_| {
        Error::new(ErrorKind::AllocationFailed).with_detail("output allocation failed")
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

#[cfg(test)]
mod tests;
