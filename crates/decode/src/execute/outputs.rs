//! Decoding every frame output with its type: serial, struct, numeric or
//! string. Output `k` of a chunk is its stream `streams - k - 1`, as in
//! upstream `addChunksIntoFinalStreams`.
#![cfg_attr(
    not(test),
    expect(dead_code, reason = "the public typed-output API comes next")
)]

use alloc::vec::Vec;

use ozlrip_core::{Error, ErrorKind, Limits, Result};
use xxhash_rust::xxh3::Xxh3;

use crate::info::FrameValueType;
use crate::parse::FramePlan;
use crate::standard;

use super::output::{OutputBudget, check_output_len};
use super::plan::{ChunkExecutionPlan, build_chunk_execution_plan};
use super::streams::StreamSlot;
use super::{DecodeRuntime, decode_plan_with_context, run_chunk};

/// One decoded frame output. The buffers are reused across decodes.
#[derive(Debug, Default)]
pub(crate) struct DecodedOutput {
    pub(crate) value_type: Option<FrameValueType>,
    /// Element width: 1 for serial and string outputs.
    pub(crate) width: usize,
    /// Content bytes; numeric elements are little-endian.
    pub(crate) bytes: Vec<u8>,
    /// String lengths, for string outputs.
    pub(crate) lengths: Vec<u32>,
}

/// Decodes every output of `plan` into `outputs`, which ends up with one
/// entry per output. Existing entries keep their allocations. On error the
/// entries hold partial content.
pub(crate) fn decode_outputs_with_context(
    input: &[u8],
    plan: &FramePlan,
    outputs: &mut Vec<DecodedOutput>,
    limits: Limits,
    verify_content: bool,
    runtime: &mut DecodeRuntime<'_>,
) -> Result<()> {
    let info = &plan.info;
    let count = info.outputs;
    outputs.truncate(count);
    outputs.resize_with(count, DecodedOutput::default);
    for (output, &value_type) in outputs.iter_mut().zip(&info.output_types) {
        output.value_type = Some(value_type);
        output.width = 0;
        output.bytes.clear();
        output.lengths.clear();
    }

    // A single serial output takes the direct-append decode path.
    if info.output_types.as_slice() == [FrameValueType::Serial] {
        let output = &mut outputs[0];
        output.width = 1;
        decode_plan_with_context(
            input,
            plan,
            &mut output.bytes,
            limits,
            verify_content,
            runtime,
        )?;
        return Ok(());
    }

    let declared_total = info.decoded_bytes.ok_or_else(|| {
        Error::new(ErrorKind::Unsupported)
            .with_detail("unknown OpenZL output sizes are unsupported")
    })?;
    // Checks the declared total against the limits and the expansion ratio.
    OutputBudget::new(declared_total, input.len(), limits)?;
    let mut budgets = Vec::new();
    budgets.try_reserve_exact(count).map_err(|_| {
        Error::new(ErrorKind::AllocationFailed).with_detail("output budget allocation failed")
    })?;
    for (index, output) in outputs.iter_mut().enumerate() {
        let mut bytes = OutputBudget::for_output(plan, index, input.len(), limits)?;
        bytes.reserve(&mut output.bytes)?;
        let lengths = match info.output_elements.get(index).copied().flatten() {
            Some(elements) if output.value_type == Some(FrameValueType::String) => {
                let elements = usize::try_from(elements).map_err(|_| {
                    Error::new(ErrorKind::LimitExceeded).with_detail("string count is too large")
                })?;
                let length_bytes = elements.checked_mul(4).ok_or_else(|| {
                    Error::new(ErrorKind::IntegerOverflow).with_detail("string count overflows")
                })?;
                let budget = OutputBudget::new(length_bytes, input.len(), limits)?;
                output.lengths.try_reserve_exact(elements).map_err(|_| {
                    Error::new(ErrorKind::AllocationFailed)
                        .with_detail("string length allocation failed")
                })?;
                Some(budget)
            }
            _ => None,
        };
        budgets.push((bytes, lengths));
    }

    for chunk in &plan.chunks {
        let execution = build_chunk_execution_plan(chunk)?;
        let streams = run_chunk(
            input,
            chunk,
            &execution,
            info.format_version,
            limits,
            info.dictionary_bundle_id.as_deref(),
            runtime,
        )?;
        let mut hasher = (verify_content && chunk.decoded_checksum.is_some()).then(Xxh3::new);
        for (index, (output, budget)) in outputs.iter_mut().zip(&mut budgets).enumerate() {
            let slot = streams
                .len()
                .checked_sub(index + 1)
                .and_then(|slot| streams.get(slot).map(|stream| (slot, stream)));
            let Some((slot, stream)) = slot else {
                return Err(Error::new(ErrorKind::InvalidGraph)
                    .with_detail("chunk has fewer streams than frame outputs"));
            };
            let chunk_output = ChunkOutput::new(stream, stream_type(&execution, slot))?;
            append_chunk_output(output, budget, &chunk_output, limits)?;
            if let Some(hasher) = &mut hasher {
                hasher.update(chunk_output.bytes);
                if info.format_version >= 15
                    && let Some(lengths) = chunk_output.lengths
                {
                    hash_lengths(hasher, lengths);
                }
            }
        }
        if let (Some(hasher), Some(expected)) = (hasher, chunk.decoded_checksum) {
            #[expect(clippy::cast_possible_truncation, reason = "the low 32 bits")]
            let actual = hasher.digest() as u32;
            if actual != expected {
                return Err(Error::new(ErrorKind::ChecksumMismatch)
                    .with_detail("OpenZL decoded checksum mismatch"));
            }
        }
        for stream in streams {
            if let StreamSlot::Owned(stream) = stream {
                runtime.scratch.recycle_owned_stream(stream);
            }
        }
    }

    for (bytes, lengths) in &budgets {
        bytes.finish()?;
        if let Some(lengths) = lengths {
            lengths.finish()?;
        }
    }
    Ok(())
}

/// A chunk's contribution to one output.
struct ChunkOutput<'a> {
    value_type: FrameValueType,
    width: usize,
    bytes: &'a [u8],
    lengths: Option<&'a [u32]>,
}

impl<'a> ChunkOutput<'a> {
    fn new(stream: &'a StreamSlot<'a>, value_type: FrameValueType) -> Result<Self> {
        let input = stream.as_input()?;
        Ok(Self {
            value_type,
            width: input.element_width,
            bytes: input.bytes,
            lengths: input.string_lengths,
        })
    }
}

/// Checks a chunk's output against the frame header and appends it.
fn append_chunk_output(
    output: &mut DecodedOutput,
    (bytes_budget, lengths_budget): &mut (OutputBudget, Option<OutputBudget>),
    chunk: &ChunkOutput<'_>,
    limits: Limits,
) -> Result<()> {
    if Some(chunk.value_type) != output.value_type {
        return Err(
            Error::new(ErrorKind::Malformed).with_detail("final stream type does not match header")
        );
    }
    match chunk.value_type {
        FrameValueType::Serial | FrameValueType::String if chunk.width != 1 => {
            return Err(Error::new(ErrorKind::InvalidType)
                .with_detail("serial and string outputs have 1-byte elements"));
        }
        FrameValueType::Numeric if !matches!(chunk.width, 1 | 2 | 4 | 8) => {
            return Err(
                Error::new(ErrorKind::InvalidType).with_detail("numeric output width is invalid")
            );
        }
        _ => {}
    }
    if output.width == 0 {
        output.width = chunk.width;
    } else if output.width != chunk.width {
        return Err(Error::new(ErrorKind::Malformed)
            .with_detail("output element width changes between chunks"));
    }
    if !chunk.bytes.len().is_multiple_of(chunk.width) {
        return Err(
            Error::new(ErrorKind::Malformed).with_detail("output stream has a partial element")
        );
    }

    bytes_budget.consume(chunk.bytes.len())?;
    output.bytes.extend_from_slice(chunk.bytes);

    match (chunk.value_type, chunk.lengths) {
        (FrameValueType::String, Some(lengths)) => {
            let length_bytes = lengths.len().checked_mul(4).ok_or_else(|| {
                Error::new(ErrorKind::IntegerOverflow).with_detail("string count overflows")
            })?;
            match lengths_budget {
                Some(budget) => budget.consume(length_bytes)?,
                None => check_output_len((output.lengths.len() + lengths.len()) * 4, limits)?,
            }
            output.lengths.try_reserve(lengths.len()).map_err(|_| {
                Error::new(ErrorKind::AllocationFailed)
                    .with_detail("string length allocation failed")
            })?;
            output.lengths.extend_from_slice(lengths);
        }
        (FrameValueType::String, None) => {
            return Err(
                Error::new(ErrorKind::Malformed).with_detail("string output has no lengths")
            );
        }
        _ => {}
    }
    Ok(())
}

/// Type of stream `slot` in a chunk: the output type of the node that
/// regenerates it, or serial for a stored stream.
fn stream_type(plan: &ChunkExecutionPlan, slot: usize) -> FrameValueType {
    plan.nodes
        .iter()
        .find(|node| node.output_targets.contains(&slot))
        .and_then(|node| standard::standard_node(node.standard_id))
        .map_or(FrameValueType::Serial, |node| node.output_type)
}

/// Hashes string lengths as upstream does: 32-bit little-endian values.
fn hash_lengths(hasher: &mut Xxh3, lengths: &[u32]) {
    let mut buffer = [0u8; 256];
    for chunk in lengths.chunks(buffer.len() / 4) {
        for (bytes, length) in buffer.as_chunks_mut::<4>().0.iter_mut().zip(chunk) {
            *bytes = length.to_le_bytes();
        }
        hasher.update(&buffer[..chunk.len() * 4]);
    }
}
