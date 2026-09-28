//! Decoding every frame output with its type: serial, struct, numeric or
//! string. Output `k` of a chunk is its stream `streams - k - 1`, as in
//! upstream `addChunksIntoFinalStreams`.

use alloc::vec::Vec;

use ozlrip_core::{Error, ErrorKind, Limits, Result};
use xxhash_rust::xxh3::Xxh3;

use crate::info::FrameValueType;
use crate::parse::FramePlan;
use crate::standard;

use super::output::{OutputBudget, check_expansion, check_output_len, declared_output_size};
use super::plan::{ChunkExecutionPlan, build_chunk_execution_plan};
use super::streams::StreamSlot;
use super::{chunk::run_chunk, decode_plan_with_context, runtime::DecodeRuntime};

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
    reset_outputs(outputs, info.outputs, &info.output_types);

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

    let mut budgets = plan_output_budgets(plan, outputs, input.len(), limits)?;
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
        let mut hasher =
            ChunkHasher::new(verify_content, chunk.decoded_checksum, info.format_version);
        append_chunk_outputs(
            outputs,
            &mut budgets,
            &streams,
            &execution,
            limits,
            &mut hasher,
        )?;
        hasher.finish()?;
        runtime.scratch.recycle_stream_slots(streams);
    }
    budgets.iter().try_for_each(OutputBudgets::finish)
}

/// Resizes `outputs` to `count` empty entries typed by `types`, keeping the
/// allocations of existing entries.
fn reset_outputs(outputs: &mut Vec<DecodedOutput>, count: usize, types: &[FrameValueType]) {
    outputs.truncate(count);
    outputs.resize_with(count, DecodedOutput::default);
    for (output, &value_type) in outputs.iter_mut().zip(types) {
        output.value_type = Some(value_type);
        output.width = 0;
        output.bytes.clear();
        output.lengths.clear();
    }
}

/// The declared content size of one output, and its string lengths.
struct OutputBudgets {
    bytes: OutputBudget,
    lengths: Option<OutputBudget>,
}

impl OutputBudgets {
    fn finish(&self) -> Result<()> {
        self.bytes.finish()?;
        self.lengths.as_ref().map_or(Ok(()), OutputBudget::finish)
    }
}

/// One budget per output, checked against the limits and one expansion
/// ratio for the whole frame, then reserved in `outputs`.
fn plan_output_budgets(
    plan: &FramePlan,
    outputs: &mut [DecodedOutput],
    encoded_size: usize,
    limits: Limits,
) -> Result<Vec<OutputBudgets>> {
    let info = &plan.info;
    let declared_total = info.decoded_bytes.ok_or_else(|| {
        Error::new(ErrorKind::Unsupported)
            .with_detail("unknown OpenZL output sizes are unsupported")
    })?;
    check_output_len(declared_total, limits)?;
    let mut budgets = Vec::new();
    budgets.try_reserve_exact(outputs.len()).map_err(|_| {
        Error::new(ErrorKind::AllocationFailed).with_detail("output budget allocation failed")
    })?;
    // String lengths are decoded output too, so the expansion ratio covers
    // them together with the content of every output.
    let mut expanded = declared_total;
    for (index, output) in outputs.iter().enumerate() {
        let bytes = OutputBudget::part(declared_output_size(plan, index)?, limits)?;
        let lengths = match info.output_elements.get(index).copied().flatten() {
            Some(elements) if output.value_type == Some(FrameValueType::String) => {
                let length_bytes = string_length_bytes(elements)?;
                expanded = expanded.checked_add(length_bytes).ok_or_else(|| {
                    Error::new(ErrorKind::IntegerOverflow)
                        .with_detail("decoded output size overflows")
                })?;
                Some(OutputBudget::part(length_bytes, limits)?)
            }
            _ => None,
        };
        budgets.push(OutputBudgets { bytes, lengths });
    }
    check_expansion(expanded, encoded_size, limits)?;
    for (output, budget) in outputs.iter_mut().zip(&mut budgets) {
        budget.bytes.reserve(&mut output.bytes)?;
        if let Some(lengths) = &budget.lengths {
            output
                .lengths
                .try_reserve_exact(lengths.remaining() / 4)
                .map_err(|_| {
                    Error::new(ErrorKind::AllocationFailed)
                        .with_detail("string length allocation failed")
                })?;
        }
    }
    Ok(budgets)
}

/// Bytes that `elements` 32-bit string lengths take.
fn string_length_bytes(elements: u64) -> Result<usize> {
    let elements = usize::try_from(elements).map_err(|_| {
        Error::new(ErrorKind::LimitExceeded).with_detail("string count is too large")
    })?;
    elements
        .checked_mul(4)
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow).with_detail("string count overflows"))
}

/// Appends a chunk's final streams to their outputs: output `k` is stream
/// `streams - k - 1`.
fn append_chunk_outputs(
    outputs: &mut [DecodedOutput],
    budgets: &mut [OutputBudgets],
    streams: &[StreamSlot<'_>],
    execution: &ChunkExecutionPlan,
    limits: Limits,
    hasher: &mut ChunkHasher,
) -> Result<()> {
    for (index, (output, budget)) in outputs.iter_mut().zip(budgets).enumerate() {
        let slot = streams
            .len()
            .checked_sub(index + 1)
            .and_then(|slot| streams.get(slot).map(|stream| (slot, stream)));
        let Some((slot, stream)) = slot else {
            return Err(Error::new(ErrorKind::InvalidGraph)
                .with_detail("chunk has fewer streams than frame outputs"));
        };
        let chunk_output = ChunkOutput::new(stream, stream_type(execution, slot))?;
        append_chunk_output(output, budget, &chunk_output, limits)?;
        hasher.update(&chunk_output);
    }
    Ok(())
}

/// The content checksum of one chunk, hashed over its outputs in order,
/// when the chunk has one and verification is on.
struct ChunkHasher {
    hasher: Option<Xxh3>,
    expected: Option<u32>,
    /// String lengths are hashed from format v15 on.
    hash_lengths: bool,
}

impl ChunkHasher {
    fn new(verify: bool, expected: Option<u32>, format_version: u32) -> Self {
        Self {
            hasher: (verify && expected.is_some()).then(Xxh3::new),
            expected,
            hash_lengths: format_version >= 15,
        }
    }

    fn update(&mut self, output: &ChunkOutput<'_>) {
        let Some(hasher) = &mut self.hasher else {
            return;
        };
        hasher.update(output.bytes);
        if self.hash_lengths
            && let Some(lengths) = output.lengths
        {
            hash_lengths(hasher, lengths);
        }
    }

    fn finish(self) -> Result<()> {
        if let (Some(hasher), Some(expected)) = (self.hasher, self.expected) {
            #[expect(clippy::cast_possible_truncation, reason = "the low 32 bits")]
            let actual = hasher.digest() as u32;
            if actual != expected {
                return Err(Error::new(ErrorKind::ChecksumMismatch)
                    .with_detail("OpenZL decoded checksum mismatch"));
            }
        }
        Ok(())
    }
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
    budgets: &mut OutputBudgets,
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

    budgets.bytes.consume(chunk.bytes.len())?;
    output.bytes.extend_from_slice(chunk.bytes);

    match (chunk.value_type, chunk.lengths) {
        (FrameValueType::String, Some(lengths)) => {
            let length_bytes = lengths.len().checked_mul(4).ok_or_else(|| {
                Error::new(ErrorKind::IntegerOverflow).with_detail("string count overflows")
            })?;
            match &mut budgets.lengths {
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
