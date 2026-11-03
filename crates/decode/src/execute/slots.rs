//! The stream table of a chunk: one slot per stream, filled with the
//! stored streams first and with node outputs as the graph runs.

use alloc::vec::Vec;

use ozlrip_core::{Error, ErrorKind, Limits, Result};
use smallvec::SmallVec;

use super::plan::NodeExecutionPlan;
use super::runtime::DecodeScratch;
use super::streams::{BorrowedStream, OwnedStream, StreamInput};

pub(super) fn move_stream_to_single_output(
    streams: &mut [StreamSlot<'_>],
    node: &NodeExecutionPlan,
    output_width: usize,
    live: &mut LiveBytes,
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
            if let Some(lengths) = stream.string_lengths.take() {
                live.release(lengths.len().saturating_mul(4));
            }
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

pub(super) fn single_execution_input<'a>(
    streams: &'a [StreamSlot<'a>],
    input_start: usize,
) -> Result<StreamInput<'a>> {
    streams
        .get(input_start)
        .ok_or_else(|| Error::new(ErrorKind::InvalidGraph).with_detail("node input is missing"))?
        .as_input()
}

pub(super) fn initialize_stream_slots<'a>(
    input: &'a [u8],
    chunk: &crate::parse::ChunkPlan,
    regen_targets: &[bool],
) -> Result<Vec<StreamSlot<'a>>> {
    let mut streams = Vec::new();
    streams
        .try_reserve_exact(regen_targets.len())
        .map_err(|_| {
            Error::new(ErrorKind::AllocationFailed).with_detail("stream table allocation failed")
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

pub(super) fn collect_node_inputs<'a>(
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
        Error::new(ErrorKind::AllocationFailed).with_detail("node input allocation failed")
    })?;
    for slot in input_slots.iter().rev() {
        inputs.push(slot.as_input()?);
    }
    Ok(inputs)
}

pub(super) enum StreamSlot<'a> {
    Empty,
    Borrowed(BorrowedStream<'a>),
    Owned(OwnedStream),
}

impl<'a> StreamSlot<'a> {
    pub(super) fn as_input(&'a self) -> Result<StreamInput<'a>> {
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

pub(super) fn recycle_consumed_owned_streams(
    streams: &mut [StreamSlot<'_>],
    input_start: usize,
    input_count: usize,
    scratch: &mut DecodeScratch,
    live: &mut LiveBytes,
) -> Result<()> {
    let input_end = input_start
        .checked_add(input_count)
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
    let input_slots = streams.get_mut(input_start..input_end).ok_or_else(|| {
        Error::new(ErrorKind::InvalidGraph).with_detail("node input range is out of bounds")
    })?;
    for slot in input_slots {
        if let StreamSlot::Owned(stream) = core::mem::replace(slot, StreamSlot::Empty) {
            live.release(stream.live_bytes());
            scratch.recycle_owned_stream(stream);
        }
    }
    Ok(())
}

/// Bytes held by the owned intermediate streams of the chunk being decoded,
/// bounded by [`Limits::max_live_bytes`]. Borrowed input streams do not
/// count.
pub(super) struct LiveBytes {
    pub(super) current: usize,
    pub(super) limit: usize,
}

impl LiveBytes {
    pub(super) fn new(limits: Limits) -> Self {
        Self {
            current: 0,
            limit: limits.max_live_bytes,
        }
    }

    pub(super) fn add(&mut self, stream: &OwnedStream) -> Result<()> {
        self.current = self
            .current
            .checked_add(stream.live_bytes())
            .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
        if self.current > self.limit {
            return Err(Error::new(ErrorKind::LimitExceeded)
                .with_detail("live intermediate stream limit exceeded"));
        }
        Ok(())
    }

    pub(super) fn release(&mut self, bytes: usize) {
        debug_assert!(bytes <= self.current);
        self.current = self.current.saturating_sub(bytes);
    }
}

/// Recycles the owned streams among a chunk's stream slots.
pub(super) fn recycle_stream_slots(scratch: &mut DecodeScratch, streams: Vec<StreamSlot<'_>>) {
    for slot in streams {
        if let StreamSlot::Owned(stream) = slot {
            scratch.recycle_owned_stream(stream);
        }
    }
}
