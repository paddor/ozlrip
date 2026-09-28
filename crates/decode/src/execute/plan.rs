use alloc::{format, vec::Vec};

use crate::parse::NodePlan;
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

impl NodeExecutionPlan {
    /// This node's header within the chunk's transform headers.
    pub(super) fn header<'a>(&self, headers: &'a [u8]) -> Result<&'a [u8]> {
        let end = self
            .header_start
            .checked_add(self.header_size)
            .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
        headers.get(self.header_start..end).ok_or_else(|| {
            Error::new(ErrorKind::InvalidGraph).with_detail("node header is out of bounds")
        })
    }
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
            Error::new(ErrorKind::AllocationFailed).with_detail("regen target allocation failed")
        })?;
    regen_targets.resize(total_streams, false);

    let mut nodes = Vec::new();
    nodes.try_reserve_exact(chunk.transforms()).map_err(|_| {
        Error::new(ErrorKind::AllocationFailed).with_detail("node execution allocation failed")
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
        let input_count = node_input_count(node, standard_id)?;
        let input_end = stream_cursor
            .checked_add(input_count)
            .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
        let output_targets =
            resolve_output_targets(node, standard_id, input_end, &mut regen_targets)?;
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

/// Number of streams a node reads: its static inputs plus its variable
/// ones.
fn node_input_count(node: &NodePlan, standard_id: u32) -> Result<usize> {
    let variable_inputs = usize::try_from(node.variable_outputs()).map_err(|_| {
        Error::new(ErrorKind::LimitExceeded).with_detail("node input count is too large")
    })?;
    let static_inputs = standard::standard_node(standard_id)
        .ok_or_else(|| {
            Error::new(ErrorKind::Unsupported)
                .with_detail("standard transform graph execution is not implemented yet")
        })?
        .shape
        .static_inputs;
    static_inputs
        .checked_add(variable_inputs)
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))
}

/// The stream slots a node's outputs fill, marked in `regen_targets`.
fn resolve_output_targets(
    node: &NodePlan,
    standard_id: u32,
    input_end: usize,
    regen_targets: &mut [bool],
) -> Result<SmallVec<[usize; 2]>> {
    let total_streams = regen_targets.len();
    let mut output_targets = SmallVec::<[usize; 2]>::new();
    output_targets
        .try_reserve_exact(node.regen_distances().len())
        .map_err(|_| {
            Error::new(ErrorKind::AllocationFailed)
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
            return Err(
                Error::new(ErrorKind::InvalidGraph).with_detail("duplicate regen stream distance")
            );
        }
        *target = true;
        output_targets.push(output_target);
    }
    Ok(output_targets)
}
