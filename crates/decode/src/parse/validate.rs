use alloc::{format, vec::Vec};

use crate::standard::{self, NodeShape};
use ozlrip_core::{Error, ErrorKind, Limits, Result};

use super::reader::{check_limit, sum_usize};
use super::{ChunkPlan, FramePlan, NodePlan, TransformType};
use crate::arith::checked_add;

pub(super) fn validate_frame_plan(plan: &FramePlan, limits: Limits) -> Result<()> {
    if plan.info.chunks != plan.chunks.len() {
        return Err(Error::new(ErrorKind::InvalidGraph).with_detail("chunk count mismatch"));
    }

    let mut transforms = 0usize;
    let mut stored_streams = 0usize;
    let mut regenerated_streams = 0usize;
    for chunk in &plan.chunks {
        validate_chunk_plan(chunk, plan.info.output_types.len(), limits)?;
        transforms = checked_add(transforms, chunk.transforms())?;
        stored_streams = checked_add(stored_streams, chunk.stored_streams())?;
        regenerated_streams = checked_add(regenerated_streams, chunk.regenerated_streams())?;
    }

    if transforms != plan.info.transforms
        || stored_streams != plan.info.stored_streams
        || regenerated_streams != plan.info.regenerated_streams
    {
        return Err(Error::new(ErrorKind::InvalidGraph).with_detail("chunk summary mismatch"));
    }

    Ok(())
}

pub(super) fn validate_chunk_plan(
    chunk: &ChunkPlan,
    output_count: usize,
    limits: Limits,
) -> Result<()> {
    let stream_bound = checked_add(chunk.regenerated_streams(), chunk.stored_streams())?;
    if output_count > stream_bound {
        return Err(Error::new(ErrorKind::InvalidGraph)
            .with_detail("chunk has fewer streams than final outputs"));
    }
    if chunk.nodes.len() == 1 {
        return validate_single_node_chunk_plan(chunk, output_count, stream_bound, limits);
    }
    let first_final_stream = stream_bound.saturating_sub(output_count);
    let mut graph = StreamGraph::new(stream_bound)?;
    let mut stream_cursor = 0usize;
    let mut header_end = 0usize;
    let mut regenerated = 0usize;
    for node in &chunk.nodes {
        let shape = validate_node_kind(node)?;
        if node.transform_header_start != header_end {
            return Err(Error::new(ErrorKind::InvalidGraph).with_detail("transform header gap"));
        }
        header_end = checked_add(node.transform_header_start, node.transform_header_size)?;
        let input_end = checked_add(stream_cursor, node_input_count(node, shape)?)?;
        if input_end > first_final_stream {
            return Err(Error::new(ErrorKind::InvalidGraph)
                .with_detail("node input range reaches final output streams"));
        }
        let output_depth = graph.output_depth(stream_cursor, input_end, limits)?;
        validate_node_outputs(node, shape)?;
        let marked = graph.mark_regen_targets(node, input_end, output_depth)?;
        regenerated = checked_add(regenerated, marked)?;
        stream_cursor = input_end;
    }
    if header_end != chunk.transform_header_bytes {
        return Err(
            Error::new(ErrorKind::InvalidGraph).with_detail("transform header size mismatch")
        );
    }
    validate_stream_totals(chunk, regenerated)?;
    graph.validate_final_outputs(first_final_stream, chunk.stored_streams())
}

/// Which streams of a chunk the nodes regenerate, and each stream's depth
/// in the graph.
struct StreamGraph {
    produced: Vec<bool>,
    depths: Vec<usize>,
}

impl StreamGraph {
    fn new(stream_bound: usize) -> Result<Self> {
        let mut produced = Vec::new();
        produced.try_reserve_exact(stream_bound).map_err(|_| {
            Error::new(ErrorKind::AllocationFailed)
                .with_detail("regen target validation allocation failed")
        })?;
        produced.resize(stream_bound, false);
        let mut depths = Vec::new();
        depths.try_reserve_exact(stream_bound).map_err(|_| {
            Error::new(ErrorKind::AllocationFailed)
                .with_detail("stream depth validation allocation failed")
        })?;
        depths.resize(stream_bound, 0usize);
        Ok(Self { produced, depths })
    }

    /// Depth of the outputs of a node reading streams `start..end`.
    fn output_depth(&self, start: usize, end: usize, limits: Limits) -> Result<usize> {
        let input_depth = self.depths[start..end].iter().copied().max().unwrap_or(0);
        let output_depth = checked_add(input_depth, 1)?;
        check_limit(output_depth, limits.max_graph_depth, "max_graph_depth")?;
        Ok(output_depth)
    }

    /// Marks the streams `node` regenerates and returns how many it marked.
    fn mark_regen_targets(
        &mut self,
        node: &NodePlan,
        input_end: usize,
        output_depth: usize,
    ) -> Result<usize> {
        for &distance in &node.regen_distances {
            let distance =
                usize::try_from(distance).map_err(|_| Error::new(ErrorKind::LimitExceeded))?;
            let target = checked_add(input_end, distance)?;
            if target >= self.produced.len() {
                return Err(Error::new(ErrorKind::InvalidGraph)
                    .with_detail("regen stream distance is out of bounds"));
            }
            if self.produced[target] {
                return Err(Error::new(ErrorKind::InvalidGraph)
                    .with_detail("duplicate regen stream distance"));
            }
            self.produced[target] = true;
            self.depths[target] = output_depth;
        }
        Ok(node.regen_distances.len())
    }

    /// Final outputs no node regenerates must be stored streams.
    fn validate_final_outputs(&self, first_final_stream: usize, stored: usize) -> Result<()> {
        let finals = self.produced.get(first_final_stream..).unwrap_or_default();
        let stored_final_outputs = finals.iter().filter(|&&produced| !produced).count();
        if stored_final_outputs > stored {
            return Err(Error::new(ErrorKind::InvalidGraph)
                .with_detail("final output stream is not produced"));
        }
        Ok(())
    }
}

pub(super) fn validate_single_node_chunk_plan(
    chunk: &ChunkPlan,
    output_count: usize,
    stream_bound: usize,
    limits: Limits,
) -> Result<()> {
    let first_final_stream = stream_bound.saturating_sub(output_count);
    let node = &chunk.nodes[0];
    let shape = validate_node_kind(node)?;
    if node.transform_header_start != 0 {
        return Err(Error::new(ErrorKind::InvalidGraph).with_detail("transform header gap"));
    }
    if node.transform_header_size != chunk.transform_header_bytes {
        return Err(
            Error::new(ErrorKind::InvalidGraph).with_detail("transform header size mismatch")
        );
    }
    let input_count = node_input_count(node, shape)?;
    if input_count > first_final_stream {
        return Err(Error::new(ErrorKind::InvalidGraph)
            .with_detail("node input range reaches final output streams"));
    }
    check_limit(1, limits.max_graph_depth, "max_graph_depth")?;
    validate_node_outputs(node, shape)?;
    let produced_final_outputs =
        single_node_final_outputs(node, input_count, stream_bound, first_final_stream)?;
    validate_stream_totals(chunk, node.regen_distances.len())?;
    let stored_final_outputs = output_count.saturating_sub(produced_final_outputs);
    if stored_final_outputs > chunk.stored_streams() {
        return Err(
            Error::new(ErrorKind::InvalidGraph).with_detail("final output stream is not produced")
        );
    }
    Ok(())
}

/// Checks the only node's regen distances without allocating and returns
/// how many final outputs it regenerates.
fn single_node_final_outputs(
    node: &NodePlan,
    input_count: usize,
    stream_bound: usize,
    first_final_stream: usize,
) -> Result<usize> {
    let mut produced_final_outputs = 0usize;
    for &distance in &node.regen_distances {
        let distance =
            usize::try_from(distance).map_err(|_| Error::new(ErrorKind::LimitExceeded))?;
        let target = checked_add(input_count, distance)?;
        if target >= stream_bound {
            return Err(Error::new(ErrorKind::InvalidGraph)
                .with_detail("regen stream distance is out of bounds"));
        }
        if target >= first_final_stream {
            produced_final_outputs = checked_add(produced_final_outputs, 1)?;
        }
    }
    let distances = &node.regen_distances;
    if (1..distances.len()).any(|index| distances[..index].contains(&distances[index])) {
        return Err(
            Error::new(ErrorKind::InvalidGraph).with_detail("duplicate regen stream distance")
        );
    }
    Ok(produced_final_outputs)
}

/// The node's transform ID is a standard one this decoder knows.
fn validate_node_kind(node: &NodePlan) -> Result<NodeShape> {
    if node.transform_type == TransformType::Standard && node.transform_id >= 128 {
        return Err(Error::new(ErrorKind::Unsupported)
            .with_detail("standard transform ID is outside the OpenZL range"));
    }
    validate_known_standard_node_shape(node)
}

/// Number of streams the node reads: its static inputs plus its variable
/// ones, if its shape allows them.
fn node_input_count(node: &NodePlan, shape: NodeShape) -> Result<usize> {
    let variable_inputs =
        usize::try_from(node.variable_outputs).map_err(|_| Error::new(ErrorKind::LimitExceeded))?;
    if variable_inputs > 0 && !shape.variable_inputs {
        return Err(
            Error::new(ErrorKind::InvalidGraph).with_detail("node has unexpected variable inputs")
        );
    }
    checked_add(shape.static_inputs, variable_inputs)
}

/// The node's output count fits its shape, and it names no dictionary a
/// custom transform would need.
fn validate_node_outputs(node: &NodePlan, shape: NodeShape) -> Result<()> {
    validate_node_output_count(node, shape)?;
    if node.dict_index.is_some() && node.transform_type == TransformType::Custom {
        return Err(Error::new(ErrorKind::Unsupported)
            .with_detail("custom transform dictionaries are unsupported"));
    }
    Ok(())
}

/// The chunk's regenerated stream count and stored stream sizes and ranges
/// match its header.
fn validate_stream_totals(chunk: &ChunkPlan, regenerated: usize) -> Result<()> {
    if regenerated != chunk.regenerated_streams() {
        return Err(
            Error::new(ErrorKind::InvalidGraph).with_detail("regenerated stream count mismatch")
        );
    }
    if sum_usize(&chunk.stored_stream_sizes)? != chunk.stored_stream_bytes {
        return Err(Error::new(ErrorKind::InvalidGraph).with_detail("stored stream size mismatch"));
    }
    if chunk.stored_stream_ranges.len() != chunk.stored_stream_sizes.len() {
        return Err(
            Error::new(ErrorKind::InvalidGraph).with_detail("stored stream range count mismatch")
        );
    }
    let mut expected_start = checked_add(
        chunk.transform_header_range.start,
        chunk.transform_header_range.len,
    )?;
    for (range, &size) in chunk
        .stored_stream_ranges
        .iter()
        .zip(chunk.stored_stream_sizes.iter())
    {
        if range.start != expected_start || range.len != size {
            return Err(
                Error::new(ErrorKind::InvalidGraph).with_detail("stored stream range mismatch")
            );
        }
        expected_start = checked_add(range.start, range.len)?;
    }
    Ok(())
}

pub(super) fn validate_known_standard_node_shape(node: &NodePlan) -> Result<NodeShape> {
    let Some(id) = node.standard_id() else {
        return Err(Error::new(ErrorKind::Unsupported)
            .with_detail("custom OpenZL transforms are not implemented"));
    };
    let shape = standard::standard_node(id)
        .map(|node| node.shape)
        .ok_or_else(|| {
            Error::new(ErrorKind::Unsupported).with_detail(format!(
                "standard transform graph shape is unsupported: id={id}"
            ))
        })?;
    Ok(shape)
}

pub(super) fn validate_node_output_count(node: &NodePlan, shape: NodeShape) -> Result<()> {
    if node.regen_distances.len() < shape.min_outputs {
        return Err(
            Error::new(ErrorKind::InvalidGraph).with_detail("node has too few output streams")
        );
    }
    if let Some(max_outputs) = shape.max_outputs
        && node.regen_distances.len() > max_outputs
    {
        return Err(
            Error::new(ErrorKind::InvalidGraph).with_detail("node has too many output streams")
        );
    }
    Ok(())
}
