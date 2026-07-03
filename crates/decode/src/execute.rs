use alloc::{format, vec, vec::Vec};

use ozlrip_core::{Error, ErrorKind, FrameValueType, Limits, Result};
use smallvec::{SmallVec, smallvec};
use zrip_core::{
    bitstream::{reader::BitReader, reader_reverse::ReverseBitReader},
    fse::{
        FseDecodeEntry,
        table_builder::{build_decode_table, parse_fse_table_description},
    },
    huffman::{HuffmanDecodeEntry, decode},
};

#[cfg(feature = "zstd")]
use crate::parse::SingleZstdFrame;
use crate::{parse::FramePlan, standard};

#[cfg(test)]
pub(crate) fn decode_plan(
    input: &[u8],
    plan: &FramePlan,
    dst: &mut Vec<u8>,
    limits: Limits,
) -> Result<usize> {
    #[cfg(feature = "zstd")]
    let mut zstd = zrip::DecompressContext::new();
    decode_plan_with_context(
        input,
        plan,
        dst,
        limits,
        #[cfg(feature = "zstd")]
        &mut zstd,
    )
}

pub(crate) fn decode_plan_with_context(
    input: &[u8],
    plan: &FramePlan,
    dst: &mut Vec<u8>,
    limits: Limits,
    #[cfg(feature = "zstd")] zstd: &mut zrip::DecompressContext,
) -> Result<usize> {
    if plan.info.dictionary_bundle_id.is_some() {
        return Err(Error::new(ErrorKind::Unsupported)
            .with_detail("dictionary bundle materialization is not implemented"));
    }
    if let Some(written) = try_decode_single_zstd_into_dst(
        input,
        plan,
        dst,
        limits,
        #[cfg(feature = "zstd")]
        zstd,
    )? {
        return Ok(written);
    }
    let decoded = collect_decoded_output(
        input,
        plan,
        limits,
        #[cfg(feature = "zstd")]
        zstd,
    )?;
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

#[cfg(feature = "zstd")]
pub(crate) fn decode_single_zstd_frame_with_context(
    input: &[u8],
    frame: SingleZstdFrame,
    dst: &mut Vec<u8>,
    limits: Limits,
    zstd: &mut zrip::DecompressContext,
) -> Result<usize> {
    let stored = frame.stored.as_slice(input)?;
    let mut offset = 0usize;
    let element_width = read_var_u64(stored, &mut offset)?;
    if element_width != 1 {
        return Err(Error::new(ErrorKind::Unsupported)
            .with_detail("zstd serial streams with non-byte elements are unsupported"));
    }
    let magicless = stored
        .get(offset..)
        .ok_or_else(|| Error::at(ErrorKind::Truncated, offset))?;
    let start = dst.len();
    let written = match zstd.decompress_after_magic_into(magicless, dst, limits.max_decoded_bytes) {
        Ok(written) => written,
        Err(err) => {
            dst.truncate(start);
            return Err(map_zstd_error(&err));
        }
    };
    if written > limits.max_buffer_bytes {
        dst.truncate(start);
        return Err(
            Error::new(ErrorKind::LimitExceeded).with_detail("decoded output limit exceeded")
        );
    }
    if let Some(expected) = frame.decoded_bytes
        && expected != written
    {
        dst.truncate(start);
        return Err(Error::new(ErrorKind::Malformed).with_detail("decoded output size mismatch"));
    }
    if frame.frame_bytes > 0 && written / frame.frame_bytes > limits.max_expansion_ratio {
        dst.truncate(start);
        return Err(Error::new(ErrorKind::LimitExceeded).with_detail("expansion ratio exceeded"));
    }
    #[cfg(feature = "checksum")]
    if let Err(err) = verify_decoded_checksum(&dst[start..], frame.decoded_checksum) {
        dst.truncate(start);
        return Err(err);
    }
    #[cfg(not(feature = "checksum"))]
    let _ = frame.decoded_checksum;
    Ok(written)
}

#[cfg(feature = "zstd")]
fn try_decode_single_zstd_into_dst(
    input: &[u8],
    plan: &FramePlan,
    dst: &mut Vec<u8>,
    limits: Limits,
    zstd: &mut zrip::DecompressContext,
) -> Result<Option<usize>> {
    if plan.info.output_types.as_slice() != [FrameValueType::Serial] || plan.chunks.len() != 1 {
        return Ok(None);
    }
    let chunk = &plan.chunks[0];
    let [node] = chunk.nodes() else {
        return Ok(None);
    };
    if node.standard_id() != Some(standard::ZSTD_ID)
        || node.variable_outputs() != 0
        || node.regen_distances() != [0]
        || node.transform_header_size() != 0
        || node.transform_header_start() != 0
        || chunk.stored_streams() != 1
    {
        return Ok(None);
    }

    let stored = chunk
        .stored_stream_range(0)
        .ok_or_else(|| {
            Error::new(ErrorKind::InvalidGraph).with_detail("zstd input stream is missing")
        })?
        .as_slice(input)?;
    let mut offset = 0usize;
    let element_width = read_var_u64(stored, &mut offset)?;
    if element_width == 0 || element_width != 1 {
        return Ok(None);
    }
    let magicless = stored
        .get(offset..)
        .ok_or_else(|| Error::at(ErrorKind::Truncated, offset))?;
    let start = dst.len();
    let written = match zstd.decompress_after_magic_into(magicless, dst, limits.max_decoded_bytes) {
        Ok(written) => written,
        Err(err) => {
            dst.truncate(start);
            return Err(map_zstd_error(&err));
        }
    };
    if written > limits.max_buffer_bytes {
        dst.truncate(start);
        return Err(
            Error::new(ErrorKind::LimitExceeded).with_detail("decoded output limit exceeded")
        );
    }
    if let Err(err) = check_output_size(written, input.len(), plan, limits) {
        dst.truncate(start);
        return Err(err);
    }
    #[cfg(feature = "checksum")]
    if let Err(err) = verify_decoded_checksum(&dst[start..], chunk.decoded_checksum) {
        dst.truncate(start);
        return Err(err);
    }
    #[cfg(not(feature = "checksum"))]
    let _ = chunk.decoded_checksum;
    Ok(Some(written))
}

#[cfg(not(feature = "zstd"))]
fn try_decode_single_zstd_into_dst(
    _input: &[u8],
    _plan: &FramePlan,
    _dst: &mut Vec<u8>,
    _limits: Limits,
) -> Result<Option<usize>> {
    Ok(None)
}

fn collect_decoded_output<'a>(
    input: &'a [u8],
    plan: &FramePlan,
    limits: Limits,
    #[cfg(feature = "zstd")] zstd: &mut zrip::DecompressContext,
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
    for chunk in &plan.chunks {
        let decoded = if chunk.has_nodes() {
            decode_transform_chunk(
                input,
                chunk,
                plan.info.format_version,
                limits,
                #[cfg(feature = "zstd")]
                zstd,
            )?
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
    #[cfg(feature = "zstd")] zstd: &mut zrip::DecompressContext,
) -> Result<DecodedChunk<'a>> {
    let plan = build_chunk_execution_plan(chunk)?;
    let mut streams = initialize_stream_slots(input, chunk, &plan.regen_targets)?;
    let transform_headers = chunk.transform_header_range().as_slice(input)?;

    for node in plan.nodes {
        let header = node_header(transform_headers, node.header_start, node.header_size)?;
        if try_execute_single_input_splitn_node(&mut streams, &node, header, limits)? {
            continue;
        }
        if try_execute_byte_preserving_conversion_node(&mut streams, &node, header, limits)? {
            continue;
        }

        let inputs = collect_node_inputs(&streams, node.input_start, node.input_count)?;
        let outputs = execute_standard_node(
            node.standard_id,
            &inputs,
            node.variable_inputs,
            header,
            format_version,
            limits,
            #[cfg(feature = "zstd")]
            zstd,
        )?;
        drop(inputs);
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

fn try_execute_single_input_splitn_node(
    streams: &mut [StreamSlot<'_>],
    node: &NodeExecutionPlan,
    header: &[u8],
    limits: Limits,
) -> Result<bool> {
    if !matches!(
        node.standard_id,
        standard::SPLITN_ID | standard::SPLITN_STRUCT_ID
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
            let [int_log] = header else {
                return Err(Error::new(ErrorKind::Malformed)
                    .with_detail("convert_num_to_serial_le header is malformed"));
            };
            if *int_log > 3 {
                return Err(Error::new(ErrorKind::Malformed)
                    .with_detail("convert_num_to_serial_le integer width is invalid"));
            }
            let int_size = 1usize
                .checked_shl(u32::from(*int_log))
                .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
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

struct ChunkExecutionPlan {
    nodes: Vec<NodeExecutionPlan>,
    regen_targets: Vec<bool>,
}

struct NodeExecutionPlan {
    standard_id: u32,
    input_start: usize,
    input_count: usize,
    output_targets: SmallVec<[usize; 2]>,
    variable_inputs: u32,
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
        let input_count = standard_node_input_count(standard_id, variable_inputs)?;
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
        | standard::CONVERT_STRUCT_TO_NUM_LE_ID
        | standard::CONVERT_NUM_TO_STRUCT_LE_ID
        | standard::CONVERT_SERIAL_TO_NUM_LE_ID
        | standard::CONVERT_NUM_TO_SERIAL_LE_ID
        | standard::CONVERT_STRING_TO_SERIAL_ID
        | standard::CONVERT_SERIAL_TO_STRUCT_ID
        | standard::CONVERT_STRUCT_TO_SERIAL_ID
        | standard::ZIGZAG_ID
        | standard::DELTA_INT_ID
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

fn execute_standard_node(
    standard_id: u32,
    inputs: &[StreamInput<'_>],
    variable_inputs: u32,
    header: &[u8],
    format_version: u32,
    limits: Limits,
    #[cfg(feature = "zstd")] zstd: &mut zrip::DecompressContext,
) -> Result<SmallVec<[OwnedStream; 2]>> {
    match standard_id {
        standard::CONCAT_SERIAL_ID | standard::CONCAT_NUM_ID | standard::CONCAT_STRUCT_ID => {
            decode_concat_node(inputs, header, limits).map(SmallVec::from_vec)
        }
        standard::SPLITN_ID => {
            one_serial(decode_splitn_node(inputs, variable_inputs, header, limits))
        }
        standard::SPLITN_STRUCT_ID => one_typed(decode_splitn_typed_node(
            inputs,
            variable_inputs,
            header,
            limits,
        )),
        standard::SPLIT_BY_STRUCT_ID => one_typed(decode_split_by_struct_node(
            inputs,
            variable_inputs,
            header,
            limits,
        )),
        standard::FLATPACK_ID => one_serial(decode_flatpack_node(inputs, header, limits)),
        standard::SEPARATE_STRING_COMPONENTS_ID => one_typed(
            decode_separate_string_components_node(inputs, header, limits),
        ),
        standard::CONVERT_STRING_TO_SERIAL_ID => one_serial(decode_string_to_serial_node(
            single_stream(inputs)?,
            header,
            limits,
        )),
        standard::DISPATCH_STRING_ID => one_typed(decode_dispatch_string_node(
            inputs,
            variable_inputs,
            header,
            format_version,
            limits,
        )),
        standard::DISPATCH_N_BY_TAG_ID => one_serial(decode_dispatch_n_by_tag_node(
            inputs,
            variable_inputs,
            header,
            format_version,
            limits,
        )),
        standard::SENTINEL_ID => one_typed(decode_sentinel_node(inputs, header, limits)),
        id if is_transpose_split(id) => one_typed(decode_transpose_split_node(
            inputs,
            variable_inputs,
            header,
            limits,
        )),
        standard::LZ4_ID => one_serial(decode_lz4_chunk(single_input(inputs)?, header, limits)),
        standard::ZSTD_ID => one_serial(decode_zstd_chunk(
            single_input(inputs)?,
            header,
            limits,
            #[cfg(feature = "zstd")]
            zstd,
        )),
        standard::BITPACK_SERIAL_ID => one_serial(decode_bitpack_serial_chunk(
            single_input(inputs)?,
            header,
            limits,
        )),
        standard::BITPACK_INT_ID => one_typed(decode_bitpack_int_chunk(
            single_input(inputs)?,
            header,
            limits,
        )),
        standard::CONSTANT_SERIAL_ID => one_serial(decode_constant_serial_chunk(
            single_input(inputs)?,
            header,
            limits,
        )),
        standard::CONVERT_SERIAL_TO_STRUCT_ID => one_typed(
            decode_byte_preserving_conversion_chunk(single_stream(inputs)?, header, limits),
        ),
        standard::CONVERT_STRUCT_TO_SERIAL_ID => one_typed(decode_serial_to_struct_chunk(
            single_stream(inputs)?,
            header,
            limits,
        )),
        standard::CONVERT_STRUCT_TO_NUM_LE_ID | standard::CONVERT_NUM_TO_STRUCT_LE_ID => one_typed(
            decode_num_to_struct_le_chunk(single_stream(inputs)?, header, limits),
        ),
        standard::CONVERT_SERIAL_TO_NUM_LE_ID => one_serial(decode_numeric_to_serial_le_chunk(
            single_stream(inputs)?,
            header,
            limits,
        )),
        standard::CONVERT_NUM_TO_SERIAL_LE_ID => one_typed(decode_serial_to_numeric_le_chunk(
            single_stream(inputs)?,
            header,
            limits,
        )),
        standard::MUX_LENGTHS_ID => {
            decode_mux_lengths_node(inputs, header, limits).map(SmallVec::from_vec)
        }
        standard::LZ_ID => one_serial(decode_lz_node(inputs, header, limits)),
        standard::FIELD_LZ_ID => one_typed(decode_field_lz_node(inputs, header, limits)),
        standard::ZIGZAG_ID => one_typed(decode_zigzag_numeric_chunk(
            single_stream(inputs)?,
            header,
            limits,
        )),
        standard::DELTA_INT_ID => {
            one_typed(decode_delta_node(single_stream(inputs)?, header, limits))
        }
        standard::BITUNPACK_ID => one_serial(decode_bitunpack_serial8_chunk(
            single_input(inputs)?,
            header,
            limits,
        )),
        standard::BIT_SPLIT_ID => one_typed(decode_bitsplit_node(
            inputs,
            variable_inputs,
            header,
            limits,
        )),
        standard::RANGE_PACK_ID => one_serial(decode_range_pack_serial8_chunk(
            single_input(inputs)?,
            header,
            limits,
        )),
        standard::FSE_NCOUNT_ID => one_typed(decode_fse_ncount_node(
            single_stream(inputs)?,
            header,
            limits,
        )),
        standard::FSE_V2_ID => one_serial(decode_fse_v2_node(inputs, header, limits)),
        standard::HUFFMAN_V2_ID => one_serial(decode_huffman_v2_node(inputs, header, limits)),
        standard::QUANTIZE_OFFSETS_ID => one_typed(decode_quantize_node(
            inputs,
            header,
            limits,
            &QUANTIZE_OFFSETS,
        )),
        standard::QUANTIZE_LENGTHS_ID => one_typed(decode_quantize_node(
            inputs,
            header,
            limits,
            &QUANTIZE_LENGTHS,
        )),
        standard::PARTITION_ID => one_typed(decode_partition_node(inputs, header, limits)),
        standard::TOKENIZE_FIXED_ID | standard::TOKENIZE_NUMERIC_ID => {
            one_typed(decode_tokenize_fixed_node(inputs, header, limits))
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
}

impl OwnedStream {
    fn serial(bytes: Vec<u8>) -> Self {
        Self {
            bytes,
            element_width: 1,
            string_lengths: None,
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
) -> Result<OwnedStream> {
    if !header.is_empty() {
        return Err(Error::new(ErrorKind::Unsupported)
            .with_detail("transpose_split transform headers are unsupported"));
    }
    if variable_inputs != 0
        && usize::try_from(variable_inputs)
            .ok()
            .is_some_and(|count| count != inputs.len())
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
    let mut output = Vec::new();
    output.try_reserve_exact(output_len).map_err(|_| {
        Error::new(ErrorKind::LimitExceeded).with_detail("transpose allocation failed")
    })?;
    for element in 0..lane_len {
        for lane in inputs {
            output.push(lane.bytes[element]);
        }
    }
    Ok(OwnedStream {
        bytes: output,
        element_width: width,
        string_lengths: None,
    })
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
    let mut total = 0usize;
    let mut string_lengths = Vec::new();
    string_lengths.try_reserve_exact(field_count).map_err(|_| {
        Error::new(ErrorKind::LimitExceeded).with_detail("string length allocation failed")
    })?;
    for index in 0..field_count {
        let size = read_usize_numeric_element(field_sizes.bytes, field_sizes.element_width, index)?;
        total = total
            .checked_add(size)
            .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
        string_lengths.push(u32::try_from(size).map_err(|_| {
            Error::new(ErrorKind::LimitExceeded).with_detail("string field size is too large")
        })?);
    }
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
    })
}

fn decode_dispatch_string_node(
    inputs: &[StreamInput<'_>],
    variable_inputs: u32,
    header: &[u8],
    format_version: u32,
    limits: Limits,
) -> Result<OwnedStream> {
    if !header.is_empty() {
        return Err(
            Error::new(ErrorKind::Malformed).with_detail("dispatch_string header must be empty")
        );
    }
    let variable_inputs = usize::try_from(variable_inputs)
        .map_err(|_| Error::new(ErrorKind::LimitExceeded).with_detail("input count too large"))?;
    if inputs.len()
        != variable_inputs
            .checked_add(1)
            .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?
    {
        return Err(Error::new(ErrorKind::InvalidGraph)
            .with_detail("dispatch_string input count does not match node shape"));
    }
    let (indices, string_inputs) = inputs.split_first().ok_or_else(|| {
        Error::new(ErrorKind::InvalidGraph).with_detail("dispatch_string index stream is missing")
    })?;
    let expected_index_width = if format_version < 21 { 1 } else { 2 };
    require_numeric_width(indices, expected_index_width, "dispatch_string indices")?;
    let index_count = numeric_element_count(indices.bytes, indices.element_width)?;
    if index_count != 0 && string_inputs.is_empty() {
        return Err(Error::new(ErrorKind::Malformed)
            .with_detail("dispatch_string indices require string inputs"));
    }
    let mut sources = Vec::new();
    sources
        .try_reserve_exact(string_inputs.len())
        .map_err(|_| {
            Error::new(ErrorKind::LimitExceeded).with_detail("dispatch allocation failed")
        })?;
    let mut total_string_count = 0usize;
    let mut total_bytes = 0usize;
    for input in string_inputs {
        if input.element_width != 1 {
            return Err(Error::new(ErrorKind::InvalidType)
                .with_detail("dispatch_string inputs must be byte strings"));
        }
        let lengths = input.string_lengths.ok_or_else(|| {
            Error::new(ErrorKind::InvalidType)
                .with_detail("dispatch_string input is missing string lengths")
        })?;
        let byte_total = checked_sum_u32(lengths)?;
        if byte_total != input.bytes.len() {
            return Err(Error::new(ErrorKind::Malformed)
                .with_detail("dispatch_string input lengths do not sum to content size"));
        }
        total_string_count = total_string_count
            .checked_add(lengths.len())
            .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
        total_bytes = total_bytes
            .checked_add(byte_total)
            .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
        let mut offsets = Vec::new();
        offsets.try_reserve_exact(lengths.len()).map_err(|_| {
            Error::new(ErrorKind::LimitExceeded).with_detail("dispatch allocation failed")
        })?;
        let mut offset = 0usize;
        for &length in lengths {
            offsets.push(offset);
            offset = offset
                .checked_add(usize::try_from(length).map_err(|_| {
                    Error::new(ErrorKind::LimitExceeded).with_detail("string length too large")
                })?)
                .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
        }
        sources.push(DispatchStringSource {
            bytes: input.bytes,
            lengths,
            offsets,
            position: 0,
        });
    }
    if index_count != total_string_count {
        return Err(Error::new(ErrorKind::Malformed)
            .with_detail("dispatch_string index count does not match string count"));
    }
    if total_bytes > limits.max_decoded_bytes || total_bytes > limits.max_buffer_bytes {
        return Err(
            Error::new(ErrorKind::LimitExceeded).with_detail("decoded output limit exceeded")
        );
    }
    let mut output = Vec::new();
    output.try_reserve_exact(total_bytes).map_err(|_| {
        Error::new(ErrorKind::LimitExceeded).with_detail("dispatch output allocation failed")
    })?;
    let mut output_lengths = Vec::new();
    output_lengths.try_reserve_exact(index_count).map_err(|_| {
        Error::new(ErrorKind::LimitExceeded).with_detail("dispatch length allocation failed")
    })?;
    match indices.element_width {
        1 => {
            for &source in indices.bytes {
                append_dispatched_string(
                    usize::from(source),
                    &mut sources,
                    &mut output,
                    &mut output_lengths,
                )?;
            }
        }
        2 => {
            for source in indices.bytes.chunks_exact(2) {
                append_dispatched_string(
                    usize::from(u16::from_le_bytes([source[0], source[1]])),
                    &mut sources,
                    &mut output,
                    &mut output_lengths,
                )?;
            }
        }
        _ => unreachable!("require_numeric_width accepted only the expected dispatch width"),
    }
    for source in sources {
        if source.position != source.lengths.len() {
            return Err(Error::new(ErrorKind::Malformed)
                .with_detail("dispatch_string did not consume every source string"));
        }
    }
    Ok(OwnedStream {
        bytes: output,
        element_width: 1,
        string_lengths: Some(output_lengths),
    })
}

struct DispatchStringSource<'a> {
    bytes: &'a [u8],
    lengths: &'a [u32],
    offsets: Vec<usize>,
    position: usize,
}

#[expect(
    clippy::inline_always,
    reason = "profiled CSV dispatch hot path benefits from inlining this leaf"
)]
#[inline(always)]
fn append_dispatched_string(
    source: usize,
    sources: &mut [DispatchStringSource<'_>],
    output: &mut Vec<u8>,
    output_lengths: &mut Vec<u32>,
) -> Result<()> {
    let source = sources.get_mut(source).ok_or_else(|| {
        Error::new(ErrorKind::Malformed).with_detail("dispatch_string source index is invalid")
    })?;
    let length = *source.lengths.get(source.position).ok_or_else(|| {
        Error::new(ErrorKind::Malformed).with_detail("dispatch_string source is exhausted")
    })?;
    let offset = source.offsets[source.position];
    let length_usize = usize::try_from(length)
        .map_err(|_| Error::new(ErrorKind::LimitExceeded).with_detail("string length too large"))?;
    let end = offset
        .checked_add(length_usize)
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
    let bytes = source.bytes.get(offset..end).ok_or_else(|| {
        Error::new(ErrorKind::Malformed).with_detail("dispatch_string range is invalid")
    })?;
    output.extend_from_slice(bytes);
    output_lengths.push(length);
    source.position = source
        .position
        .checked_add(1)
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
    Ok(())
}

fn decode_dispatch_n_by_tag_node(
    inputs: &[StreamInput<'_>],
    variable_inputs: u32,
    header: &[u8],
    format_version: u32,
    limits: Limits,
) -> Result<Vec<u8>> {
    if !header.is_empty() {
        return Err(
            Error::new(ErrorKind::Malformed).with_detail("dispatchN_byTag header must be empty")
        );
    }
    let variable_inputs = usize::try_from(variable_inputs)
        .map_err(|_| Error::new(ErrorKind::LimitExceeded).with_detail("input count too large"))?;
    if inputs.len()
        != variable_inputs
            .checked_add(2)
            .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?
    {
        return Err(Error::new(ErrorKind::InvalidGraph)
            .with_detail("dispatchN_byTag input count does not match node shape"));
    }
    let [tags, segment_sizes, segment_inputs @ ..] = inputs else {
        return Err(Error::new(ErrorKind::InvalidGraph)
            .with_detail("dispatchN_byTag input count does not match node shape"));
    };
    if segment_inputs.len() != variable_inputs {
        return Err(Error::new(ErrorKind::InvalidGraph)
            .with_detail("dispatchN_byTag variable input count does not match node shape"));
    }
    let expected_tag_width = if format_version < 20 { 1 } else { 2 };
    if tags.element_width > expected_tag_width {
        return Err(Error::new(ErrorKind::Unsupported)
            .with_detail("dispatchN_byTag tag width is unsupported"));
    }
    validate_numeric_stream_width(tags.element_width, "dispatchN_byTag tags")?;
    validate_numeric_stream_width(segment_sizes.element_width, "dispatchN_byTag segment sizes")?;
    let segment_count = numeric_element_count(segment_sizes.bytes, segment_sizes.element_width)?;
    if numeric_element_count(tags.bytes, tags.element_width)? != segment_count {
        return Err(Error::new(ErrorKind::Malformed)
            .with_detail("dispatchN_byTag tag count does not match segment count"));
    }
    if segment_count != 0 && segment_inputs.is_empty() {
        return Err(Error::new(ErrorKind::Malformed)
            .with_detail("dispatchN_byTag segments require source streams"));
    }
    if format_version < 20 && segment_inputs.len() >= 256 {
        return Err(Error::new(ErrorKind::Unsupported)
            .with_detail("dispatchN_byTag source count is unsupported"));
    }
    if format_version >= 20 && segment_inputs.len() >= (1usize << 16) {
        return Err(Error::new(ErrorKind::Unsupported)
            .with_detail("dispatchN_byTag source count is unsupported"));
    }

    let mut source_totals = Vec::new();
    source_totals
        .try_reserve_exact(segment_inputs.len())
        .map_err(|_| {
            Error::new(ErrorKind::LimitExceeded).with_detail("dispatchN_byTag allocation failed")
        })?;
    let mut total_output = 0usize;
    for input in segment_inputs {
        if input.element_width == 0 {
            return Err(Error::new(ErrorKind::InvalidType)
                .with_detail("dispatchN_byTag source width is zero"));
        }
        source_totals.push(0usize);
        total_output = total_output
            .checked_add(input.bytes.len())
            .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
    }
    if total_output > limits.max_decoded_bytes || total_output > limits.max_buffer_bytes {
        return Err(
            Error::new(ErrorKind::LimitExceeded).with_detail("decoded output limit exceeded")
        );
    }

    for segment in 0..segment_count {
        let tag = read_usize_numeric_element(tags.bytes, tags.element_width, segment)?;
        let size =
            read_usize_numeric_element(segment_sizes.bytes, segment_sizes.element_width, segment)?;
        let source_total = source_totals.get_mut(tag).ok_or_else(|| {
            Error::new(ErrorKind::Malformed).with_detail("dispatchN_byTag tag is out of range")
        })?;
        *source_total = source_total
            .checked_add(size)
            .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
    }
    for (total, input) in source_totals.iter().zip(segment_inputs) {
        if *total != input.bytes.len() {
            return Err(Error::new(ErrorKind::Malformed)
                .with_detail("dispatchN_byTag segment sizes do not consume source stream"));
        }
    }

    let mut source_positions = vec![0usize; segment_inputs.len()];
    let mut output = Vec::new();
    output.try_reserve_exact(total_output).map_err(|_| {
        Error::new(ErrorKind::LimitExceeded).with_detail("dispatchN_byTag output allocation failed")
    })?;
    for segment in 0..segment_count {
        let tag = read_usize_numeric_element(tags.bytes, tags.element_width, segment)?;
        let size =
            read_usize_numeric_element(segment_sizes.bytes, segment_sizes.element_width, segment)?;
        let input = segment_inputs.get(tag).ok_or_else(|| {
            Error::new(ErrorKind::Malformed).with_detail("dispatchN_byTag tag is out of range")
        })?;
        let position = source_positions.get_mut(tag).ok_or_else(|| {
            Error::new(ErrorKind::Malformed).with_detail("dispatchN_byTag tag is out of range")
        })?;
        let end = position
            .checked_add(size)
            .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
        let segment_bytes = input.bytes.get(*position..end).ok_or_else(|| {
            Error::new(ErrorKind::Malformed)
                .with_detail("dispatchN_byTag source stream is truncated")
        })?;
        output.extend_from_slice(segment_bytes);
        *position = end;
    }
    if output.len() != total_output {
        return Err(
            Error::new(ErrorKind::Malformed).with_detail("dispatchN_byTag output size mismatch")
        );
    }
    Ok(output)
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
    if output_len > limits.max_decoded_bytes || output_len > limits.max_buffer_bytes {
        return Err(
            Error::new(ErrorKind::LimitExceeded).with_detail("decoded output limit exceeded")
        );
    }
    let mut output = Vec::new();
    output.try_reserve_exact(output_len).map_err(|_| {
        Error::new(ErrorKind::LimitExceeded).with_detail("split_by_struct allocation failed")
    })?;
    for element in 0..element_count {
        for input in inputs {
            let start = element
                .checked_mul(input.element_width)
                .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
            let end = start
                .checked_add(input.element_width)
                .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
            output.extend_from_slice(&input.bytes[start..end]);
        }
    }
    Ok(OwnedStream {
        bytes: output,
        element_width: 1,
        string_lengths: None,
    })
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
        },
        OwnedStream {
            bytes: match_lengths,
            element_width,
            string_lengths: None,
        },
    ])
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

#[inline]
fn write_numeric_element(dst: &mut [u8], element_width: usize, value: u64) {
    dst[..element_width].copy_from_slice(&value.to_le_bytes()[..element_width]);
}

fn decode_lz_node(inputs: &[StreamInput<'_>], header: &[u8], limits: Limits) -> Result<Vec<u8>> {
    let [literals, offsets, literal_lengths, match_lengths] = inputs else {
        return Err(Error::new(ErrorKind::InvalidGraph)
            .with_detail("lz input count does not match node shape"));
    };
    if literals.element_width != 1 {
        return Err(
            Error::new(ErrorKind::InvalidType).with_detail("lz literals must be serial bytes")
        );
    }
    validate_numeric_stream_width(offsets.element_width, "lz offsets")?;
    validate_numeric_stream_width(literal_lengths.element_width, "lz literal lengths")?;
    validate_numeric_stream_width(match_lengths.element_width, "lz match lengths")?;
    let sequence_count = numeric_element_count(offsets.bytes, offsets.element_width)?;
    if numeric_element_count(literal_lengths.bytes, literal_lengths.element_width)?
        != sequence_count
        || numeric_element_count(match_lengths.bytes, match_lengths.element_width)?
            != sequence_count
    {
        return Err(
            Error::new(ErrorKind::Malformed).with_detail("lz sequence stream counts do not match")
        );
    }

    let mut offset = 0usize;
    let output_len = read_var_u64(header, &mut offset)?;
    if offset != header.len() {
        return Err(Error::new(ErrorKind::Malformed).with_detail("lz header has trailing bytes"));
    }
    let output_len = usize::try_from(output_len).map_err(|_| {
        Error::new(ErrorKind::LimitExceeded).with_detail("lz output size is too large")
    })?;
    if output_len > limits.max_decoded_bytes || output_len > limits.max_buffer_bytes {
        return Err(
            Error::new(ErrorKind::LimitExceeded).with_detail("decoded output limit exceeded")
        );
    }
    let mut output = Vec::new();
    output
        .try_reserve_exact(output_len)
        .map_err(|_| Error::new(ErrorKind::LimitExceeded).with_detail("lz allocation failed"))?;
    output.resize(output_len, 0);

    let mut out_pos = 0usize;
    let mut lit_pos = 0usize;
    for sequence in 0..sequence_count {
        let literal_len = read_usize_numeric_element(
            literal_lengths.bytes,
            literal_lengths.element_width,
            sequence,
        )?;
        let match_offset =
            read_usize_numeric_element(offsets.bytes, offsets.element_width, sequence)?;
        let match_len =
            read_usize_numeric_element(match_lengths.bytes, match_lengths.element_width, sequence)?;

        let literal_end = lit_pos
            .checked_add(literal_len)
            .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
        let out_literal_end = out_pos
            .checked_add(literal_len)
            .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
        let literal_src = literals.bytes.get(lit_pos..literal_end).ok_or_else(|| {
            Error::new(ErrorKind::Malformed).with_detail("lz literal stream is too short")
        })?;
        if out_literal_end > output_len {
            return Err(Error::new(ErrorKind::Malformed)
                .with_detail("lz literal length exceeds output size"));
        }
        let literal_dst = output.get_mut(out_pos..out_literal_end).ok_or_else(|| {
            Error::new(ErrorKind::Malformed).with_detail("lz literal length exceeds output size")
        })?;
        literal_dst.copy_from_slice(literal_src);
        lit_pos = literal_end;
        out_pos = out_literal_end;

        if match_offset == 0 {
            return Err(Error::new(ErrorKind::Malformed).with_detail("lz offset is zero"));
        }
        if match_offset > out_pos {
            return Err(
                Error::new(ErrorKind::Malformed).with_detail("lz offset exceeds decoded prefix")
            );
        }
        let out_match_end = out_pos
            .checked_add(match_len)
            .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
        if out_match_end > output_len {
            return Err(
                Error::new(ErrorKind::Malformed).with_detail("lz match length exceeds output size")
            );
        }
        copy_lz_match(&mut output, out_pos, match_offset, match_len);
        out_pos = out_match_end;
    }

    let remaining_literals = literals.bytes.get(lit_pos..).ok_or_else(|| {
        Error::new(ErrorKind::Malformed).with_detail("lz literal stream is too short")
    })?;
    let out_end = out_pos
        .checked_add(remaining_literals.len())
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
    if out_end != output_len {
        return Err(
            Error::new(ErrorKind::Malformed).with_detail("lz output size does not match header")
        );
    }
    output[out_pos..].copy_from_slice(remaining_literals);
    Ok(output)
}

fn copy_lz_match(output: &mut [u8], out_pos: usize, match_offset: usize, match_len: usize) {
    if match_len == 0 {
        return;
    }
    let src_start = out_pos - match_offset;
    if match_len <= match_offset {
        output.copy_within(src_start..src_start + match_len, out_pos);
        return;
    }

    output.copy_within(src_start..out_pos, out_pos);
    let mut copied = match_offset;
    while copied < match_len {
        let len = copied.min(match_len - copied);
        output.copy_within(out_pos..out_pos + len, out_pos + copied);
        copied += len;
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
    if usize::try_from(variable_inputs)
        .ok()
        .is_some_and(|count| count != inputs.len())
    {
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

    Ok(OwnedStream {
        bytes: output,
        element_width: output_width,
        string_lengths: None,
    })
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

fn decode_field_lz_node(
    inputs: &[StreamInput<'_>],
    header: &[u8],
    limits: Limits,
) -> Result<OwnedStream> {
    let [
        literals,
        tokens,
        offsets,
        extra_literal_lengths,
        extra_match_lengths,
    ] = inputs
    else {
        return Err(Error::new(ErrorKind::InvalidGraph)
            .with_detail("field_lz input count does not match node shape"));
    };
    let element_width = literals.element_width;
    if !matches!(element_width, 1 | 2 | 4 | 8) {
        return Err(
            Error::new(ErrorKind::InvalidType).with_detail("field_lz literal width is unsupported")
        );
    }
    require_numeric_width(tokens, 2, "field_lz tokens")?;
    require_numeric_width(offsets, 4, "field_lz offsets")?;
    require_numeric_width(extra_literal_lengths, 4, "field_lz extra literal lengths")?;
    require_numeric_width(extra_match_lengths, 4, "field_lz extra match lengths")?;

    let mut header_offset = 0usize;
    let output_elements = read_var_u64(header, &mut header_offset)?;
    if header_offset != header.len() {
        return Err(
            Error::new(ErrorKind::Malformed).with_detail("field_lz header has trailing bytes")
        );
    }
    let output_elements = usize::try_from(output_elements).map_err(|_| {
        Error::new(ErrorKind::LimitExceeded).with_detail("field_lz output size is too large")
    })?;
    let output_capacity = output_elements
        .checked_mul(element_width)
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
    if output_capacity > limits.max_decoded_bytes || output_capacity > limits.max_buffer_bytes {
        return Err(
            Error::new(ErrorKind::LimitExceeded).with_detail("decoded output limit exceeded")
        );
    }

    let token_count = numeric_element_count(tokens.bytes, 2)?;
    let mut output = Vec::new();
    output.try_reserve_exact(output_capacity).map_err(|_| {
        Error::new(ErrorKind::LimitExceeded).with_detail("field_lz allocation failed")
    })?;

    let min_match = match element_width {
        1 => 4usize,
        2 => 2usize,
        _ => 1usize,
    };
    let mut reps = [element_width, element_width * 2, element_width * 4];
    let mut literal_pos = 0usize;
    let mut offset_pos = 0usize;
    let mut extra_literal_pos = 0usize;
    let mut extra_match_pos = 0usize;
    let offset_count = numeric_element_count(offsets.bytes, 4)?;
    let extra_literal_count = numeric_element_count(extra_literal_lengths.bytes, 4)?;
    let extra_match_count = numeric_element_count(extra_match_lengths.bytes, 4)?;

    for token_index in 0..token_count {
        let token = read_u16_element(tokens.bytes, token_index)?;
        let offset_code = usize::from(token & 0x3);
        let literal_code = usize::from((token >> 2) & 0x0f);
        let match_code = usize::from((token >> 6) & 0x0f);

        let match_offset = match offset_code {
            3 => {
                let raw_offset = usize::try_from(read_u32_element(offsets.bytes, offset_pos)?)
                    .map_err(|_| {
                        Error::new(ErrorKind::LimitExceeded)
                            .with_detail("numeric value is too large")
                    })?;
                offset_pos = checked_next_numeric_pos(offset_pos, offset_count)?;
                let byte_offset = raw_offset
                    .checked_mul(element_width)
                    .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
                reps[2] = reps[1];
                reps[1] = reps[0];
                reps[0] = byte_offset;
                byte_offset
            }
            0 => reps[0],
            1 => {
                let byte_offset = reps[1];
                reps.swap(1, 0);
                byte_offset
            }
            2 => {
                let byte_offset = reps[2];
                reps[2] = reps[1];
                reps[1] = reps[0];
                reps[0] = byte_offset;
                byte_offset
            }
            _ => unreachable!("offset code is masked to two bits"),
        };

        let mut literal_elements = literal_code;
        if literal_code == 15 {
            literal_elements = literal_elements
                .checked_add(
                    usize::try_from(read_u32_element(
                        extra_literal_lengths.bytes,
                        extra_literal_pos,
                    )?)
                    .map_err(|_| {
                        Error::new(ErrorKind::LimitExceeded)
                            .with_detail("numeric value is too large")
                    })?,
                )
                .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
            extra_literal_pos = checked_next_numeric_pos(extra_literal_pos, extra_literal_count)?;
        }
        let literal_len = literal_elements
            .checked_mul(element_width)
            .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;

        let mut match_elements = match_code
            .checked_add(min_match)
            .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
        if match_code == 15 {
            match_elements = match_elements
                .checked_add(
                    usize::try_from(read_u32_element(
                        extra_match_lengths.bytes,
                        extra_match_pos,
                    )?)
                    .map_err(|_| {
                        Error::new(ErrorKind::LimitExceeded)
                            .with_detail("numeric value is too large")
                    })?,
                )
                .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
            extra_match_pos = checked_next_numeric_pos(extra_match_pos, extra_match_count)?;
        }
        let match_len = match_elements
            .checked_mul(element_width)
            .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;

        append_field_lz_literals(&mut output, literals.bytes, &mut literal_pos, literal_len)?;
        append_field_lz_match(&mut output, match_offset, match_len, output_capacity)?;
    }

    let remaining_literals = literals.bytes.get(literal_pos..).ok_or_else(|| {
        Error::new(ErrorKind::Malformed).with_detail("field_lz literal stream is too short")
    })?;
    let final_len = output
        .len()
        .checked_add(remaining_literals.len())
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
    if final_len > output_capacity {
        return Err(Error::new(ErrorKind::Malformed)
            .with_detail("field_lz output size exceeds header capacity"));
    }
    output.extend_from_slice(remaining_literals);

    if offset_pos != offset_count
        || extra_literal_pos != extra_literal_count
        || extra_match_pos != extra_match_count
    {
        return Err(Error::new(ErrorKind::Malformed)
            .with_detail("field_lz numeric stream was not fully consumed"));
    }

    Ok(OwnedStream {
        bytes: output,
        element_width,
        string_lengths: None,
    })
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

fn decode_fse_ncount_node(
    source: StreamInput<'_>,
    header: &[u8],
    limits: Limits,
) -> Result<OwnedStream> {
    if !header.is_empty() {
        return Err(
            Error::new(ErrorKind::Unsupported).with_detail("fse_ncount headers are unsupported")
        );
    }
    if source.element_width != 1 {
        return Err(
            Error::new(ErrorKind::InvalidType).with_detail("fse_ncount input must be serial")
        );
    }

    let mut reader = BitReader::new(source.bytes);
    let (mut distribution, _accuracy_log) = parse_fse_table_description(&mut reader, u8::MAX)
        .map_err(|err| {
            Error::new(ErrorKind::Malformed).with_detail(format!("invalid fse_ncount: {err}"))
        })?;
    if reader.bytes_consumed() != source.bytes.len() {
        return Err(
            Error::new(ErrorKind::Malformed).with_detail("fse_ncount input has trailing bytes")
        );
    }
    while distribution.last().copied() == Some(0) {
        distribution.pop();
    }

    let output_len = distribution
        .len()
        .checked_mul(2)
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
    if output_len > limits.max_decoded_bytes || output_len > limits.max_buffer_bytes {
        return Err(
            Error::new(ErrorKind::LimitExceeded).with_detail("decoded output limit exceeded")
        );
    }

    let mut output = Vec::new();
    output.try_reserve_exact(output_len).map_err(|_| {
        Error::new(ErrorKind::LimitExceeded).with_detail("fse_ncount allocation failed")
    })?;
    for count in distribution {
        output.extend_from_slice(&count.to_le_bytes());
    }
    Ok(OwnedStream {
        bytes: output,
        element_width: 2,
        string_lengths: None,
    })
}

fn decode_fse_v2_node(
    inputs: &[StreamInput<'_>],
    header: &[u8],
    limits: Limits,
) -> Result<Vec<u8>> {
    let [norm, bits] = inputs else {
        return Err(Error::new(ErrorKind::InvalidGraph)
            .with_detail("fse_v2 input count does not match node shape"));
    };
    require_numeric_width(norm, 2, "fse_v2 normalized counts")?;
    if bits.element_width != 1 {
        return Err(Error::new(ErrorKind::InvalidType).with_detail("fse_v2 bits must be serial"));
    }

    let parsed = parse_fse_v2_header(header)?;
    if parsed.output_len > limits.max_decoded_bytes || parsed.output_len > limits.max_buffer_bytes {
        return Err(
            Error::new(ErrorKind::LimitExceeded).with_detail("decoded output limit exceeded")
        );
    }

    let mut distribution = Vec::new();
    distribution
        .try_reserve_exact(numeric_element_count(norm.bytes, 2)?)
        .map_err(|_| {
            Error::new(ErrorKind::LimitExceeded).with_detail("fse distribution allocation failed")
        })?;
    for count in norm.bytes.chunks_exact(2) {
        distribution.push(i16::from_le_bytes(count.try_into().map_err(|_| {
            Error::new(ErrorKind::Malformed).with_detail("invalid fse count")
        })?));
    }
    let accuracy_log = validate_fse_distribution(&distribution)?;
    let table = build_decode_table(&distribution, accuracy_log).map_err(|err| {
        Error::new(ErrorKind::Malformed).with_detail(format!("invalid fse_v2 table: {err}"))
    })?;
    decode_fse_symbols(
        bits.bytes,
        parsed.output_len,
        parsed.nb_states,
        &table,
        accuracy_log,
    )
}

#[derive(Clone, Copy)]
struct FseV2Header {
    nb_states: usize,
    output_len: usize,
}

fn parse_fse_v2_header(header: &[u8]) -> Result<FseV2Header> {
    if !(2..=9).contains(&header.len()) {
        return Err(Error::new(ErrorKind::Malformed).with_detail("fse_v2 header is malformed"));
    }
    let nb_states = usize::from(header[0]);
    if !matches!(nb_states, 2 | 4) {
        return Err(
            Error::new(ErrorKind::Unsupported).with_detail("fse_v2 state count is unsupported")
        );
    }
    let mut output_len = 0u64;
    for (shift, &byte) in header[1..].iter().enumerate() {
        let bit_shift = shift
            .checked_mul(8)
            .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
        output_len |= u64::from(byte) << bit_shift;
    }
    if output_len < 2 {
        return Err(Error::new(ErrorKind::Malformed)
            .with_detail("fse_v2 output count must be at least two"));
    }
    let output_len = usize::try_from(output_len).map_err(|_| {
        Error::new(ErrorKind::LimitExceeded).with_detail("fse_v2 output size is too large")
    })?;
    Ok(FseV2Header {
        nb_states,
        output_len,
    })
}

fn validate_fse_distribution(distribution: &[i16]) -> Result<u8> {
    if distribution.len() < 2 || distribution.len() > 256 {
        return Err(
            Error::new(ErrorKind::Malformed).with_detail("fse_v2 normalized count size is invalid")
        );
    }
    let mut sum = 0u32;
    for &count in distribution {
        if count < -1 {
            return Err(
                Error::new(ErrorKind::Malformed).with_detail("fse_v2 normalized count is invalid")
            );
        }
        if count == -1 {
            sum = sum
                .checked_add(1)
                .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
        } else {
            sum = sum
                .checked_add(u32::try_from(count).map_err(|_| {
                    Error::new(ErrorKind::Malformed).with_detail("fse_v2 count is invalid")
                })?)
                .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
        }
    }
    if sum == 0 || !sum.is_power_of_two() {
        return Err(
            Error::new(ErrorKind::Malformed).with_detail("fse_v2 normalized count sum is invalid")
        );
    }
    let accuracy_log = u8::try_from(sum.ilog2()).map_err(|_| Error::new(ErrorKind::Malformed))?;
    if !(zrip_core::fse::MIN_TABLE_LOG..=zrip_core::fse::MAX_TABLE_LOG).contains(&accuracy_log) {
        return Err(Error::new(ErrorKind::Malformed).with_detail("fse_v2 table log is unsupported"));
    }
    Ok(accuracy_log)
}

#[derive(Clone, Copy)]
struct OpenZlFseState<'a> {
    table: &'a [FseDecodeEntry],
    state: u32,
}

impl<'a> OpenZlFseState<'a> {
    fn new(
        table: &'a [FseDecodeEntry],
        accuracy_log: u8,
        reader: &mut ReverseBitReader<'_>,
    ) -> Result<Self> {
        let state = reader
            .read_bits(accuracy_log)
            .map_err(|err| Error::new(ErrorKind::Malformed).with_detail(format!("{err}")))?;
        Ok(Self { table, state })
    }

    fn symbol(self) -> Result<u8> {
        let index = usize::try_from(self.state).map_err(|_| Error::new(ErrorKind::Malformed))?;
        Ok(self
            .table
            .get(index)
            .ok_or_else(|| Error::new(ErrorKind::Malformed).with_detail("fse state is invalid"))?
            .symbol)
    }

    fn update(&mut self, reader: &mut ReverseBitReader<'_>) -> Result<()> {
        let index = usize::try_from(self.state).map_err(|_| Error::new(ErrorKind::Malformed))?;
        let entry = self
            .table
            .get(index)
            .ok_or_else(|| Error::new(ErrorKind::Malformed).with_detail("fse state is invalid"))?;
        let bits = reader
            .read_bits(entry.num_bits)
            .map_err(|err| Error::new(ErrorKind::Malformed).with_detail(format!("{err}")))?;
        self.state = u32::from(entry.base_line)
            .checked_add(bits)
            .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
        Ok(())
    }
}

fn decode_fse_symbols(
    bits: &[u8],
    output_len: usize,
    nb_states: usize,
    table: &[FseDecodeEntry],
    accuracy_log: u8,
) -> Result<Vec<u8>> {
    let mut reader = ReverseBitReader::new(bits)
        .map_err(|err| Error::new(ErrorKind::Malformed).with_detail(format!("{err}")))?;
    let mut states = Vec::new();
    states.try_reserve_exact(nb_states).map_err(|_| {
        Error::new(ErrorKind::LimitExceeded).with_detail("fse state allocation failed")
    })?;
    for _ in 0..nb_states {
        states.push(OpenZlFseState::new(table, accuracy_log, &mut reader)?);
    }

    let mut output = Vec::new();
    output.try_reserve_exact(output_len).map_err(|_| {
        Error::new(ErrorKind::LimitExceeded).with_detail("fse output allocation failed")
    })?;
    for index in 0..output_len {
        let state_index = index % nb_states;
        let state = states
            .get_mut(state_index)
            .ok_or_else(|| Error::new(ErrorKind::Malformed).with_detail("fse state is missing"))?;
        output.push(state.symbol()?);
        if index + nb_states < output_len {
            state.update(&mut reader)?;
        }
    }
    if reader.bits_remaining() != 0 {
        return Err(Error::new(ErrorKind::Malformed).with_detail("fse_v2 input has trailing bits"));
    }
    Ok(output)
}

fn decode_huffman_v2_node(
    inputs: &[StreamInput<'_>],
    header: &[u8],
    limits: Limits,
) -> Result<Vec<u8>> {
    let [weights, bits] = inputs else {
        return Err(Error::new(ErrorKind::InvalidGraph)
            .with_detail("huffman_v2 input count does not match node shape"));
    };
    require_numeric_width(weights, 1, "huffman_v2 weights")?;
    if bits.element_width != 1 {
        return Err(
            Error::new(ErrorKind::InvalidType).with_detail("huffman_v2 bits must be serial")
        );
    }
    let parsed = parse_huffman_v2_header(header)?;
    if parsed.output_len > limits.max_decoded_bytes || parsed.output_len > limits.max_buffer_bytes {
        return Err(
            Error::new(ErrorKind::LimitExceeded).with_detail("decoded output limit exceeded")
        );
    }
    let (table, table_log) = build_complete_huffman_decode_table(weights.bytes)?;
    let decoded = if parsed.x4 {
        decode::decode_4_streams(&table, table_log, bits.bytes, parsed.output_len)
    } else {
        decode::decode_single_stream(&table, table_log, bits.bytes, parsed.output_len)
    }
    .map_err(|err| Error::new(ErrorKind::Malformed).with_detail(format!("{err}")))?;
    Ok(decoded)
}

#[derive(Clone, Copy)]
struct HuffmanV2Header {
    x4: bool,
    output_len: usize,
}

fn parse_huffman_v2_header(header: &[u8]) -> Result<HuffmanV2Header> {
    if !(2..=9).contains(&header.len()) {
        return Err(Error::new(ErrorKind::Malformed).with_detail("huffman_v2 header is malformed"));
    }
    let x4 = (header[0] & 1) != 0;
    let mut output_len = 0u64;
    for (shift, &byte) in header[1..].iter().enumerate() {
        let bit_shift = shift
            .checked_mul(8)
            .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
        output_len |= u64::from(byte) << bit_shift;
    }
    if output_len < 2 {
        return Err(Error::new(ErrorKind::Malformed)
            .with_detail("huffman_v2 output count must be at least two"));
    }
    let output_len = usize::try_from(output_len).map_err(|_| {
        Error::new(ErrorKind::LimitExceeded).with_detail("huffman_v2 output size is too large")
    })?;
    Ok(HuffmanV2Header { x4, output_len })
}

fn build_complete_huffman_decode_table(weights: &[u8]) -> Result<(Vec<HuffmanDecodeEntry>, u8)> {
    if weights.len() < 2 || weights.len() > 256 {
        return Err(
            Error::new(ErrorKind::Malformed).with_detail("huffman_v2 weight count is invalid")
        );
    }
    let mut sum = 0u32;
    let mut non_zero = 0usize;
    for &weight in weights {
        if weight > 12 {
            return Err(
                Error::new(ErrorKind::Malformed).with_detail("huffman_v2 weight is invalid")
            );
        }
        if weight != 0 {
            non_zero = non_zero
                .checked_add(1)
                .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
            sum = sum
                .checked_add(1u32 << (u32::from(weight) - 1))
                .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
        }
    }
    if non_zero < 2 || sum == 0 || !sum.is_power_of_two() {
        return Err(
            Error::new(ErrorKind::Malformed).with_detail("huffman_v2 weights are not normalized")
        );
    }
    let table_log = u8::try_from(sum.ilog2()).map_err(|_| Error::new(ErrorKind::Malformed))?;
    if table_log > 12 {
        return Err(Error::new(ErrorKind::Malformed).with_detail("huffman_v2 table is too large"));
    }
    let table_size = 1usize
        .checked_shl(u32::from(table_log))
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
    let mut table = vec![HuffmanDecodeEntry::default(); table_size];
    let max_weight = table_log
        .checked_add(1)
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
    let mut rank_count = vec![0u32; usize::from(max_weight) + 1];
    for &weight in weights {
        if weight != 0 {
            let count = rank_count.get_mut(usize::from(weight)).ok_or_else(|| {
                Error::new(ErrorKind::Malformed).with_detail("huffman_v2 weight is out of range")
            })?;
            *count = count
                .checked_add(1)
                .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
        }
    }

    let mut rank_start = vec![0u32; usize::from(max_weight) + 1];
    let mut cumulative = 0u32;
    for weight in 1..=max_weight {
        rank_start[usize::from(weight)] = cumulative;
        cumulative = cumulative
            .checked_add(
                rank_count[usize::from(weight)]
                    .checked_mul(1u32 << (u32::from(weight) - 1))
                    .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?,
            )
            .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
    }

    for (symbol, &weight) in weights.iter().enumerate() {
        if weight == 0 {
            continue;
        }
        let num_bits = max_weight - weight;
        let entries = 1usize
            .checked_shl(u32::from(weight) - 1)
            .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
        let start = usize::try_from(rank_start[usize::from(weight)])
            .map_err(|_| Error::new(ErrorKind::LimitExceeded))?;
        let end = start
            .checked_add(entries)
            .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
        if end > table.len() {
            return Err(
                Error::new(ErrorKind::Malformed).with_detail("huffman_v2 decode table overflows")
            );
        }
        rank_start[usize::from(weight)] =
            u32::try_from(end).map_err(|_| Error::new(ErrorKind::LimitExceeded))?;
        let symbol = u8::try_from(symbol).map_err(|_| Error::new(ErrorKind::Malformed))?;
        table[start..end].fill(HuffmanDecodeEntry { symbol, num_bits });
    }
    Ok((table, table_log))
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
    decode_tokenize_indices(
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
    })
}

#[expect(
    clippy::inline_always,
    reason = "profiled SAO tokenize hot path benefits from inlining this loop"
)]
#[inline(always)]
fn decode_tokenize_indices(
    alphabet: &[u8],
    alphabet_size: usize,
    element_width: usize,
    indices: &[u8],
    index_width: usize,
    output: &mut Vec<u8>,
) -> Result<()> {
    match index_width {
        1 => {
            for &index in indices {
                append_tokenized_element(
                    alphabet,
                    alphabet_size,
                    element_width,
                    index.into(),
                    output,
                )?;
            }
        }
        2 => {
            for index in indices.chunks_exact(2) {
                append_tokenized_element(
                    alphabet,
                    alphabet_size,
                    element_width,
                    u16::from_le_bytes([index[0], index[1]]).into(),
                    output,
                )?;
            }
        }
        4 => {
            for index in indices.chunks_exact(4) {
                append_tokenized_element(
                    alphabet,
                    alphabet_size,
                    element_width,
                    u32::from_le_bytes([index[0], index[1], index[2], index[3]])
                        .try_into()
                        .map_err(|_| {
                            Error::new(ErrorKind::LimitExceeded)
                                .with_detail("numeric value is too large")
                        })?,
                    output,
                )?;
            }
        }
        8 => {
            for index in indices.chunks_exact(8) {
                append_tokenized_element(
                    alphabet,
                    alphabet_size,
                    element_width,
                    u64::from_le_bytes([
                        index[0], index[1], index[2], index[3], index[4], index[5], index[6],
                        index[7],
                    ])
                    .try_into()
                    .map_err(|_| {
                        Error::new(ErrorKind::LimitExceeded)
                            .with_detail("numeric value is too large")
                    })?,
                    output,
                )?;
            }
        }
        _ => unreachable!("validate_numeric_stream_width accepted only supported widths"),
    }
    Ok(())
}

#[expect(
    clippy::inline_always,
    reason = "profiled SAO tokenize hot path benefits from inlining this leaf"
)]
#[inline(always)]
fn append_tokenized_element(
    alphabet: &[u8],
    alphabet_size: usize,
    element_width: usize,
    index: usize,
    output: &mut Vec<u8>,
) -> Result<()> {
    if index >= alphabet_size {
        return Err(
            Error::new(ErrorKind::Malformed).with_detail("tokenize_fixed index is out of bounds")
        );
    }
    let start = index * element_width;
    output.extend_from_slice(&alphabet[start..start + element_width]);
    Ok(())
}

struct QuantizeParams {
    bits: &'static [u8],
    base: &'static [u32],
}

const QUANTIZE_OFFSETS_BITS: [u8; 32] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
    26, 27, 28, 29, 30, 31,
];
const QUANTIZE_OFFSETS_BASE: [u32; 32] = [
    0x1,
    0x2,
    0x4,
    0x8,
    0x10,
    0x20,
    0x40,
    0x80,
    0x100,
    0x200,
    0x400,
    0x800,
    0x1000,
    0x2000,
    0x4000,
    0x8000,
    0x1_0000,
    0x2_0000,
    0x4_0000,
    0x8_0000,
    0x10_0000,
    0x20_0000,
    0x40_0000,
    0x80_0000,
    0x100_0000,
    0x200_0000,
    0x400_0000,
    0x800_0000,
    0x1000_0000,
    0x2000_0000,
    0x4000_0000,
    0x8000_0000,
];
const QUANTIZE_LENGTHS_BITS: [u8; 44] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
    17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
];
const QUANTIZE_LENGTHS_BASE: [u32; 44] = [
    0,
    1,
    2,
    3,
    4,
    5,
    6,
    7,
    8,
    9,
    10,
    11,
    12,
    13,
    14,
    15,
    0x10,
    0x20,
    0x40,
    0x80,
    0x100,
    0x200,
    0x400,
    0x800,
    0x1000,
    0x2000,
    0x4000,
    0x8000,
    0x1_0000,
    0x2_0000,
    0x4_0000,
    0x8_0000,
    0x10_0000,
    0x20_0000,
    0x40_0000,
    0x80_0000,
    0x100_0000,
    0x200_0000,
    0x400_0000,
    0x800_0000,
    0x1000_0000,
    0x2000_0000,
    0x4000_0000,
    0x8000_0000,
];
const QUANTIZE_OFFSETS: QuantizeParams = QuantizeParams {
    bits: &QUANTIZE_OFFSETS_BITS,
    base: &QUANTIZE_OFFSETS_BASE,
};
const QUANTIZE_LENGTHS: QuantizeParams = QuantizeParams {
    bits: &QUANTIZE_LENGTHS_BITS,
    base: &QUANTIZE_LENGTHS_BASE,
};

fn decode_quantize_node(
    inputs: &[StreamInput<'_>],
    header: &[u8],
    limits: Limits,
    params: &QuantizeParams,
) -> Result<OwnedStream> {
    if !header.is_empty() {
        return Err(
            Error::new(ErrorKind::Unsupported).with_detail("quantize headers are unsupported")
        );
    }
    let [codes, extra_bits] = inputs else {
        return Err(Error::new(ErrorKind::InvalidGraph)
            .with_detail("quantize input count does not match node shape"));
    };
    require_numeric_width(codes, 1, "quantize codes")?;
    if extra_bits.element_width != 1 {
        return Err(Error::new(ErrorKind::InvalidType).with_detail("quantize bits must be serial"));
    }
    let output_len = codes
        .bytes
        .len()
        .checked_mul(4)
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
    if output_len > limits.max_decoded_bytes || output_len > limits.max_buffer_bytes {
        return Err(
            Error::new(ErrorKind::LimitExceeded).with_detail("decoded output limit exceeded")
        );
    }

    let mut reader = ForwardBitReader::new(extra_bits.bytes);
    let mut output = Vec::new();
    output.try_reserve_exact(output_len).map_err(|_| {
        Error::new(ErrorKind::LimitExceeded).with_detail("quantize allocation failed")
    })?;
    for &code in codes.bytes {
        let code_index = usize::from(code);
        let bits = *params.bits.get(code_index).ok_or_else(|| {
            Error::new(ErrorKind::Malformed).with_detail("quantize code is out of range")
        })?;
        let base = *params.base.get(code_index).ok_or_else(|| {
            Error::new(ErrorKind::Malformed).with_detail("quantize code is out of range")
        })?;
        let extra = reader.read(u32::from(bits))?;
        let value = base
            .checked_add(extra)
            .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
        output.extend_from_slice(&value.to_le_bytes());
    }
    reader.finish_zero_padding()?;
    Ok(OwnedStream {
        bytes: output,
        element_width: 4,
        string_lengths: None,
    })
}

const PARTITION_MAX_PARTITIONS: usize = 256;
const PARTITION_HEADER_IS_PRESET_BIT: u8 = 0x04;
const PARTITION_HEADER_IS_FIRST_VALUE_ZERO_BIT: u8 = 0x08;
const PARTITION_HEADER_IS_POW2_BIT: u8 = 0x20;

const PARTITION_QUANTIZE_OFFSETS_SIZES: [u64; 32] = [
    0x1,
    0x2,
    0x4,
    0x8,
    0x10,
    0x20,
    0x40,
    0x80,
    0x100,
    0x200,
    0x400,
    0x800,
    0x1000,
    0x2000,
    0x4000,
    0x8000,
    0x1_0000,
    0x2_0000,
    0x4_0000,
    0x8_0000,
    0x10_0000,
    0x20_0000,
    0x40_0000,
    0x80_0000,
    0x100_0000,
    0x200_0000,
    0x400_0000,
    0x800_0000,
    0x1000_0000,
    0x2000_0000,
    0x4000_0000,
    0x8000_0000,
];
const PARTITION_QUANTIZE_LENGTHS_SIZES: [u64; 44] = [
    0x1,
    0x1,
    0x1,
    0x1,
    0x1,
    0x1,
    0x1,
    0x1,
    0x1,
    0x1,
    0x1,
    0x1,
    0x1,
    0x1,
    0x1,
    0x1,
    0x10,
    0x20,
    0x40,
    0x80,
    0x100,
    0x200,
    0x400,
    0x800,
    0x1000,
    0x2000,
    0x4000,
    0x8000,
    0x10000,
    0x20000,
    0x4_0000,
    0x8_0000,
    0x10_0000,
    0x20_0000,
    0x40_0000,
    0x80_0000,
    0x100_0000,
    0x200_0000,
    0x400_0000,
    0x800_0000,
    0x1000_0000,
    0x2000_0000,
    0x4000_0000,
    0x8000_0000,
];
const PARTITION_VARBYTE16_SIZES: [u64; 16] = [
    0x2, 0x2, 0x4, 0x8, 0x10, 0x20, 0x40, 0x80, 0x100, 0x200, 0x400, 0x800, 0x1000, 0x2000, 0x4000,
    0x8000,
];

struct PartitionParams {
    start_value: u64,
    sizes: Vec<u64>,
}

fn decode_partition_node(
    inputs: &[StreamInput<'_>],
    header: &[u8],
    limits: Limits,
) -> Result<OwnedStream> {
    let [buckets, offsets] = inputs else {
        return Err(Error::new(ErrorKind::InvalidGraph)
            .with_detail("partition input count does not match node shape"));
    };
    require_numeric_width(buckets, 1, "partition buckets")?;
    if offsets.element_width != 1 {
        return Err(Error::new(ErrorKind::InvalidType).with_detail("partition bits must be serial"));
    }

    let (params, element_width) = parse_partition_header(header)?;
    let output_len = buckets
        .bytes
        .len()
        .checked_mul(element_width)
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
    if output_len > limits.max_decoded_bytes || output_len > limits.max_buffer_bytes {
        return Err(
            Error::new(ErrorKind::LimitExceeded).with_detail("decoded output limit exceeded")
        );
    }

    let bases = partition_bases(&params)?;
    let bits = partition_bits(&params)?;
    let max_value = max_numeric_value(element_width)?;
    let mut reader = ForwardBitReader::new(offsets.bytes);
    let mut output = Vec::new();
    output.try_reserve_exact(output_len).map_err(|_| {
        Error::new(ErrorKind::LimitExceeded).with_detail("partition allocation failed")
    })?;

    for &bucket in buckets.bytes {
        let bucket = usize::from(bucket);
        let base = *bases.get(bucket).ok_or_else(|| {
            Error::new(ErrorKind::Malformed).with_detail("partition bucket is out of range")
        })?;
        let bit_width = *bits.get(bucket).ok_or_else(|| {
            Error::new(ErrorKind::Malformed).with_detail("partition bucket is out of range")
        })?;
        let offset = reader.read_u64(usize::from(bit_width))?;
        let value = base
            .checked_add(offset)
            .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
        if value > max_value {
            return Err(Error::new(ErrorKind::Malformed)
                .with_detail("partition value exceeds output element width"));
        }
        write_numeric_element_vec(&mut output, element_width, value);
    }

    Ok(OwnedStream {
        bytes: output,
        element_width,
        string_lengths: None,
    })
}

fn parse_partition_header(header: &[u8]) -> Result<(PartitionParams, usize)> {
    let (&flags, mut rest) = header
        .split_first()
        .ok_or_else(|| Error::new(ErrorKind::Malformed).with_detail("partition header is empty"))?;
    let element_width = 1usize
        .checked_shl(u32::from(flags & 0x03))
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;

    let params = if (flags & PARTITION_HEADER_IS_PRESET_BIT) != 0 {
        if !rest.is_empty() {
            return Err(Error::new(ErrorKind::Malformed)
                .with_detail("partition preset header has trailing bytes"));
        }
        partition_preset(flags >> 3)?
    } else {
        let start_value = if (flags & PARTITION_HEADER_IS_FIRST_VALUE_ZERO_BIT) != 0 {
            0
        } else {
            read_var_u64_from_slice(&mut rest)?
        };
        let sizes = if (flags & PARTITION_HEADER_IS_POW2_BIT) != 0 {
            parse_partition_pow2_sizes(flags, rest)?
        } else {
            parse_partition_varint_sizes(rest)?
        };
        PartitionParams { start_value, sizes }
    };

    validate_partition_params(&params)?;
    Ok((params, element_width))
}

fn partition_preset(preset: u8) -> Result<PartitionParams> {
    let (start_value, sizes): (u64, &[u64]) = match preset {
        0 => (1, &PARTITION_QUANTIZE_OFFSETS_SIZES),
        1 => (0, &PARTITION_QUANTIZE_LENGTHS_SIZES),
        2 => (0, &PARTITION_VARBYTE16_SIZES),
        _ => {
            return Err(Error::new(ErrorKind::Malformed).with_detail("partition preset is unknown"));
        }
    };
    Ok(PartitionParams {
        start_value,
        sizes: sizes.to_vec(),
    })
}

fn parse_partition_pow2_sizes(flags: u8, bytes: &[u8]) -> Result<Vec<u64>> {
    if bytes.is_empty() {
        return Err(Error::new(ErrorKind::Malformed).with_detail("partition sizes are missing"));
    }
    let last = *bytes.last().unwrap_or(&0);
    if last == 0 {
        return Err(
            Error::new(ErrorKind::Malformed).with_detail("partition sizes bitstream is corrupt")
        );
    }
    let num_bits = usize::from(flags >> 6) + 3;
    let high_bit = usize::try_from(u8::BITS - 1 - last.leading_zeros())
        .map_err(|_| Error::new(ErrorKind::IntegerOverflow))?;
    let unused_bits = 8usize
        .checked_sub(high_bit)
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
    let total_bits = bytes
        .len()
        .checked_mul(8)
        .and_then(|bits| bits.checked_sub(unused_bits))
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
    if total_bits % num_bits != 0 {
        return Err(
            Error::new(ErrorKind::Malformed).with_detail("partition size bitstream is misaligned")
        );
    }
    let count = total_bits / num_bits;
    if count > PARTITION_MAX_PARTITIONS {
        return Err(Error::new(ErrorKind::Malformed).with_detail("partition count exceeds maximum"));
    }
    let mut reader = ForwardBitReader::new(bytes);
    let mut sizes = Vec::new();
    sizes.try_reserve_exact(count).map_err(|_| {
        Error::new(ErrorKind::LimitExceeded).with_detail("partition sizes allocation failed")
    })?;
    for _ in 0..count {
        let log2_size = reader.read_u64(num_bits)?;
        if log2_size >= u64::BITS.into() {
            return Err(
                Error::new(ErrorKind::Malformed).with_detail("partition size shift is invalid")
            );
        }
        sizes.push(1u64 << log2_size);
    }
    Ok(sizes)
}

fn parse_partition_varint_sizes(mut bytes: &[u8]) -> Result<Vec<u64>> {
    let mut sizes = Vec::new();
    while !bytes.is_empty() {
        if sizes.len() >= PARTITION_MAX_PARTITIONS {
            return Err(
                Error::new(ErrorKind::Malformed).with_detail("partition count exceeds maximum")
            );
        }
        sizes.push(read_var_u64_from_slice(&mut bytes)?);
    }
    Ok(sizes)
}

fn validate_partition_params(params: &PartitionParams) -> Result<()> {
    if params.sizes.is_empty()
        || params.sizes.len() > PARTITION_MAX_PARTITIONS
        || (params.sizes.len() == 1 && params.start_value == 0)
    {
        return Err(
            Error::new(ErrorKind::Malformed).with_detail("partition parameters are invalid")
        );
    }
    let mut sum = params.start_value;
    for (index, &size) in params.sizes.iter().enumerate() {
        if size == 0 {
            return Err(
                Error::new(ErrorKind::Malformed).with_detail("partition size must be nonzero")
            );
        }
        match sum.checked_add(size) {
            Some(next) => sum = next,
            None if index + 1 == params.sizes.len() => sum = sum.wrapping_add(size),
            None => {
                return Err(Error::new(ErrorKind::IntegerOverflow)
                    .with_detail("partition size sum overflowed"));
            }
        }
    }
    let _ = sum;
    Ok(())
}

fn partition_bases(params: &PartitionParams) -> Result<Vec<u64>> {
    let mut bases = Vec::new();
    bases.try_reserve_exact(params.sizes.len()).map_err(|_| {
        Error::new(ErrorKind::LimitExceeded).with_detail("partition bases allocation failed")
    })?;
    let mut base = params.start_value;
    for &size in &params.sizes {
        bases.push(base);
        base = base.wrapping_add(size);
    }
    Ok(bases)
}

fn partition_bits(params: &PartitionParams) -> Result<Vec<u8>> {
    let mut bits = Vec::new();
    bits.try_reserve_exact(params.sizes.len()).map_err(|_| {
        Error::new(ErrorKind::LimitExceeded).with_detail("partition bits allocation failed")
    })?;
    for &size in &params.sizes {
        let bit_width = if size <= 1 {
            0
        } else {
            u8::try_from(u64::BITS - (size - 1).leading_zeros())
                .map_err(|_| Error::new(ErrorKind::IntegerOverflow))?
        };
        bits.push(bit_width);
    }
    Ok(bits)
}

fn read_var_u64_from_slice(bytes: &mut &[u8]) -> Result<u64> {
    let mut offset = 0usize;
    let value = read_var_u64(bytes, &mut offset)?;
    *bytes = bytes
        .get(offset..)
        .ok_or_else(|| Error::new(ErrorKind::Malformed).with_detail("varint offset is invalid"))?;
    Ok(value)
}

fn write_numeric_element_vec(output: &mut Vec<u8>, element_width: usize, value: u64) {
    output.extend_from_slice(&value.to_le_bytes()[..element_width]);
}

struct ForwardBitReader<'a> {
    bytes: &'a [u8],
    bit_pos: usize,
}

impl<'a> ForwardBitReader<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, bit_pos: 0 }
    }

    fn read(&mut self, bits: u32) -> Result<u32> {
        if bits > 31 {
            return Err(
                Error::new(ErrorKind::Malformed).with_detail("forward bit width is unsupported")
            );
        }
        u32::try_from(
            self.read_u64(
                usize::try_from(bits).map_err(|_| Error::new(ErrorKind::IntegerOverflow))?,
            )?,
        )
        .map_err(|_| Error::new(ErrorKind::IntegerOverflow))
    }

    fn read_u64(&mut self, bits: usize) -> Result<u64> {
        if bits > 64 {
            return Err(
                Error::new(ErrorKind::Malformed).with_detail("forward bit width is unsupported")
            );
        }
        let end = self
            .bit_pos
            .checked_add(bits)
            .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
        let total_bits = self
            .bytes
            .len()
            .checked_mul(8)
            .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
        if end > total_bits {
            return Err(
                Error::new(ErrorKind::Malformed).with_detail("forward bitstream is truncated")
            );
        }
        let mut value = 0u64;
        for bit in 0..bits {
            let absolute = self
                .bit_pos
                .checked_add(bit)
                .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
            let byte = self.bytes[absolute / 8];
            let set = (byte >> (absolute % 8)) & 1;
            value |= u64::from(set) << bit;
        }
        self.bit_pos = end;
        Ok(value)
    }

    fn finish_zero_padding(&self) -> Result<()> {
        let total_bits = self
            .bytes
            .len()
            .checked_mul(8)
            .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
        for absolute in self.bit_pos..total_bits {
            let byte = self.bytes[absolute / 8];
            if ((byte >> (absolute % 8)) & 1) != 0 {
                return Err(Error::new(ErrorKind::Malformed)
                    .with_detail("forward bitstream has nonzero padding"));
            }
        }
        Ok(())
    }
}

fn checked_next_numeric_pos(position: usize, count: usize) -> Result<usize> {
    if position >= count {
        return Err(Error::new(ErrorKind::Malformed).with_detail("numeric stream is exhausted"));
    }
    position
        .checked_add(1)
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))
}

fn append_field_lz_literals(
    output: &mut Vec<u8>,
    literals: &[u8],
    literal_pos: &mut usize,
    literal_len: usize,
) -> Result<()> {
    let literal_end = literal_pos
        .checked_add(literal_len)
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
    let src = literals.get(*literal_pos..literal_end).ok_or_else(|| {
        Error::new(ErrorKind::Malformed).with_detail("field_lz literal stream is too short")
    })?;
    output.extend_from_slice(src);
    *literal_pos = literal_end;
    Ok(())
}

fn append_field_lz_match(
    output: &mut Vec<u8>,
    match_offset: usize,
    match_len: usize,
    output_capacity: usize,
) -> Result<()> {
    if match_offset == 0 {
        return Err(Error::new(ErrorKind::Malformed).with_detail("field_lz offset is zero"));
    }
    if match_offset > output.len() {
        return Err(
            Error::new(ErrorKind::Malformed).with_detail("field_lz offset exceeds decoded prefix")
        );
    }
    let end = output
        .len()
        .checked_add(match_len)
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
    if end > output_capacity {
        return Err(Error::new(ErrorKind::Malformed)
            .with_detail("field_lz match length exceeds output size"));
    }
    let start = output.len();
    output.resize(end, 0);
    copy_lz_match(output, start, match_offset, match_len);
    Ok(())
}

fn decode_bitpack_serial_chunk(stored: &[u8], header: &[u8], limits: Limits) -> Result<Vec<u8>> {
    let parsed = parse_bitpack_header(header, stored.len())?;
    if parsed.element_width != 1 {
        return Err(Error::new(ErrorKind::Unsupported)
            .with_detail("only serial byte bitpack output is implemented"));
    }
    decode_bitpack_chunk(stored, parsed, limits)
}

fn decode_bitpack_int_chunk(stored: &[u8], header: &[u8], limits: Limits) -> Result<OwnedStream> {
    let parsed = parse_bitpack_header(header, stored.len())?;
    let element_width = parsed.element_width;
    Ok(OwnedStream {
        bytes: decode_bitpack_chunk(stored, parsed, limits)?,
        element_width,
        string_lengths: None,
    })
}

fn decode_bitpack_chunk(stored: &[u8], parsed: BitpackHeader, limits: Limits) -> Result<Vec<u8>> {
    let output_len = parsed
        .elements
        .checked_mul(parsed.element_width)
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
    if output_len > limits.max_decoded_bytes || output_len > limits.max_buffer_bytes {
        return Err(
            Error::new(ErrorKind::LimitExceeded).with_detail("decoded output limit exceeded")
        );
    }
    let mut output = Vec::new();
    output.try_reserve_exact(output_len).map_err(|_| {
        Error::new(ErrorKind::LimitExceeded).with_detail("bitpack allocation failed")
    })?;
    output.resize(output_len, 0);
    unpack_lsb_bits(stored, parsed.bits, parsed.element_width, &mut output)?;
    Ok(output)
}

#[derive(Clone, Copy)]
struct BitpackHeader {
    element_width: usize,
    bits: usize,
    elements: usize,
}

fn parse_bitpack_header(header: &[u8], packed_len: usize) -> Result<BitpackHeader> {
    if header.is_empty() || header.len() > 2 {
        return Err(Error::new(ErrorKind::Malformed).with_detail("bitpack header is malformed"));
    }
    let element_width = 1usize
        .checked_shl(u32::from((header[0] >> 6) & 0x3))
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
    let bits = usize::from(header[0] & 0x3f)
        .checked_add(1)
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
    let max_bits = element_width
        .checked_mul(8)
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
    if bits > max_bits {
        return Err(Error::new(ErrorKind::Malformed).with_detail("bitpack width is too large"));
    }
    let max_elements = packed_len.checked_mul(8).ok_or_else(|| {
        Error::new(ErrorKind::IntegerOverflow).with_detail("bitpack size overflowed")
    })? / bits;
    let extra = header.get(1).copied().map_or(0usize, usize::from);
    if extra > max_elements {
        return Err(Error::new(ErrorKind::Malformed).with_detail("bitpack header is corrupt"));
    }
    Ok(BitpackHeader {
        element_width,
        bits,
        elements: max_elements - extra,
    })
}

fn unpack_lsb_bits(
    stored: &[u8],
    bits: usize,
    element_width: usize,
    output: &mut [u8],
) -> Result<()> {
    let full_width_bits = element_width
        .checked_mul(8)
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
    if bits == full_width_bits {
        let src = stored.get(..output.len()).ok_or_else(|| {
            Error::new(ErrorKind::Malformed).with_detail("bitpack input is truncated")
        })?;
        output.copy_from_slice(src);
        return Ok(());
    }
    if bits <= 56 {
        return unpack_lsb_bits_u64(stored, bits, element_width, output);
    }

    let mask = (1u128 << bits) - 1;
    let mut byte_index = 0usize;
    let mut bit_buffer = 0u128;
    let mut available_bits = 0usize;

    for out in output.chunks_exact_mut(element_width) {
        while available_bits < bits {
            let byte = *stored.get(byte_index).ok_or_else(|| {
                Error::new(ErrorKind::Malformed).with_detail("bitpack input is truncated")
            })?;
            bit_buffer |= u128::from(byte) << available_bits;
            available_bits += 8;
            byte_index = byte_index
                .checked_add(1)
                .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
        }

        let value = bit_buffer & mask;
        out.copy_from_slice(&value.to_le_bytes()[..element_width]);
        bit_buffer >>= bits;
        available_bits -= bits;
    }
    Ok(())
}

fn unpack_lsb_bits_u64(
    stored: &[u8],
    bits: usize,
    element_width: usize,
    output: &mut [u8],
) -> Result<()> {
    let mask = (1u64 << bits) - 1;
    let mut byte_index = 0usize;
    let mut bit_buffer = 0u64;
    let mut available_bits = 0usize;

    for out in output.chunks_exact_mut(element_width) {
        while available_bits < bits {
            let byte = *stored.get(byte_index).ok_or_else(|| {
                Error::new(ErrorKind::Malformed).with_detail("bitpack input is truncated")
            })?;
            bit_buffer |= u64::from(byte) << available_bits;
            available_bits += 8;
            byte_index = byte_index
                .checked_add(1)
                .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
        }

        let value = bit_buffer & mask;
        out.copy_from_slice(&value.to_le_bytes()[..element_width]);
        bit_buffer >>= bits;
        available_bits -= bits;
    }
    Ok(())
}

fn decode_constant_serial_chunk(stored: &[u8], header: &[u8], limits: Limits) -> Result<Vec<u8>> {
    if stored.len() != 1 {
        return Err(Error::new(ErrorKind::Malformed)
            .with_detail("constant_serial input must contain one byte"));
    }
    let mut offset = 0usize;
    let output_len = read_var_u64(header, &mut offset)?;
    if offset != header.len() {
        return Err(
            Error::new(ErrorKind::Malformed).with_detail("unexpected constant_serial header bytes")
        );
    }
    if output_len == 0 {
        return Err(Error::new(ErrorKind::Malformed)
            .with_detail("constant_serial output count must be nonzero"));
    }
    let output_len = usize::try_from(output_len).map_err(|_| {
        Error::new(ErrorKind::LimitExceeded).with_detail("output count is too large")
    })?;
    if output_len > limits.max_decoded_bytes || output_len > limits.max_buffer_bytes {
        return Err(
            Error::new(ErrorKind::LimitExceeded).with_detail("decoded output limit exceeded")
        );
    }
    let mut output = Vec::new();
    output.try_reserve_exact(output_len).map_err(|_| {
        Error::new(ErrorKind::LimitExceeded).with_detail("constant allocation failed")
    })?;
    output.resize(output_len, stored[0]);
    Ok(output)
}

fn decode_byte_preserving_conversion_chunk(
    stored: StreamInput<'_>,
    header: &[u8],
    limits: Limits,
) -> Result<OwnedStream> {
    if !header.is_empty() {
        return Err(
            Error::new(ErrorKind::Unsupported).with_detail("conversion headers are unsupported")
        );
    }
    copy_byte_preserving_conversion(stored, stored.element_width, limits)
}

fn decode_num_to_struct_le_chunk(
    stored: StreamInput<'_>,
    header: &[u8],
    limits: Limits,
) -> Result<OwnedStream> {
    if !header.is_empty() {
        return Err(Error::new(ErrorKind::Unsupported)
            .with_detail("convert_num_to_struct_le headers are unsupported"));
    }
    copy_byte_preserving_conversion(stored, stored.element_width, limits)
}

fn decode_serial_to_struct_chunk(
    stored: StreamInput<'_>,
    header: &[u8],
    limits: Limits,
) -> Result<OwnedStream> {
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
    if !stored.bytes.len().is_multiple_of(element_width) {
        return Err(Error::new(ErrorKind::Malformed)
            .with_detail("serial stream size is not a multiple of struct width"));
    }
    copy_byte_preserving_conversion(stored, element_width, limits)
}

fn decode_numeric_to_serial_le_chunk(
    stored: StreamInput<'_>,
    header: &[u8],
    limits: Limits,
) -> Result<Vec<u8>> {
    if !header.is_empty() {
        return Err(Error::new(ErrorKind::Unsupported)
            .with_detail("convert_serial_to_num_le headers are unsupported"));
    }
    Ok(copy_byte_preserving_conversion(stored, 1, limits)?.bytes)
}

fn decode_serial_to_numeric_le_chunk(
    stored: StreamInput<'_>,
    header: &[u8],
    limits: Limits,
) -> Result<OwnedStream> {
    let [int_log] = header else {
        return Err(Error::new(ErrorKind::Malformed)
            .with_detail("convert_num_to_serial_le header is malformed"));
    };
    if *int_log > 3 {
        return Err(Error::new(ErrorKind::Malformed)
            .with_detail("convert_num_to_serial_le integer width is invalid"));
    }
    let int_size = 1usize
        .checked_shl(u32::from(*int_log))
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
    if !stored.bytes.len().is_multiple_of(int_size) {
        return Err(Error::new(ErrorKind::Malformed)
            .with_detail("serial stream size is not a multiple of integer width"));
    }
    copy_byte_preserving_conversion(stored, int_size, limits)
}

fn copy_byte_preserving_conversion(
    stored: StreamInput<'_>,
    element_width: usize,
    limits: Limits,
) -> Result<OwnedStream> {
    if stored.bytes.len() > limits.max_decoded_bytes || stored.bytes.len() > limits.max_buffer_bytes
    {
        return Err(
            Error::new(ErrorKind::LimitExceeded).with_detail("decoded output limit exceeded")
        );
    }
    let mut output = Vec::new();
    output.try_reserve_exact(stored.bytes.len()).map_err(|_| {
        Error::new(ErrorKind::LimitExceeded).with_detail("conversion allocation failed")
    })?;
    output.extend_from_slice(stored.bytes);
    Ok(OwnedStream {
        bytes: output,
        element_width,
        string_lengths: None,
    })
}

fn decode_zigzag_numeric_chunk(
    stored: StreamInput<'_>,
    header: &[u8],
    limits: Limits,
) -> Result<OwnedStream> {
    if !header.is_empty() {
        return Err(Error::new(ErrorKind::Unsupported)
            .with_detail("zigzag transform headers are unsupported"));
    }
    validate_numeric_stream_width(stored.element_width, "zigzag")?;
    if !stored.bytes.len().is_multiple_of(stored.element_width) {
        return Err(
            Error::new(ErrorKind::Malformed).with_detail("zigzag input has partial element")
        );
    }
    if stored.bytes.len() > limits.max_decoded_bytes || stored.bytes.len() > limits.max_buffer_bytes
    {
        return Err(
            Error::new(ErrorKind::LimitExceeded).with_detail("decoded output limit exceeded")
        );
    }
    let mut output = Vec::new();
    output.try_reserve_exact(stored.bytes.len()).map_err(|_| {
        Error::new(ErrorKind::LimitExceeded).with_detail("zigzag allocation failed")
    })?;
    match stored.element_width {
        1 => {
            for &encoded in stored.bytes {
                let mask = 0u8.wrapping_sub(encoded & 1);
                output.push((encoded >> 1) ^ mask);
            }
        }
        2 => {
            for encoded in stored.bytes.chunks_exact(2) {
                let value = u16::from_le_bytes([encoded[0], encoded[1]]);
                let mask = 0u16.wrapping_sub(value & 1);
                output.extend_from_slice(&((value >> 1) ^ mask).to_le_bytes());
            }
        }
        4 => {
            for encoded in stored.bytes.chunks_exact(4) {
                let value = u32::from_le_bytes([encoded[0], encoded[1], encoded[2], encoded[3]]);
                let mask = 0u32.wrapping_sub(value & 1);
                output.extend_from_slice(&((value >> 1) ^ mask).to_le_bytes());
            }
        }
        8 => {
            for encoded in stored.bytes.chunks_exact(8) {
                let value = u64::from_le_bytes([
                    encoded[0], encoded[1], encoded[2], encoded[3], encoded[4], encoded[5],
                    encoded[6], encoded[7],
                ]);
                let mask = 0u64.wrapping_sub(value & 1);
                output.extend_from_slice(&((value >> 1) ^ mask).to_le_bytes());
            }
        }
        _ => unreachable!("validate_numeric_stream_width accepted only supported widths"),
    }
    Ok(OwnedStream {
        bytes: output,
        element_width: stored.element_width,
        string_lengths: None,
    })
}

fn decode_delta_node(
    stored: StreamInput<'_>,
    header: &[u8],
    limits: Limits,
) -> Result<OwnedStream> {
    validate_numeric_stream_width(stored.element_width, "delta input")?;
    let stored_elements = numeric_element_count(stored.bytes, stored.element_width)?;
    let output_elements = match header.len() {
        0 if stored_elements == 0 => 0,
        0 => {
            return Err(
                Error::new(ErrorKind::Malformed).with_detail("delta stream has no first value")
            );
        }
        len if len == stored.element_width => stored_elements.checked_add(1).ok_or_else(|| {
            Error::new(ErrorKind::IntegerOverflow).with_detail("delta size overflowed")
        })?,
        _ => {
            return Err(Error::new(ErrorKind::Malformed)
                .with_detail("delta header must contain one element"));
        }
    };
    let output_len = output_elements
        .checked_mul(stored.element_width)
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
    if output_len > limits.max_decoded_bytes || output_len > limits.max_buffer_bytes {
        return Err(
            Error::new(ErrorKind::LimitExceeded).with_detail("decoded output limit exceeded")
        );
    }
    let mut output = Vec::new();
    output
        .try_reserve_exact(output_len)
        .map_err(|_| Error::new(ErrorKind::LimitExceeded).with_detail("delta allocation failed"))?;
    if output_elements == 0 {
        return Ok(OwnedStream {
            bytes: output,
            element_width: stored.element_width,
            string_lengths: None,
        });
    }
    output.resize(output_len, 0);
    output[..stored.element_width].copy_from_slice(header);
    decode_delta_elements(stored.bytes, header, stored.element_width, &mut output);
    Ok(OwnedStream {
        bytes: output,
        element_width: stored.element_width,
        string_lengths: None,
    })
}

fn decode_delta_elements(stored: &[u8], header: &[u8], element_width: usize, output: &mut [u8]) {
    match element_width {
        1 => {
            let mut previous = header[0];
            for (index, &delta) in stored.iter().enumerate() {
                previous = previous.wrapping_add(delta);
                output[index + 1] = previous;
            }
        }
        2 => {
            let mut previous = u16::from_le_bytes([header[0], header[1]]);
            for (out, delta) in output[2..].chunks_exact_mut(2).zip(stored.chunks_exact(2)) {
                previous = previous.wrapping_add(u16::from_le_bytes([delta[0], delta[1]]));
                out.copy_from_slice(&previous.to_le_bytes());
            }
        }
        4 => {
            let mut previous = u32::from_le_bytes([header[0], header[1], header[2], header[3]]);
            for (out, delta) in output[4..].chunks_exact_mut(4).zip(stored.chunks_exact(4)) {
                previous = previous
                    .wrapping_add(u32::from_le_bytes([delta[0], delta[1], delta[2], delta[3]]));
                out.copy_from_slice(&previous.to_le_bytes());
            }
        }
        8 => {
            let mut previous = u64::from_le_bytes([
                header[0], header[1], header[2], header[3], header[4], header[5], header[6],
                header[7],
            ]);
            for (out, delta) in output[8..].chunks_exact_mut(8).zip(stored.chunks_exact(8)) {
                previous = previous.wrapping_add(u64::from_le_bytes([
                    delta[0], delta[1], delta[2], delta[3], delta[4], delta[5], delta[6], delta[7],
                ]));
                out.copy_from_slice(&previous.to_le_bytes());
            }
        }
        _ => unreachable!("validate_numeric_stream_width accepted only supported widths"),
    }
}

fn decode_bitunpack_serial8_chunk(stored: &[u8], header: &[u8], limits: Limits) -> Result<Vec<u8>> {
    if header.is_empty() || header.len() > 2 {
        return Err(Error::new(ErrorKind::Malformed).with_detail("bitunpack header is malformed"));
    }
    let bits = usize::from(header[0]);
    if bits == 0 || bits > 8 {
        return Err(Error::new(ErrorKind::Unsupported)
            .with_detail("only byte-width bitunpack input is implemented"));
    }
    let bit_count = stored.len().checked_mul(bits).ok_or_else(|| {
        Error::new(ErrorKind::IntegerOverflow).with_detail("bitunpack size overflowed")
    })?;
    let output_len = bit_count.checked_add(7).ok_or_else(|| {
        Error::new(ErrorKind::IntegerOverflow).with_detail("bitunpack size overflowed")
    })? / 8;
    if output_len > limits.max_decoded_bytes || output_len > limits.max_buffer_bytes {
        return Err(
            Error::new(ErrorKind::LimitExceeded).with_detail("decoded output limit exceeded")
        );
    }
    if bits < 8 {
        let limit = 1u16 << bits;
        if stored.iter().any(|&value| u16::from(value) >= limit) {
            return Err(
                Error::new(ErrorKind::Malformed).with_detail("bitunpack value exceeds bit width")
            );
        }
    }
    let mut output = Vec::new();
    output.try_reserve_exact(output_len).map_err(|_| {
        Error::new(ErrorKind::LimitExceeded).with_detail("bitunpack allocation failed")
    })?;
    output.resize(output_len, 0);
    let mut bit_pos = 0usize;
    for &value in stored {
        let byte_pos = bit_pos / 8;
        let shift = bit_pos % 8;
        output[byte_pos] |= value << shift;
        if shift + bits > 8 {
            output[byte_pos + 1] |= value >> (8 - shift);
        }
        bit_pos += bits;
    }
    if header.len() == 2 {
        let rem_bits = output_len
            .checked_mul(8)
            .and_then(|bits_in_output| bits_in_output.checked_sub(bit_count))
            .ok_or_else(|| {
                Error::new(ErrorKind::IntegerOverflow).with_detail("bitunpack size overflowed")
            })?;
        if rem_bits == 0 || output_len == 0 || usize::from(header[1]) >= (1usize << rem_bits) {
            return Err(Error::new(ErrorKind::Malformed)
                .with_detail("bitunpack trailing bits are malformed"));
        }
        let last = output.last_mut().ok_or_else(|| {
            Error::new(ErrorKind::Malformed).with_detail("missing bitunpack output")
        })?;
        *last |= header[1] << (8 - rem_bits);
    }
    Ok(output)
}

fn decode_range_pack_serial8_chunk(
    stored: &[u8],
    header: &[u8],
    limits: Limits,
) -> Result<Vec<u8>> {
    if header.is_empty() {
        return Err(Error::new(ErrorKind::Malformed).with_detail("range_pack header is malformed"));
    }
    if header[0] != 1 {
        return Err(Error::new(ErrorKind::Unsupported)
            .with_detail("only byte-width range_pack output is implemented"));
    }
    let min_value = match header.len() {
        1 => 0,
        2 => header[1],
        _ => {
            return Err(
                Error::new(ErrorKind::Malformed).with_detail("range_pack header is malformed")
            );
        }
    };
    if stored.len() > limits.max_decoded_bytes || stored.len() > limits.max_buffer_bytes {
        return Err(
            Error::new(ErrorKind::LimitExceeded).with_detail("decoded output limit exceeded")
        );
    }
    let mut output = Vec::new();
    output.try_reserve_exact(stored.len()).map_err(|_| {
        Error::new(ErrorKind::LimitExceeded).with_detail("range_pack allocation failed")
    })?;
    for &value in stored {
        let decoded = value.checked_add(min_value).ok_or_else(|| {
            Error::new(ErrorKind::Malformed).with_detail("range_pack value overflowed")
        })?;
        output.push(decoded);
    }
    Ok(output)
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

#[cfg(feature = "zstd")]
fn decode_zstd_chunk(
    stored: &[u8],
    header: &[u8],
    limits: Limits,
    zstd: &mut zrip::DecompressContext,
) -> Result<Vec<u8>> {
    if !header.is_empty() {
        return Err(Error::new(ErrorKind::Unsupported)
            .with_detail("zstd transform headers are unsupported"));
    }
    let mut offset = 0usize;
    let element_width = read_var_u64(stored, &mut offset)?;
    if element_width == 0 || element_width != 1 {
        return Err(Error::new(ErrorKind::Unsupported)
            .with_detail("only serial byte zstd output is implemented"));
    }
    let magicless = stored
        .get(offset..)
        .ok_or_else(|| Error::at(ErrorKind::Truncated, offset))?;
    let output = zstd
        .decompress_after_magic_with_limit(magicless, limits.max_decoded_bytes)
        .map_err(|err| map_zstd_error(&err))?;
    let output = output.into_owned();
    if output.len() > limits.max_buffer_bytes {
        return Err(
            Error::new(ErrorKind::LimitExceeded).with_detail("decoded output limit exceeded")
        );
    }
    Ok(output)
}

#[cfg(feature = "zstd")]
fn map_zstd_error(err: &zrip::DecompressError) -> Error {
    if *err == zrip::DecompressError::OutputTooSmall {
        Error::new(ErrorKind::LimitExceeded).with_detail("decoded output limit exceeded")
    } else {
        Error::new(ErrorKind::Malformed).with_detail("OpenZL zstd frame failed")
    }
}

#[cfg(not(feature = "zstd"))]
fn decode_zstd_chunk(_stored: &[u8], _header: &[u8], _limits: Limits) -> Result<Vec<u8>> {
    Err(Error::new(ErrorKind::Unsupported).with_detail("zstd support is disabled"))
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

struct DecodedOutput<'a> {
    chunks: Vec<DecodedChunk<'a>>,
    total_len: usize,
}

enum DecodedChunk<'a> {
    Borrowed(&'a [u8]),
    Owned(Vec<u8>),
}

impl DecodedChunk<'_> {
    fn as_slice(&self) -> &[u8] {
        match self {
            Self::Borrowed(bytes) => bytes,
            Self::Owned(bytes) => bytes,
        }
    }
}

fn check_output_size(
    size: usize,
    encoded_size: usize,
    plan: &FramePlan,
    limits: Limits,
) -> Result<()> {
    if size > limits.max_decoded_bytes || size > limits.max_buffer_bytes {
        return Err(
            Error::new(ErrorKind::LimitExceeded).with_detail("decoded output limit exceeded")
        );
    }
    let max_expanded = encoded_size
        .checked_mul(limits.max_expansion_ratio)
        .ok_or_else(|| {
            Error::new(ErrorKind::IntegerOverflow)
                .with_detail("encoded size expansion limit overflowed")
        })?;
    if size > max_expanded {
        return Err(
            Error::new(ErrorKind::LimitExceeded).with_detail("decoded expansion ratio exceeded")
        );
    }
    if let Some(expected) = plan.info.output_sizes.first().and_then(|size| *size) {
        let expected = usize::try_from(expected).map_err(|_| {
            Error::new(ErrorKind::LimitExceeded).with_detail("decoded output size is too large")
        })?;
        if expected != size {
            return Err(Error::new(ErrorKind::Malformed)
                .with_detail("stored output size does not match frame header"));
        }
    }
    Ok(())
}

#[cfg(feature = "checksum")]
fn verify_decoded_checksum(output: &[u8], expected: Option<u32>) -> Result<()> {
    if let Some(expected) = expected {
        let actual = (xxhash_rust::xxh3::xxh3_64(output) & 0xffff_ffff) as u32;
        if actual != expected {
            return Err(Error::new(ErrorKind::ChecksumMismatch)
                .with_detail("OpenZL decoded checksum mismatch"));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse::parse_frame_plan;
    use alloc::vec;

    const MAGIC_BASE: u32 = 0xd7b1_a5c0;

    fn magic(version: u32) -> [u8; 4] {
        (MAGIC_BASE + version).to_le_bytes()
    }

    fn push_var_u64(out: &mut Vec<u8>, mut value: u64) {
        while value >= 0x80 {
            out.push(u8::try_from(value & 0x7f).unwrap() | 0x80);
            value >>= 7;
        }
        out.push(u8::try_from(value).unwrap());
    }

    fn lz4_serial_frame(stored: &[u8], decoded_len: usize) -> Vec<u8> {
        let mut transform_header = Vec::new();
        push_var_u64(&mut transform_header, u64::try_from(decoded_len).unwrap());
        let mut input = Vec::new();
        input.extend_from_slice(&magic(23));
        input.push(0);
        input.push(1);
        push_var_u64(&mut input, u64::try_from(decoded_len + 1).unwrap());
        input.push(2);
        input.push(1);
        input.push(0);
        input.push(62);
        input.push(1);
        push_var_u64(
            &mut input,
            u64::try_from(transform_header.len() - 1).unwrap(),
        );
        input.push(0);
        input.push(0);
        input.push(0);
        push_var_u64(&mut input, u64::try_from(stored.len()).unwrap());
        input.extend_from_slice(&transform_header);
        input.extend_from_slice(stored);
        input.push(0);
        input
    }

    fn standard_transform_serial_frame(
        version: u32,
        transform_id: u8,
        stored: &[u8],
        decoded_len: usize,
        transform_header: &[u8],
    ) -> Vec<u8> {
        let mut input = Vec::new();
        input.extend_from_slice(&magic(version));
        input.push(0);
        input.push(1);
        push_var_u64(&mut input, u64::try_from(decoded_len + 1).unwrap());
        input.push(2);
        input.push(1);
        input.push(0);
        input.push(transform_id);
        if transform_header.is_empty() {
            input.push(0);
        } else {
            input.push(1);
            push_var_u64(
                &mut input,
                u64::try_from(transform_header.len() - 1).unwrap(),
            );
        }
        input.push(0);
        input.push(0);
        input.push(0);
        push_var_u64(&mut input, u64::try_from(stored.len()).unwrap());
        input.extend_from_slice(transform_header);
        input.extend_from_slice(stored);
        input.push(0);
        input
    }

    fn concat_serial_frame(payload: &[u8]) -> Vec<u8> {
        let size_stream = u32::try_from(payload.len()).unwrap().to_le_bytes();
        let mut input = Vec::new();
        input.extend_from_slice(&magic(21));
        input.push(0);
        input.push(1);
        push_var_u64(&mut input, u64::try_from(payload.len() + 1).unwrap());
        input.push(2);
        input.push(2);
        input.push(0);
        input.push(55);
        input.push(0);
        input.push(0);
        input.push(0);
        input.push(0);
        push_var_u64(&mut input, u64::try_from(payload.len()).unwrap());
        input.push(4);
        input.extend_from_slice(payload);
        input.extend_from_slice(&size_stream);
        input.push(0);
        input
    }

    fn splitn_serial_frame(streams: &[&[u8]]) -> Vec<u8> {
        let decoded_len = streams.iter().map(|stream| stream.len()).sum::<usize>();
        let mut input = Vec::new();
        input.extend_from_slice(&magic(21));
        input.push(0);
        input.push(1);
        push_var_u64(&mut input, u64::try_from(decoded_len + 1).unwrap());
        input.push(2);
        push_var_u64(&mut input, u64::try_from(streams.len()).unwrap());
        input.push(0);
        input.push(40);
        input.push(0);
        if streams.is_empty() {
            input.push(0);
        } else {
            input.push(1);
            push_var_u64(&mut input, u64::try_from(streams.len() - 1).unwrap());
        }
        input.push(0);
        if !streams.is_empty() {
            input.push(0);
        }
        for stream in streams.iter().rev() {
            push_var_u64(&mut input, u64::try_from(stream.len()).unwrap());
        }
        for stream in streams.iter().rev() {
            input.extend_from_slice(stream);
        }
        input.push(0);
        input
    }

    fn zstd_serial_frame(stored: &[u8], decoded_len: usize) -> Vec<u8> {
        standard_transform_serial_frame(21, 22, stored, decoded_len, &[])
    }

    fn bitpack_serial_frame(values: &[u8], bits: u8) -> Vec<u8> {
        let stored = pack_lsb_bits(values, bits);
        let max_elements = (stored.len() * 8) / usize::from(bits);
        let extra = max_elements - values.len();
        let mut header = vec![bits - 1];
        if extra != 0 {
            header.push(u8::try_from(extra).unwrap());
        }
        standard_transform_serial_frame(21, 27, &stored, values.len(), &header)
    }

    fn bitpack_int_frame(values: &[u64], bits: u8, element_width: u8) -> Vec<u8> {
        let stored = pack_lsb_values(values, bits);
        let max_elements = (stored.len() * 8) / usize::from(bits);
        let extra = max_elements - values.len();
        let width_log = match element_width {
            1 => 0,
            2 => 1,
            4 => 2,
            8 => 3,
            _ => panic!("invalid element width"),
        };
        let mut header = vec![(width_log << 6) | (bits - 1)];
        if extra != 0 {
            header.push(u8::try_from(extra).unwrap());
        }
        standard_transform_serial_frame(
            21,
            28,
            &stored,
            values.len() * usize::from(element_width),
            &header,
        )
    }

    fn bitunpack_serial_frame(values: &[u8], bits: u8, trailing_bits: Option<u8>) -> Vec<u8> {
        let mut header = vec![bits];
        if let Some(trailing_bits) = trailing_bits {
            header.push(trailing_bits);
        }
        let decoded_len = (values.len() * usize::from(bits)).div_ceil(8);
        standard_transform_serial_frame(21, 34, values, decoded_len, &header)
    }

    fn range_pack_serial_frame(values: &[u8], min_value: Option<u8>) -> Vec<u8> {
        let mut header = vec![1];
        if let Some(min_value) = min_value {
            header.push(min_value);
        }
        standard_transform_serial_frame(21, 35, values, values.len(), &header)
    }

    fn constant_serial_frame(value: u8, count: usize) -> Vec<u8> {
        let mut header = Vec::new();
        push_var_u64(&mut header, u64::try_from(count).unwrap());
        standard_transform_serial_frame(21, 44, &[value], count, &header)
    }

    fn zigzag_serial_frame(stored: &[u8]) -> Vec<u8> {
        standard_transform_serial_frame(21, 3, stored, stored.len(), &[])
    }

    fn delta_serial_frame(first: Option<u8>, deltas: &[u8]) -> Vec<u8> {
        let header = first.map_or_else(Vec::new, |value| vec![value]);
        let decoded_len = deltas.len() + usize::from(first.is_some());
        standard_transform_serial_frame(21, 1, deltas, decoded_len, &header)
    }

    fn zigzag_delta_graph_frame(zigzag_encoded_deltas: &[u8], first: u8) -> Vec<u8> {
        let decoded_len = zigzag_encoded_deltas.len() + 1;
        let mut input = Vec::new();
        input.extend_from_slice(&magic(21));
        input.push(0);
        input.push(1);
        push_var_u64(&mut input, u64::try_from(decoded_len + 1).unwrap());
        input.push(3);
        input.push(1);
        input.push(0);
        input.extend_from_slice(&[67, 0]);
        input.push(2);
        input.push(0);
        input.push(0);
        input.push(0);
        input.push(0);
        push_var_u64(
            &mut input,
            u64::try_from(zigzag_encoded_deltas.len()).unwrap(),
        );
        input.push(first);
        input.extend_from_slice(zigzag_encoded_deltas);
        input.push(0);
        input
    }

    fn flatpack_serial_frame(alphabet: &[u8], indexes: &[u8]) -> Vec<u8> {
        let packed = pack_flatpack_indexes(alphabet.len(), indexes);
        let mut input = Vec::new();
        input.extend_from_slice(&magic(21));
        input.push(0);
        input.push(1);
        push_var_u64(&mut input, u64::try_from(indexes.len() + 1).unwrap());
        input.push(2);
        input.push(2);
        input.push(0);
        input.push(29);
        input.push(0);
        input.push(0);
        input.push(0);
        input.push(0);
        push_var_u64(&mut input, u64::try_from(packed.len()).unwrap());
        push_var_u64(&mut input, u64::try_from(alphabet.len()).unwrap());
        input.extend_from_slice(&packed);
        input.extend_from_slice(alphabet);
        input.push(0);
        input
    }

    fn transpose_split_frame(width: usize, lanes: &[&[u8]]) -> Vec<u8> {
        let decoded_len = lanes.first().map_or(0, |lane| lane.len() * width);
        let transform_id = match width {
            2 => 30,
            4 => 31,
            8 => 32,
            _ => unreachable!(),
        };
        let mut input = Vec::new();
        input.extend_from_slice(&magic(21));
        input.push(0);
        input.push(1);
        push_var_u64(&mut input, u64::try_from(decoded_len + 1).unwrap());
        input.push(2);
        push_var_u64(&mut input, u64::try_from(lanes.len()).unwrap());
        input.push(0);
        input.push(transform_id);
        input.push(0);
        input.push(0);
        input.push(0);
        input.push(0);
        for lane in lanes.iter().rev() {
            push_var_u64(&mut input, u64::try_from(lane.len()).unwrap());
        }
        for lane in lanes.iter().rev() {
            input.extend_from_slice(lane);
        }
        input.push(0);
        input
    }

    fn dynamic_transpose_split_frame(lanes: &[&[u8]]) -> Vec<u8> {
        let decoded_len = lanes.first().map_or(0, |lane| lane.len() * lanes.len());
        let mut input = Vec::new();
        input.extend_from_slice(&magic(21));
        input.push(0);
        input.push(1);
        push_var_u64(&mut input, u64::try_from(decoded_len + 1).unwrap());
        input.push(2);
        push_var_u64(&mut input, u64::try_from(lanes.len()).unwrap());
        input.push(0);
        input.push(4);
        input.push(0);
        if lanes.is_empty() {
            input.push(0);
        } else {
            input.push(1);
            push_var_u64(&mut input, u64::try_from(lanes.len() - 1).unwrap());
        }
        input.push(0);
        if !lanes.is_empty() {
            input.push(0);
        }
        for lane in lanes.iter().rev() {
            push_var_u64(&mut input, u64::try_from(lane.len()).unwrap());
        }
        for lane in lanes.iter().rev() {
            input.extend_from_slice(lane);
        }
        input.push(0);
        input
    }

    fn pack_flatpack_indexes(alphabet_len: usize, indexes: &[u8]) -> Vec<u8> {
        if indexes.is_empty() || alphabet_len == 0 {
            return Vec::new();
        }
        let bits = if alphabet_len <= 1 {
            alphabet_len
        } else {
            usize::BITS as usize - (alphabet_len - 1).leading_zeros() as usize
        };
        let packed_len = 1 + (bits * indexes.len()) / 8;
        let mut packed = vec![0; packed_len];
        let mut bit_offset = 0usize;
        for &index in indexes {
            let byte_offset = bit_offset / 8;
            let bit_shift = bit_offset % 8;
            let lane = u16::from(index) << bit_shift;
            let lane_bytes = lane.to_le_bytes();
            packed[byte_offset] |= lane_bytes[0];
            if bit_shift + bits > 8 {
                packed[byte_offset + 1] |= lane_bytes[1];
            }
            bit_offset += bits;
        }
        let byte_offset = bit_offset / 8;
        let bit_shift = bit_offset % 8;
        packed[byte_offset] |= 1 << bit_shift;
        packed
    }

    fn pack_lsb_bits(values: &[u8], bits: u8) -> Vec<u8> {
        let values = values.iter().copied().map(u64::from).collect::<Vec<_>>();
        pack_lsb_values(&values, bits)
    }

    fn pack_lsb_values(values: &[u64], bits: u8) -> Vec<u8> {
        let bits = usize::from(bits);
        let packed_len = (values.len() * bits).div_ceil(8);
        let mut output = vec![0; packed_len];
        let mask = if bits == 64 {
            u64::MAX
        } else {
            (1u64 << bits) - 1
        };
        for (index, &value) in values.iter().enumerate() {
            let bit_offset = index * bits;
            let byte_offset = bit_offset / 8;
            let bit_shift = bit_offset % 8;
            let lane = u128::from(value & mask) << bit_shift;
            let lane_bytes = lane.to_le_bytes();
            let byte_count = (bit_shift + bits).div_ceil(8);
            for byte_index in 0..byte_count {
                output[byte_offset + byte_index] |= lane_bytes[byte_index];
            }
        }
        output
    }

    #[test]
    fn supported_standard_nodes_have_decode_coverage() {
        let mut supported = vec![
            standard::BITPACK_SERIAL_ID,
            standard::BITPACK_INT_ID,
            standard::BIT_SPLIT_ID,
            standard::BITUNPACK_ID,
            standard::CONCAT_SERIAL_ID,
            standard::CONCAT_NUM_ID,
            standard::CONCAT_STRUCT_ID,
            standard::CONSTANT_SERIAL_ID,
            standard::CONVERT_NUM_TO_SERIAL_LE_ID,
            standard::CONVERT_NUM_TO_STRUCT_LE_ID,
            standard::CONVERT_SERIAL_TO_NUM_LE_ID,
            standard::CONVERT_SERIAL_TO_STRUCT_ID,
            standard::CONVERT_STRING_TO_SERIAL_ID,
            standard::CONVERT_STRUCT_TO_NUM_LE_ID,
            standard::CONVERT_STRUCT_TO_SERIAL_ID,
            standard::DELTA_INT_ID,
            standard::DISPATCH_N_BY_TAG_ID,
            standard::DISPATCH_STRING_ID,
            standard::FIELD_LZ_ID,
            standard::FSE_V2_ID,
            standard::FSE_NCOUNT_ID,
            standard::HUFFMAN_V2_ID,
            standard::FLATPACK_ID,
            standard::LZ_ID,
            standard::MUX_LENGTHS_ID,
            standard::PARTITION_ID,
            standard::QUANTIZE_LENGTHS_ID,
            standard::QUANTIZE_OFFSETS_ID,
            standard::RANGE_PACK_ID,
            standard::SENTINEL_ID,
            standard::SEPARATE_STRING_COMPONENTS_ID,
            standard::SPLITN_ID,
            standard::SPLITN_STRUCT_ID,
            standard::SPLIT_BY_STRUCT_ID,
            standard::TOKENIZE_FIXED_ID,
            standard::TOKENIZE_NUMERIC_ID,
            standard::TRANSPOSE_SPLIT_ID,
            standard::TRANSPOSE_SPLIT2_ID,
            standard::TRANSPOSE_SPLIT4_ID,
            standard::TRANSPOSE_SPLIT8_ID,
            standard::ZIGZAG_ID,
        ];
        #[cfg(feature = "lz4")]
        supported.push(standard::LZ4_ID);
        #[cfg(feature = "zstd")]
        supported.push(standard::ZSTD_ID);

        let mut covered = vec![
            standard::BITPACK_SERIAL_ID,
            standard::BITPACK_INT_ID,
            standard::BIT_SPLIT_ID,
            standard::BITUNPACK_ID,
            standard::CONCAT_SERIAL_ID,
            standard::CONCAT_NUM_ID,
            standard::CONCAT_STRUCT_ID,
            standard::CONSTANT_SERIAL_ID,
            standard::CONVERT_NUM_TO_SERIAL_LE_ID,
            standard::CONVERT_NUM_TO_STRUCT_LE_ID,
            standard::CONVERT_SERIAL_TO_NUM_LE_ID,
            standard::CONVERT_SERIAL_TO_STRUCT_ID,
            standard::CONVERT_STRING_TO_SERIAL_ID,
            standard::CONVERT_STRUCT_TO_NUM_LE_ID,
            standard::CONVERT_STRUCT_TO_SERIAL_ID,
            standard::DELTA_INT_ID,
            standard::DISPATCH_N_BY_TAG_ID,
            standard::DISPATCH_STRING_ID,
            standard::FIELD_LZ_ID,
            standard::FSE_V2_ID,
            standard::FSE_NCOUNT_ID,
            standard::HUFFMAN_V2_ID,
            standard::FLATPACK_ID,
            standard::LZ_ID,
            standard::MUX_LENGTHS_ID,
            standard::PARTITION_ID,
            standard::QUANTIZE_LENGTHS_ID,
            standard::QUANTIZE_OFFSETS_ID,
            standard::RANGE_PACK_ID,
            standard::SENTINEL_ID,
            standard::SEPARATE_STRING_COMPONENTS_ID,
            standard::SPLITN_ID,
            standard::SPLITN_STRUCT_ID,
            standard::SPLIT_BY_STRUCT_ID,
            standard::TOKENIZE_FIXED_ID,
            standard::TOKENIZE_NUMERIC_ID,
            standard::TRANSPOSE_SPLIT_ID,
            standard::TRANSPOSE_SPLIT2_ID,
            standard::TRANSPOSE_SPLIT4_ID,
            standard::TRANSPOSE_SPLIT8_ID,
            standard::ZIGZAG_ID,
        ];
        #[cfg(feature = "lz4")]
        covered.push(standard::LZ4_ID);
        #[cfg(feature = "zstd")]
        covered.push(standard::ZSTD_ID);

        supported.sort_unstable();
        covered.sort_unstable();
        assert_eq!(supported, covered);
    }

    #[test]
    fn decodes_v21_stored_serial_output() {
        let mut input = Vec::new();
        input.extend_from_slice(&magic(21));
        input.push(0);
        input.push(1);
        input.push(4);
        input.push(1);
        input.push(1);
        input.push(3);
        input.extend_from_slice(&[7, 8, 9]);
        input.push(0);
        let plan = parse_frame_plan(&input, Limits::default()).unwrap();
        let mut output = Vec::new();

        let written = decode_plan(&input, &plan, &mut output, Limits::default()).unwrap();

        assert_eq!(written, 3);
        assert_eq!(output, [7, 8, 9]);
    }

    #[test]
    fn decodes_empty_v21_stored_serial_output() {
        let mut input = Vec::new();
        input.extend_from_slice(&magic(21));
        input.push(0);
        input.push(1);
        input.push(1);
        input.push(0);
        let plan = parse_frame_plan(&input, Limits::default()).unwrap();
        let mut output = vec![1, 2];

        let written = decode_plan(&input, &plan, &mut output, Limits::default()).unwrap();

        assert_eq!(written, 0);
        assert_eq!(output, [1, 2]);
    }

    #[test]
    fn decodes_v21_stored_serial_chunks() {
        let mut input = Vec::new();
        input.extend_from_slice(&magic(21));
        input.push(0);
        input.push(1);
        input.push(8);
        input.push(1);
        input.push(1);
        input.push(3);
        input.extend_from_slice(&[7, 8, 9]);
        input.push(1);
        input.push(1);
        input.push(4);
        input.extend_from_slice(&[10, 11, 12, 13]);
        input.push(0);
        let plan = parse_frame_plan(&input, Limits::default()).unwrap();
        let mut output = Vec::new();

        let written = decode_plan(&input, &plan, &mut output, Limits::default()).unwrap();

        assert_eq!(written, 7);
        assert_eq!(output, [7, 8, 9, 10, 11, 12, 13]);
    }

    #[test]
    fn decodes_v21_concat_serial_chunk() {
        let input = concat_serial_frame(b"openzl concat");
        let plan = parse_frame_plan(&input, Limits::default()).unwrap();
        let mut output = Vec::new();

        let written = decode_plan(&input, &plan, &mut output, Limits::default()).unwrap();

        assert_eq!(written, 13);
        assert_eq!(output, b"openzl concat");
    }

    #[test]
    fn decodes_concat_typed_outputs() {
        let outputs = decode_concat_node(
            &[
                StreamInput {
                    bytes: &[2, 0, 0, 0, 1, 0, 0, 0],
                    element_width: 4,
                    string_lengths: None,
                },
                StreamInput {
                    bytes: &[1, 0, 2, 0, 3, 0],
                    element_width: 2,
                    string_lengths: None,
                },
            ],
            &[],
            Limits::default(),
        )
        .unwrap();

        assert_eq!(outputs.len(), 2);
        assert_eq!(outputs[0].element_width, 2);
        assert_eq!(outputs[0].bytes, [1, 0, 2, 0]);
        assert_eq!(outputs[1].element_width, 2);
        assert_eq!(outputs[1].bytes, [3, 0]);
    }

    #[test]
    fn rejects_concat_typed_size_mismatch() {
        let err = decode_concat_node(
            &[
                StreamInput {
                    bytes: &[2, 0, 0, 0],
                    element_width: 4,
                    string_lengths: None,
                },
                StreamInput {
                    bytes: &[1, 0, 2, 0, 3, 0],
                    element_width: 2,
                    string_lengths: None,
                },
            ],
            &[],
            Limits::default(),
        )
        .unwrap_err();

        assert_eq!(err.kind(), ErrorKind::Malformed);
    }

    #[test]
    fn rejects_concat_serial_output_limit_without_mutating_destination() {
        let input = concat_serial_frame(b"openzl concat");
        let plan = parse_frame_plan(&input, Limits::default()).unwrap();
        let mut output = vec![1, 2];
        let limits = Limits {
            max_decoded_bytes: 8,
            max_buffer_bytes: 8,
            ..Limits::default()
        };

        let err = decode_plan(&input, &plan, &mut output, limits).unwrap_err();

        assert_eq!(err.kind(), ErrorKind::LimitExceeded);
        assert_eq!(output, [1, 2]);
    }

    #[test]
    fn decodes_v21_splitn_serial_chunk() {
        let input = splitn_serial_frame(&[b"open", b"zl", b" splitn"]);
        let plan = parse_frame_plan(&input, Limits::default()).unwrap();
        let mut output = Vec::new();

        let written = decode_plan(&input, &plan, &mut output, Limits::default()).unwrap();

        assert_eq!(written, 13);
        assert_eq!(output, b"openzl splitn");
    }

    #[test]
    fn decodes_empty_v21_splitn_serial_chunk() {
        let input = splitn_serial_frame(&[]);
        let plan = parse_frame_plan(&input, Limits::default()).unwrap();
        let mut output = vec![1, 2];

        let written = decode_plan(&input, &plan, &mut output, Limits::default()).unwrap();

        assert_eq!(written, 0);
        assert_eq!(output, [1, 2]);
    }

    #[test]
    fn decodes_split_by_struct_node() {
        let output = decode_split_by_struct_node(
            &[
                StreamInput {
                    bytes: &[1, 2],
                    element_width: 1,
                    string_lengths: None,
                },
                StreamInput {
                    bytes: &[3, 0, 4, 0],
                    element_width: 2,
                    string_lengths: None,
                },
            ],
            2,
            &[],
            Limits::default(),
        )
        .unwrap();

        assert_eq!(output.element_width, 1);
        assert_eq!(output.bytes, [1, 3, 0, 2, 4, 0]);
    }

    #[test]
    fn rejects_split_by_struct_mismatched_element_counts() {
        let err = decode_split_by_struct_node(
            &[
                StreamInput {
                    bytes: &[1, 2],
                    element_width: 1,
                    string_lengths: None,
                },
                StreamInput {
                    bytes: &[3, 0],
                    element_width: 2,
                    string_lengths: None,
                },
            ],
            2,
            &[],
            Limits::default(),
        )
        .unwrap_err();

        assert_eq!(err.kind(), ErrorKind::Malformed);
    }

    #[test]
    fn decodes_dispatch_n_by_tag_node() {
        let output = decode_dispatch_n_by_tag_node(
            &[
                StreamInput {
                    bytes: &[0, 1, 0],
                    element_width: 1,
                    string_lengths: None,
                },
                StreamInput {
                    bytes: &[2, 3, 1],
                    element_width: 1,
                    string_lengths: None,
                },
                StreamInput {
                    bytes: b"abc",
                    element_width: 1,
                    string_lengths: None,
                },
                StreamInput {
                    bytes: b"XYZ",
                    element_width: 1,
                    string_lengths: None,
                },
            ],
            2,
            &[],
            21,
            Limits::default(),
        )
        .unwrap();

        assert_eq!(output, b"abXYZc");
    }

    #[test]
    fn rejects_dispatch_n_by_tag_invalid_tag() {
        let err = decode_dispatch_n_by_tag_node(
            &[
                StreamInput {
                    bytes: &[2],
                    element_width: 1,
                    string_lengths: None,
                },
                StreamInput {
                    bytes: &[1],
                    element_width: 1,
                    string_lengths: None,
                },
                StreamInput {
                    bytes: b"a",
                    element_width: 1,
                    string_lengths: None,
                },
            ],
            1,
            &[],
            21,
            Limits::default(),
        )
        .unwrap_err();

        assert_eq!(err.kind(), ErrorKind::Malformed);
    }

    #[test]
    fn rejects_dispatch_n_by_tag_size_mismatch() {
        let err = decode_dispatch_n_by_tag_node(
            &[
                StreamInput {
                    bytes: &[0],
                    element_width: 1,
                    string_lengths: None,
                },
                StreamInput {
                    bytes: &[2],
                    element_width: 1,
                    string_lengths: None,
                },
                StreamInput {
                    bytes: b"a",
                    element_width: 1,
                    string_lengths: None,
                },
            ],
            1,
            &[],
            21,
            Limits::default(),
        )
        .unwrap_err();

        assert_eq!(err.kind(), ErrorKind::Malformed);
    }

    #[test]
    fn rejects_splitn_output_limit_without_mutating_destination() {
        let input = splitn_serial_frame(&[b"open", b"zl", b" splitn"]);
        let plan = parse_frame_plan(&input, Limits::default()).unwrap();
        let mut output = vec![1, 2];
        let limits = Limits {
            max_decoded_bytes: 8,
            max_buffer_bytes: 8,
            ..Limits::default()
        };

        let err = decode_plan(&input, &plan, &mut output, limits).unwrap_err();

        assert_eq!(err.kind(), ErrorKind::LimitExceeded);
        assert_eq!(output, [1, 2]);
    }

    #[test]
    fn decodes_v21_bitpack_serial_chunk() {
        let expected = [0, 1, 2, 3, 4, 5, 6, 7, 1];
        let input = bitpack_serial_frame(&expected, 3);
        let plan = parse_frame_plan(&input, Limits::default()).unwrap();
        let mut output = Vec::new();

        let written = decode_plan(&input, &plan, &mut output, Limits::default()).unwrap();

        assert_eq!(written, expected.len());
        assert_eq!(output, expected);
    }

    #[test]
    fn decodes_v21_full_width_bitpack_serial_chunk() {
        let expected = b"bitpack";
        let input = bitpack_serial_frame(expected, 8);
        let plan = parse_frame_plan(&input, Limits::default()).unwrap();
        let mut output = Vec::new();

        let written = decode_plan(&input, &plan, &mut output, Limits::default()).unwrap();

        assert_eq!(written, expected.len());
        assert_eq!(output, expected);
    }

    #[test]
    fn decodes_v21_bitpack_int16_chunk() {
        let input = bitpack_int_frame(&[0, 1, 255, 256, 1023], 10, 2);
        let plan = parse_frame_plan(&input, Limits::default()).unwrap();
        let mut output = Vec::new();

        let written = decode_plan(&input, &plan, &mut output, Limits::default()).unwrap();

        assert_eq!(written, 10);
        assert_eq!(output, [0, 0, 1, 0, 255, 0, 0, 1, 255, 3]);
    }

    #[test]
    fn decodes_mux_lengths_inline_u16() {
        let muxed = [0x21];
        let long = [];
        let outputs = decode_mux_lengths_node(
            &[
                StreamInput {
                    bytes: &muxed,
                    element_width: 1,
                    string_lengths: None,
                },
                StreamInput {
                    bytes: &long,
                    element_width: 2,
                    string_lengths: None,
                },
            ],
            &[0x24],
            Limits::default(),
        )
        .unwrap();

        assert_eq!(outputs.len(), 2);
        assert_eq!(outputs[0].bytes, [1, 0]);
        assert_eq!(outputs[1].bytes, [4, 0]);
        assert_eq!(outputs[0].element_width, 2);
        assert_eq!(outputs[1].element_width, 2);
    }

    #[test]
    fn decodes_mux_lengths_overflow_u16() {
        let muxed = [0xff];
        let long = [5, 0, 2, 0];
        let outputs = decode_mux_lengths_node(
            &[
                StreamInput {
                    bytes: &muxed,
                    element_width: 1,
                    string_lengths: None,
                },
                StreamInput {
                    bytes: &long,
                    element_width: 2,
                    string_lengths: None,
                },
            ],
            &[0x24],
            Limits::default(),
        )
        .unwrap();

        assert_eq!(outputs[0].bytes, [20, 0]);
        assert_eq!(outputs[1].bytes, [19, 0]);
    }

    #[test]
    fn rejects_mux_lengths_exhausted_long_stream() {
        let muxed = [0xff];
        let long = [5, 0];
        let err = decode_mux_lengths_node(
            &[
                StreamInput {
                    bytes: &muxed,
                    element_width: 1,
                    string_lengths: None,
                },
                StreamInput {
                    bytes: &long,
                    element_width: 2,
                    string_lengths: None,
                },
            ],
            &[0x24],
            Limits::default(),
        )
        .unwrap_err();

        assert_eq!(err.kind(), ErrorKind::Malformed);
    }

    #[test]
    fn decodes_bitsplit_bf16_node() {
        let mantissas = [0x01, 0x7f];
        let exponents = [0x02, 0xff];
        let signs = [0x00, 0x01];
        let output = decode_bitsplit_node(
            &[
                StreamInput {
                    bytes: &mantissas,
                    element_width: 1,
                    string_lengths: None,
                },
                StreamInput {
                    bytes: &exponents,
                    element_width: 1,
                    string_lengths: None,
                },
                StreamInput {
                    bytes: &signs,
                    element_width: 1,
                    string_lengths: None,
                },
            ],
            3,
            &[2, 7, 8],
            Limits::default(),
        )
        .unwrap();

        assert_eq!(output.element_width, 2);
        assert_eq!(output.bytes, [0x01, 0x01, 0xff, 0xff]);
    }

    #[test]
    fn rejects_bitsplit_mismatched_input_width() {
        let input = [0u8; 2];
        let err = decode_bitsplit_node(
            &[StreamInput {
                bytes: &input,
                element_width: 1,
                string_lengths: None,
            }],
            1,
            &[2, 9],
            Limits::default(),
        )
        .unwrap_err();

        assert_eq!(err.kind(), ErrorKind::Malformed);
    }

    #[test]
    fn decodes_lz_node_with_trailing_literals() {
        let literals = b"abc!";
        let offsets = 3u16.to_le_bytes();
        let literal_lengths = 3u16.to_le_bytes();
        let match_lengths = 3u16.to_le_bytes();
        let output = decode_lz_node(
            &[
                StreamInput {
                    bytes: literals,
                    element_width: 1,
                    string_lengths: None,
                },
                StreamInput {
                    bytes: &offsets,
                    element_width: 2,
                    string_lengths: None,
                },
                StreamInput {
                    bytes: &literal_lengths,
                    element_width: 2,
                    string_lengths: None,
                },
                StreamInput {
                    bytes: &match_lengths,
                    element_width: 2,
                    string_lengths: None,
                },
            ],
            &[7],
            Limits::default(),
        )
        .unwrap();

        assert_eq!(output, b"abcabc!");
    }

    #[test]
    fn decodes_lz_node_with_overlapping_match() {
        let literals = b"a";
        let offsets = 1u16.to_le_bytes();
        let literal_lengths = 1u16.to_le_bytes();
        let match_lengths = 4u16.to_le_bytes();
        let output = decode_lz_node(
            &[
                StreamInput {
                    bytes: literals,
                    element_width: 1,
                    string_lengths: None,
                },
                StreamInput {
                    bytes: &offsets,
                    element_width: 2,
                    string_lengths: None,
                },
                StreamInput {
                    bytes: &literal_lengths,
                    element_width: 2,
                    string_lengths: None,
                },
                StreamInput {
                    bytes: &match_lengths,
                    element_width: 2,
                    string_lengths: None,
                },
            ],
            &[5],
            Limits::default(),
        )
        .unwrap();

        assert_eq!(output, b"aaaaa");
    }

    #[test]
    fn decodes_field_lz_node_with_last_literals() {
        let output = decode_field_lz_node(
            &[
                StreamInput {
                    bytes: b"abcdef",
                    element_width: 1,
                    string_lengths: None,
                },
                StreamInput {
                    bytes: &[],
                    element_width: 2,
                    string_lengths: None,
                },
                StreamInput {
                    bytes: &[],
                    element_width: 4,
                    string_lengths: None,
                },
                StreamInput {
                    bytes: &[],
                    element_width: 4,
                    string_lengths: None,
                },
                StreamInput {
                    bytes: &[],
                    element_width: 4,
                    string_lengths: None,
                },
            ],
            &[6],
            Limits::default(),
        )
        .unwrap();

        assert_eq!(output.element_width, 1);
        assert_eq!(output.bytes, b"abcdef");
    }

    #[test]
    fn decodes_field_lz_node_with_explicit_offset() {
        let token = 3u16 | (3u16 << 2);
        let offset = 3u32.to_le_bytes();
        let output = decode_field_lz_node(
            &[
                StreamInput {
                    bytes: b"abc!",
                    element_width: 1,
                    string_lengths: None,
                },
                StreamInput {
                    bytes: &token.to_le_bytes(),
                    element_width: 2,
                    string_lengths: None,
                },
                StreamInput {
                    bytes: &offset,
                    element_width: 4,
                    string_lengths: None,
                },
                StreamInput {
                    bytes: &[],
                    element_width: 4,
                    string_lengths: None,
                },
                StreamInput {
                    bytes: &[],
                    element_width: 4,
                    string_lengths: None,
                },
            ],
            &[8],
            Limits::default(),
        )
        .unwrap();

        assert_eq!(output.element_width, 1);
        assert_eq!(output.bytes, b"abcabca!");
    }

    #[test]
    fn decodes_separate_string_components_node() {
        let field_sizes = [1u16.to_le_bytes(), 3u16.to_le_bytes()].concat();
        let output = decode_separate_string_components_node(
            &[
                StreamInput {
                    bytes: b"abcd",
                    element_width: 1,
                    string_lengths: None,
                },
                StreamInput {
                    bytes: &field_sizes,
                    element_width: 2,
                    string_lengths: None,
                },
            ],
            &[],
            Limits::default(),
        )
        .unwrap();

        assert_eq!(output.element_width, 1);
        assert_eq!(output.bytes, b"abcd");
        assert_eq!(output.string_lengths.as_deref(), Some([1, 3].as_slice()));
    }

    #[test]
    fn rejects_separate_string_components_size_mismatch() {
        let field_sizes = [2u16.to_le_bytes(), 3u16.to_le_bytes()].concat();
        let err = decode_separate_string_components_node(
            &[
                StreamInput {
                    bytes: b"abcd",
                    element_width: 1,
                    string_lengths: None,
                },
                StreamInput {
                    bytes: &field_sizes,
                    element_width: 2,
                    string_lengths: None,
                },
            ],
            &[],
            Limits::default(),
        )
        .unwrap_err();

        assert_eq!(err.kind(), ErrorKind::Malformed);
    }

    #[test]
    fn decodes_dispatch_string_node() {
        let indices = [
            0u16.to_le_bytes(),
            1u16.to_le_bytes(),
            0u16.to_le_bytes(),
            1u16.to_le_bytes(),
        ]
        .concat();
        let first_lengths = [1, 1];
        let second_lengths = [1, 1];

        let output = decode_dispatch_string_node(
            &[
                StreamInput {
                    bytes: &indices,
                    element_width: 2,
                    string_lengths: None,
                },
                StreamInput {
                    bytes: b"ab",
                    element_width: 1,
                    string_lengths: Some(&first_lengths),
                },
                StreamInput {
                    bytes: b"XY",
                    element_width: 1,
                    string_lengths: Some(&second_lengths),
                },
            ],
            2,
            &[],
            21,
            Limits::default(),
        )
        .unwrap();

        assert_eq!(output.element_width, 1);
        assert_eq!(output.bytes, b"aXbY");
        assert_eq!(
            output.string_lengths.as_deref(),
            Some([1, 1, 1, 1].as_slice())
        );
    }

    #[test]
    fn rejects_dispatch_string_invalid_source_index() {
        let indices = 2u16.to_le_bytes();
        let lengths = [1];
        let err = decode_dispatch_string_node(
            &[
                StreamInput {
                    bytes: &indices,
                    element_width: 2,
                    string_lengths: None,
                },
                StreamInput {
                    bytes: b"a",
                    element_width: 1,
                    string_lengths: Some(&lengths),
                },
            ],
            1,
            &[],
            21,
            Limits::default(),
        )
        .unwrap_err();

        assert_eq!(err.kind(), ErrorKind::Malformed);
    }

    #[test]
    fn decodes_string_to_serial_node() {
        let lengths = [1, 3];
        let output = decode_string_to_serial_node(
            StreamInput {
                bytes: b"abcd",
                element_width: 1,
                string_lengths: Some(&lengths),
            },
            &[],
            Limits::default(),
        )
        .unwrap();

        assert_eq!(output, b"abcd");
    }

    #[test]
    fn decodes_sentinel_node_with_default_marker() {
        let exceptions = 300u16.to_le_bytes();
        let output = decode_sentinel_node(
            &[
                StreamInput {
                    bytes: &[1, 255, 2],
                    element_width: 1,
                    string_lengths: None,
                },
                StreamInput {
                    bytes: &exceptions,
                    element_width: 2,
                    string_lengths: None,
                },
            ],
            &[],
            Limits::default(),
        )
        .unwrap();

        assert_eq!(output.element_width, 2);
        assert_eq!(output.bytes, [1, 0, 44, 1, 2, 0]);
    }

    #[test]
    fn rejects_sentinel_unconsumed_exception() {
        let exceptions = [300u16.to_le_bytes(), 301u16.to_le_bytes()].concat();
        let err = decode_sentinel_node(
            &[
                StreamInput {
                    bytes: &[1, 255, 2],
                    element_width: 1,
                    string_lengths: None,
                },
                StreamInput {
                    bytes: &exceptions,
                    element_width: 2,
                    string_lengths: None,
                },
            ],
            &[],
            Limits::default(),
        )
        .unwrap_err();

        assert_eq!(err.kind(), ErrorKind::Malformed);
    }

    #[test]
    fn rejects_bitpack_output_limit_without_mutating_destination() {
        let expected = [0, 1, 2, 3, 4, 5, 6, 7, 1];
        let input = bitpack_serial_frame(&expected, 3);
        let plan = parse_frame_plan(&input, Limits::default()).unwrap();
        let mut output = vec![1, 2];
        let limits = Limits {
            max_decoded_bytes: 4,
            max_buffer_bytes: 4,
            ..Limits::default()
        };

        let err = decode_plan(&input, &plan, &mut output, limits).unwrap_err();

        assert_eq!(err.kind(), ErrorKind::LimitExceeded);
        assert_eq!(output, [1, 2]);
    }

    #[test]
    fn decodes_v21_bitunpack_serial8_chunk() {
        let input = bitunpack_serial_frame(&[2, 7, 3, 4, 5, 1, 7, 6], 3, None);
        let plan = parse_frame_plan(&input, Limits::default()).unwrap();
        let mut output = Vec::new();

        let written = decode_plan(&input, &plan, &mut output, Limits::default()).unwrap();

        assert_eq!(written, 3);
        assert_eq!(output, [0xfa, 0xd8, 0xdc]);
    }

    #[test]
    fn decodes_v21_bitunpack_serial8_trailing_bits() {
        let input = bitunpack_serial_frame(&[1], 3, Some(0b1_1111));
        let plan = parse_frame_plan(&input, Limits::default()).unwrap();
        let mut output = Vec::new();

        let written = decode_plan(&input, &plan, &mut output, Limits::default()).unwrap();

        assert_eq!(written, 1);
        assert_eq!(output, [0b1111_1001]);
    }

    #[test]
    fn rejects_bitunpack_value_overflow_without_mutating_destination() {
        let input = bitunpack_serial_frame(&[8], 3, None);
        let plan = parse_frame_plan(&input, Limits::default()).unwrap();
        let mut output = vec![1, 2];

        let err = decode_plan(&input, &plan, &mut output, Limits::default()).unwrap_err();

        assert_eq!(err.kind(), ErrorKind::Malformed);
        assert_eq!(output, [1, 2]);
    }

    #[test]
    fn rejects_bitunpack_output_limit_without_mutating_destination() {
        let input = bitunpack_serial_frame(&[2, 7, 3, 4, 5, 1, 7, 6], 3, None);
        let plan = parse_frame_plan(&input, Limits::default()).unwrap();
        let mut output = vec![1, 2];
        let limits = Limits {
            max_decoded_bytes: 2,
            max_buffer_bytes: 2,
            ..Limits::default()
        };

        let err = decode_plan(&input, &plan, &mut output, limits).unwrap_err();

        assert_eq!(err.kind(), ErrorKind::LimitExceeded);
        assert_eq!(output, [1, 2]);
    }

    #[test]
    fn decodes_v21_range_pack_serial8_chunk() {
        let input = range_pack_serial_frame(&[0, 1, 5], Some(10));
        let plan = parse_frame_plan(&input, Limits::default()).unwrap();
        let mut output = Vec::new();

        let written = decode_plan(&input, &plan, &mut output, Limits::default()).unwrap();

        assert_eq!(written, 3);
        assert_eq!(output, [10, 11, 15]);
    }

    #[test]
    fn decodes_v21_range_pack_serial8_without_minimum() {
        let input = range_pack_serial_frame(&[0, 1, 5], None);
        let plan = parse_frame_plan(&input, Limits::default()).unwrap();
        let mut output = Vec::new();

        let written = decode_plan(&input, &plan, &mut output, Limits::default()).unwrap();

        assert_eq!(written, 3);
        assert_eq!(output, [0, 1, 5]);
    }

    #[test]
    fn rejects_range_pack_overflow_without_mutating_destination() {
        let input = range_pack_serial_frame(&[250], Some(10));
        let plan = parse_frame_plan(&input, Limits::default()).unwrap();
        let mut output = vec![1, 2];

        let err = decode_plan(&input, &plan, &mut output, Limits::default()).unwrap_err();

        assert_eq!(err.kind(), ErrorKind::Malformed);
        assert_eq!(output, [1, 2]);
    }

    #[test]
    fn rejects_range_pack_output_limit_without_mutating_destination() {
        let input = range_pack_serial_frame(&[0, 1, 5], Some(10));
        let plan = parse_frame_plan(&input, Limits::default()).unwrap();
        let mut output = vec![1, 2];
        let limits = Limits {
            max_decoded_bytes: 2,
            max_buffer_bytes: 2,
            ..Limits::default()
        };

        let err = decode_plan(&input, &plan, &mut output, limits).unwrap_err();

        assert_eq!(err.kind(), ErrorKind::LimitExceeded);
        assert_eq!(output, [1, 2]);
    }

    #[test]
    fn decodes_v21_constant_serial_chunk() {
        let input = constant_serial_frame(b'x', 6);
        let plan = parse_frame_plan(&input, Limits::default()).unwrap();
        let mut output = Vec::new();

        let written = decode_plan(&input, &plan, &mut output, Limits::default()).unwrap();

        assert_eq!(written, 6);
        assert_eq!(output, b"xxxxxx");
    }

    #[test]
    fn rejects_zero_count_constant_serial_without_mutating_destination() {
        let input = constant_serial_frame(b'x', 0);
        let plan = parse_frame_plan(&input, Limits::default()).unwrap();
        let mut output = vec![1, 2];

        let err = decode_plan(&input, &plan, &mut output, Limits::default()).unwrap_err();

        assert_eq!(err.kind(), ErrorKind::Malformed);
        assert_eq!(output, [1, 2]);
    }

    #[test]
    fn rejects_constant_serial_output_limit_without_mutating_destination() {
        let input = constant_serial_frame(b'x', 6);
        let plan = parse_frame_plan(&input, Limits::default()).unwrap();
        let mut output = vec![1, 2];
        let limits = Limits {
            max_decoded_bytes: 4,
            max_buffer_bytes: 4,
            ..Limits::default()
        };

        let err = decode_plan(&input, &plan, &mut output, limits).unwrap_err();

        assert_eq!(err.kind(), ErrorKind::LimitExceeded);
        assert_eq!(output, [1, 2]);
    }

    #[test]
    fn decodes_v21_zigzag_serial8_chunk() {
        let input = zigzag_serial_frame(&[0, 1, 2, 3, 4, 5, 254, 255]);
        let plan = parse_frame_plan(&input, Limits::default()).unwrap();
        let mut output = Vec::new();

        let written = decode_plan(&input, &plan, &mut output, Limits::default()).unwrap();

        assert_eq!(written, 8);
        assert_eq!(output, [0, 255, 1, 254, 2, 253, 127, 128]);
    }

    #[test]
    fn decodes_zigzag_numeric_i32_chunk() {
        let values = [0u32, 1, 2, 21, 244, 245, u32::MAX];
        let mut input = Vec::new();
        for value in values {
            input.extend_from_slice(&value.to_le_bytes());
        }

        let output = decode_zigzag_numeric_chunk(
            StreamInput {
                bytes: &input,
                element_width: 4,
                string_lengths: None,
            },
            &[],
            Limits::default(),
        )
        .unwrap();

        assert_eq!(output.element_width, 4);
        assert_eq!(
            output.bytes,
            [0i32, -1, 1, -11, 122, -123, i32::MIN,]
                .into_iter()
                .flat_map(i32::to_le_bytes)
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn rejects_zigzag_header_without_mutating_destination() {
        let input = standard_transform_serial_frame(21, 3, b"bytes", 5, &[0]);
        let plan = parse_frame_plan(&input, Limits::default()).unwrap();
        let mut output = vec![1, 2];

        let err = decode_plan(&input, &plan, &mut output, Limits::default()).unwrap_err();

        assert_eq!(err.kind(), ErrorKind::Unsupported);
        assert_eq!(output, [1, 2]);
    }

    #[test]
    fn rejects_zigzag_output_limit_without_mutating_destination() {
        let input = zigzag_serial_frame(b"bytes");
        let plan = parse_frame_plan(&input, Limits::default()).unwrap();
        let mut output = vec![1, 2];
        let limits = Limits {
            max_decoded_bytes: 4,
            max_buffer_bytes: 4,
            ..Limits::default()
        };

        let err = decode_plan(&input, &plan, &mut output, limits).unwrap_err();

        assert_eq!(err.kind(), ErrorKind::LimitExceeded);
        assert_eq!(output, [1, 2]);
    }

    #[test]
    fn decodes_v21_delta_serial8_chunk() {
        let input = delta_serial_frame(Some(2), &[1, 1, 2, 250]);
        let plan = parse_frame_plan(&input, Limits::default()).unwrap();
        let mut output = Vec::new();

        let written = decode_plan(&input, &plan, &mut output, Limits::default()).unwrap();

        assert_eq!(written, 5);
        assert_eq!(output, [2, 3, 4, 6, 0]);
    }

    #[test]
    fn decodes_v21_two_node_regenerated_stream_graph() {
        let input = zigzag_delta_graph_frame(&[2, 1, 6], 10);
        let plan = parse_frame_plan(&input, Limits::default()).unwrap();
        let mut output = Vec::new();

        let written = decode_plan(&input, &plan, &mut output, Limits::default()).unwrap();

        assert_eq!(written, 4);
        assert_eq!(output, [10, 11, 10, 13]);
    }

    #[test]
    fn decodes_empty_v21_delta_serial8_chunk() {
        let input = delta_serial_frame(None, &[]);
        let plan = parse_frame_plan(&input, Limits::default()).unwrap();
        let mut output = vec![1, 2];

        let written = decode_plan(&input, &plan, &mut output, Limits::default()).unwrap();

        assert_eq!(written, 0);
        assert_eq!(output, [1, 2]);
    }

    #[test]
    fn rejects_delta_without_first_value_without_mutating_destination() {
        let input = delta_serial_frame(None, &[1]);
        let plan = parse_frame_plan(&input, Limits::default()).unwrap();
        let mut output = vec![1, 2];

        let err = decode_plan(&input, &plan, &mut output, Limits::default()).unwrap_err();

        assert_eq!(err.kind(), ErrorKind::Malformed);
        assert_eq!(output, [1, 2]);
    }

    #[test]
    fn rejects_delta_output_limit_without_mutating_destination() {
        let input = delta_serial_frame(Some(2), &[1, 1, 2, 250]);
        let plan = parse_frame_plan(&input, Limits::default()).unwrap();
        let mut output = vec![1, 2];
        let limits = Limits {
            max_decoded_bytes: 4,
            max_buffer_bytes: 4,
            ..Limits::default()
        };

        let err = decode_plan(&input, &plan, &mut output, limits).unwrap_err();

        assert_eq!(err.kind(), ErrorKind::LimitExceeded);
        assert_eq!(output, [1, 2]);
    }

    #[test]
    fn decodes_v21_convert_serial_to_struct_chunk() {
        let expected = b"struct payload bytes";
        let input = standard_transform_serial_frame(21, 5, expected, expected.len(), &[]);
        let plan = parse_frame_plan(&input, Limits::default()).unwrap();
        let mut output = Vec::new();

        let written = decode_plan(&input, &plan, &mut output, Limits::default()).unwrap();

        assert_eq!(written, expected.len());
        assert_eq!(output, expected);
    }

    #[test]
    fn decodes_v21_convert_struct_to_serial_chunk() {
        let expected = b"serial payload bytes";
        let input = standard_transform_serial_frame(21, 6, expected, expected.len(), &[1]);
        let plan = parse_frame_plan(&input, Limits::default()).unwrap();
        let mut output = Vec::new();

        let written = decode_plan(&input, &plan, &mut output, Limits::default()).unwrap();

        assert_eq!(written, expected.len());
        assert_eq!(output, expected);
    }

    #[test]
    fn decodes_v21_convert_num_to_struct_le_chunk() {
        let expected = [1, 0, 2, 0, 3, 0, 4, 0];
        let input = standard_transform_serial_frame(21, 8, &expected, expected.len(), &[]);
        let plan = parse_frame_plan(&input, Limits::default()).unwrap();
        let mut output = Vec::new();

        let written = decode_plan(&input, &plan, &mut output, Limits::default()).unwrap();

        assert_eq!(written, expected.len());
        assert_eq!(output, expected);
    }

    #[test]
    fn decodes_v21_convert_serial_to_num_le_chunk() {
        let expected = [1, 0, 2, 0, 3, 0, 4, 0];
        let input = standard_transform_serial_frame(21, 9, &expected, expected.len(), &[]);
        let plan = parse_frame_plan(&input, Limits::default()).unwrap();
        let mut output = Vec::new();

        let written = decode_plan(&input, &plan, &mut output, Limits::default()).unwrap();

        assert_eq!(written, expected.len());
        assert_eq!(output, expected);
    }

    #[test]
    fn decodes_v21_convert_num_to_serial_le_chunk() {
        let expected = [1, 0, 2, 0, 3, 0, 4, 0];
        let input = standard_transform_serial_frame(21, 10, &expected, expected.len(), &[1]);
        let plan = parse_frame_plan(&input, Limits::default()).unwrap();
        let mut output = Vec::new();

        let written = decode_plan(&input, &plan, &mut output, Limits::default()).unwrap();

        assert_eq!(written, expected.len());
        assert_eq!(output, expected);
    }

    #[test]
    fn rejects_convert_num_to_serial_bad_header_without_mutating_destination() {
        let input = standard_transform_serial_frame(21, 10, b"bytes", 5, &[]);
        let plan = parse_frame_plan(&input, Limits::default()).unwrap();
        let mut output = vec![1, 2];

        let err = decode_plan(&input, &plan, &mut output, Limits::default()).unwrap_err();

        assert_eq!(err.kind(), ErrorKind::Malformed);
        assert_eq!(output, [1, 2]);
    }

    #[test]
    fn rejects_convert_num_to_serial_unaligned_size_without_mutating_destination() {
        let input = standard_transform_serial_frame(21, 10, b"bytes", 5, &[2]);
        let plan = parse_frame_plan(&input, Limits::default()).unwrap();
        let mut output = vec![1, 2];

        let err = decode_plan(&input, &plan, &mut output, Limits::default()).unwrap_err();

        assert_eq!(err.kind(), ErrorKind::Malformed);
        assert_eq!(output, [1, 2]);
    }

    #[test]
    fn rejects_convert_serial_to_struct_header_without_mutating_destination() {
        let input = standard_transform_serial_frame(21, 5, b"bytes", 5, &[0]);
        let plan = parse_frame_plan(&input, Limits::default()).unwrap();
        let mut output = vec![1, 2];

        let err = decode_plan(&input, &plan, &mut output, Limits::default()).unwrap_err();

        assert_eq!(err.kind(), ErrorKind::Unsupported);
        assert_eq!(output, [1, 2]);
    }

    #[test]
    fn rejects_convert_serial_to_struct_output_limit_without_mutating_destination() {
        let input = standard_transform_serial_frame(21, 5, b"bytes", 5, &[]);
        let plan = parse_frame_plan(&input, Limits::default()).unwrap();
        let mut output = vec![1, 2];
        let limits = Limits {
            max_decoded_bytes: 4,
            max_buffer_bytes: 4,
            ..Limits::default()
        };

        let err = decode_plan(&input, &plan, &mut output, limits).unwrap_err();

        assert_eq!(err.kind(), ErrorKind::LimitExceeded);
        assert_eq!(output, [1, 2]);
    }

    #[test]
    fn rejects_convert_struct_to_serial_output_limit_without_mutating_destination() {
        let input = standard_transform_serial_frame(21, 6, b"bytes", 5, &[1]);
        let plan = parse_frame_plan(&input, Limits::default()).unwrap();
        let mut output = vec![1, 2];
        let limits = Limits {
            max_decoded_bytes: 4,
            max_buffer_bytes: 4,
            ..Limits::default()
        };

        let err = decode_plan(&input, &plan, &mut output, limits).unwrap_err();

        assert_eq!(err.kind(), ErrorKind::LimitExceeded);
        assert_eq!(output, [1, 2]);
    }

    #[test]
    fn decodes_v21_flatpack_serial_chunk() {
        let input = flatpack_serial_frame(b"abc", &[0, 1, 2, 1, 0]);
        let plan = parse_frame_plan(&input, Limits::default()).unwrap();
        let mut output = Vec::new();

        let written = decode_plan(&input, &plan, &mut output, Limits::default()).unwrap();

        assert_eq!(written, 5);
        assert_eq!(output, b"abcba");
    }

    #[test]
    fn decodes_empty_v21_flatpack_serial_chunk() {
        let input = flatpack_serial_frame(b"", &[]);
        let plan = parse_frame_plan(&input, Limits::default()).unwrap();
        let mut output = vec![1, 2];

        let written = decode_plan(&input, &plan, &mut output, Limits::default()).unwrap();

        assert_eq!(written, 0);
        assert_eq!(output, [1, 2]);
    }

    #[test]
    fn rejects_flatpack_output_limit_without_mutating_destination() {
        let input = flatpack_serial_frame(b"abc", &[0, 1, 2, 1, 0]);
        let plan = parse_frame_plan(&input, Limits::default()).unwrap();
        let mut output = vec![1, 2];
        let limits = Limits {
            max_decoded_bytes: 4,
            max_buffer_bytes: 4,
            ..Limits::default()
        };

        let err = decode_plan(&input, &plan, &mut output, limits).unwrap_err();

        assert_eq!(err.kind(), ErrorKind::LimitExceeded);
        assert_eq!(output, [1, 2]);
    }

    #[test]
    fn decodes_v21_transpose_split2_chunk() {
        let input = transpose_split_frame(2, &[b"ace", b"bdf"]);
        let plan = parse_frame_plan(&input, Limits::default()).unwrap();
        let mut output = Vec::new();

        let written = decode_plan(&input, &plan, &mut output, Limits::default()).unwrap();

        assert_eq!(written, 6);
        assert_eq!(output, b"abcdef");
    }

    #[test]
    fn decodes_v21_dynamic_transpose_split_chunk() {
        let input = dynamic_transpose_split_frame(&[b"ace", b"bdf"]);
        let plan = parse_frame_plan(&input, Limits::default()).unwrap();
        let mut output = Vec::new();

        let written = decode_plan(&input, &plan, &mut output, Limits::default()).unwrap();

        assert_eq!(written, 6);
        assert_eq!(output, b"abcdef");
    }

    #[test]
    fn decodes_v21_transpose_split4_chunk() {
        let input = transpose_split_frame(4, &[b"ae", b"bf", b"cg", b"dh"]);
        let plan = parse_frame_plan(&input, Limits::default()).unwrap();
        let mut output = Vec::new();

        let written = decode_plan(&input, &plan, &mut output, Limits::default()).unwrap();

        assert_eq!(written, 8);
        assert_eq!(output, b"abcdefgh");
    }

    #[test]
    fn decodes_v21_transpose_split8_chunk() {
        let input = transpose_split_frame(8, &[b"a", b"b", b"c", b"d", b"e", b"f", b"g", b"h"]);
        let plan = parse_frame_plan(&input, Limits::default()).unwrap();
        let mut output = Vec::new();

        let written = decode_plan(&input, &plan, &mut output, Limits::default()).unwrap();

        assert_eq!(written, 8);
        assert_eq!(output, b"abcdefgh");
    }

    #[test]
    fn rejects_transpose_split_mismatched_lanes_without_mutating_destination() {
        let input = transpose_split_frame(2, &[b"ace", b"bd"]);
        let plan = parse_frame_plan(&input, Limits::default()).unwrap();
        let mut output = vec![1, 2];

        let err = decode_plan(&input, &plan, &mut output, Limits::default()).unwrap_err();

        assert_eq!(err.kind(), ErrorKind::Malformed);
        assert_eq!(output, [1, 2]);
    }

    #[test]
    fn decodes_partition_preset_varbyte16_node() {
        let output = decode_partition_node(
            &[
                StreamInput {
                    bytes: &[0, 1, 2],
                    element_width: 1,
                    string_lengths: None,
                },
                StreamInput {
                    bytes: &[0x0d],
                    element_width: 1,
                    string_lengths: None,
                },
            ],
            &[0x15],
            Limits::default(),
        )
        .unwrap();

        assert_eq!(output.element_width, 2);
        assert_eq!(
            output.bytes,
            [1u16, 2, 7]
                .into_iter()
                .flat_map(u16::to_le_bytes)
                .collect::<Vec<_>>()
        );
    }

    #[cfg(feature = "lz4")]
    #[test]
    fn decodes_v23_lz4_serial_chunk() {
        let expected = b"lz4-backed OpenZL serial chunk";
        let compressed = lz4rip::block::compress(expected);
        let input = lz4_serial_frame(&compressed, expected.len());
        let plan = parse_frame_plan(&input, Limits::default()).unwrap();
        let mut output = Vec::new();

        let written = decode_plan(&input, &plan, &mut output, Limits::default()).unwrap();

        assert_eq!(written, expected.len());
        assert_eq!(output, expected);
    }

    #[cfg(feature = "zstd")]
    #[test]
    fn decodes_v21_zstd_serial_chunk() {
        let expected = b"zstd-backed OpenZL serial chunk";
        let compressed = zrip::compress(expected, 1).unwrap();
        let mut stored = Vec::new();
        push_var_u64(&mut stored, 1);
        stored.extend_from_slice(&compressed[4..]);
        let input = zstd_serial_frame(&stored, expected.len());
        let plan = parse_frame_plan(&input, Limits::default()).unwrap();
        let mut output = Vec::new();

        let written = decode_plan(&input, &plan, &mut output, Limits::default()).unwrap();

        assert_eq!(written, expected.len());
        assert_eq!(output, expected);
    }

    #[cfg(feature = "zstd")]
    #[test]
    fn rejects_malformed_zstd_chunk_without_mutating_destination() {
        let mut stored = Vec::new();
        push_var_u64(&mut stored, 1);
        stored.extend_from_slice(&[0]);
        let input = zstd_serial_frame(&stored, 8);
        let plan = parse_frame_plan(&input, Limits::default()).unwrap();
        let mut output = vec![1, 2];

        let err = decode_plan(&input, &plan, &mut output, Limits::default()).unwrap_err();

        assert_eq!(err.kind(), ErrorKind::Malformed);
        assert_eq!(output, [1, 2]);
    }

    #[cfg(feature = "zstd")]
    #[test]
    fn rejects_zstd_non_byte_output_width_without_mutating_destination() {
        let expected = b"zstd-backed OpenZL serial chunk";
        let compressed = zrip::compress(expected, 1).unwrap();
        let mut stored = Vec::new();
        push_var_u64(&mut stored, 2);
        stored.extend_from_slice(&compressed[4..]);
        let input = zstd_serial_frame(&stored, expected.len());
        let plan = parse_frame_plan(&input, Limits::default()).unwrap();
        let mut output = vec![1, 2];

        let err = decode_plan(&input, &plan, &mut output, Limits::default()).unwrap_err();

        assert_eq!(err.kind(), ErrorKind::Unsupported);
        assert_eq!(output, [1, 2]);
    }

    #[cfg(feature = "zstd")]
    #[test]
    fn rejects_zstd_transform_header_without_mutating_destination() {
        let expected = b"zstd-backed OpenZL serial chunk";
        let compressed = zrip::compress(expected, 1).unwrap();
        let mut stored = Vec::new();
        push_var_u64(&mut stored, 1);
        stored.extend_from_slice(&compressed[4..]);
        let input = standard_transform_serial_frame(21, 22, &stored, expected.len(), &[0]);
        let plan = parse_frame_plan(&input, Limits::default()).unwrap();
        let mut output = vec![1, 2];

        let err = decode_plan(&input, &plan, &mut output, Limits::default()).unwrap_err();

        assert_eq!(err.kind(), ErrorKind::Unsupported);
        assert_eq!(output, [1, 2]);
    }

    #[cfg(feature = "zstd")]
    #[test]
    fn enforces_zstd_output_limit_without_mutating_destination() {
        let expected = b"zstd output larger than configured limits";
        let compressed = zrip::compress(expected, 1).unwrap();
        let mut stored = Vec::new();
        push_var_u64(&mut stored, 1);
        stored.extend_from_slice(&compressed[4..]);
        let input = zstd_serial_frame(&stored, expected.len());
        let plan = parse_frame_plan(&input, Limits::default()).unwrap();
        let mut output = vec![1, 2];
        let limits = Limits {
            max_decoded_bytes: 8,
            max_buffer_bytes: 8,
            ..Limits::default()
        };

        let err = decode_plan(&input, &plan, &mut output, limits).unwrap_err();

        assert_eq!(err.kind(), ErrorKind::LimitExceeded);
        assert_eq!(output, [1, 2]);
    }

    #[cfg(not(feature = "zstd"))]
    #[test]
    fn rejects_zstd_chunk_when_feature_is_disabled() {
        let input = zstd_serial_frame(&[1, 0], 8);
        let plan = parse_frame_plan(&input, Limits::default()).unwrap();
        let mut output = vec![1, 2];

        let err = decode_plan(&input, &plan, &mut output, Limits::default()).unwrap_err();

        assert_eq!(err.kind(), ErrorKind::Unsupported);
        assert_eq!(output, [1, 2]);
    }

    #[cfg(feature = "lz4")]
    #[test]
    fn rejects_malformed_lz4_chunk_without_mutating_destination() {
        let input = lz4_serial_frame(&[0], 8);
        let plan = parse_frame_plan(&input, Limits::default()).unwrap();
        let mut output = vec![1, 2];

        let err = decode_plan(&input, &plan, &mut output, Limits::default()).unwrap_err();

        assert_eq!(err.kind(), ErrorKind::Malformed);
        assert_eq!(output, [1, 2]);
    }

    #[cfg(feature = "lz4")]
    #[test]
    fn enforces_lz4_header_output_limit_without_mutating_destination() {
        let input = lz4_serial_frame(&[0], 4096);
        let plan = parse_frame_plan(&input, Limits::default()).unwrap();
        let mut output = vec![1, 2];
        let limits = Limits {
            max_decoded_bytes: 1024,
            max_buffer_bytes: 1024,
            ..Limits::default()
        };

        let err = decode_plan(&input, &plan, &mut output, limits).unwrap_err();

        assert_eq!(err.kind(), ErrorKind::LimitExceeded);
        assert_eq!(output, [1, 2]);
    }

    #[cfg(not(feature = "lz4"))]
    #[test]
    fn rejects_lz4_chunk_when_feature_is_disabled() {
        let input = lz4_serial_frame(&[0], 8);
        let plan = parse_frame_plan(&input, Limits::default()).unwrap();
        let mut output = vec![1, 2];

        let err = decode_plan(&input, &plan, &mut output, Limits::default()).unwrap_err();

        assert_eq!(err.kind(), ErrorKind::Unsupported);
        assert_eq!(output, [1, 2]);
    }

    #[test]
    fn rejects_size_mismatch_without_mutating_destination() {
        let mut input = Vec::new();
        input.extend_from_slice(&magic(21));
        input.push(0);
        input.push(1);
        input.push(5);
        input.push(1);
        input.push(1);
        input.push(3);
        input.extend_from_slice(&[7, 8, 9]);
        input.push(0);
        let plan = parse_frame_plan(&input, Limits::default()).unwrap();
        let mut output = vec![1, 2];

        let err = decode_plan(&input, &plan, &mut output, Limits::default()).unwrap_err();

        assert_eq!(err.kind(), ErrorKind::Malformed);
        assert_eq!(output, [1, 2]);
    }

    #[test]
    fn enforces_expansion_ratio_without_mutating_destination() {
        let mut input = Vec::new();
        input.extend_from_slice(&magic(21));
        input.push(0);
        input.push(1);
        input.push(4);
        input.push(1);
        input.push(1);
        input.push(3);
        input.extend_from_slice(&[7, 8, 9]);
        input.push(0);
        let plan = parse_frame_plan(&input, Limits::default()).unwrap();
        let mut output = vec![1, 2];
        let limits = Limits {
            max_expansion_ratio: 0,
            ..Limits::default()
        };

        let err = decode_plan(&input, &plan, &mut output, limits).unwrap_err();

        assert_eq!(err.kind(), ErrorKind::LimitExceeded);
        assert_eq!(output, [1, 2]);
    }

    #[cfg(feature = "checksum")]
    #[test]
    fn verifies_decoded_checksum() {
        let mut input = Vec::new();
        input.extend_from_slice(&magic(21));
        input.push(1);
        input.push(1);
        input.push(4);
        input.push(1);
        input.push(1);
        input.push(3);
        input.extend_from_slice(&[7, 8, 9]);
        let checksum = (xxhash_rust::xxh3::xxh3_64(&[7, 8, 9]) & 0xffff_ffff) as u32;
        input.extend_from_slice(&checksum.to_le_bytes());
        input.push(0);
        let plan = parse_frame_plan(&input, Limits::default()).unwrap();
        let mut output = Vec::new();

        let written = decode_plan(&input, &plan, &mut output, Limits::default()).unwrap();

        assert_eq!(written, 3);
        assert_eq!(output, [7, 8, 9]);
    }

    #[cfg(feature = "checksum")]
    #[test]
    fn rejects_decoded_checksum_mismatch_without_mutating_destination() {
        let mut input = Vec::new();
        input.extend_from_slice(&magic(21));
        input.push(1);
        input.push(1);
        input.push(4);
        input.push(1);
        input.push(1);
        input.push(3);
        input.extend_from_slice(&[7, 8, 9]);
        input.extend_from_slice(&0u32.to_le_bytes());
        input.push(0);
        let plan = parse_frame_plan(&input, Limits::default()).unwrap();
        let mut output = vec![1, 2];

        let err = decode_plan(&input, &plan, &mut output, Limits::default()).unwrap_err();

        assert_eq!(err.kind(), ErrorKind::ChecksumMismatch);
        assert_eq!(output, [1, 2]);
    }

    #[cfg(feature = "checksum")]
    #[test]
    fn verifies_compressed_checksum() {
        let mut input = Vec::new();
        input.extend_from_slice(&magic(21));
        input.push(1 << 1);
        input.push(1);
        input.push(4);
        let header_checksum = (xxhash_rust::xxh3::xxh3_64(&input) & 0xff) as u8;
        input.push(header_checksum);
        let chunk_start = input.len();
        input.push(1);
        input.push(1);
        input.push(3);
        input.extend_from_slice(&[7, 8, 9]);
        let checksum = (xxhash_rust::xxh3::xxh3_64(&input[chunk_start..]) & 0xffff_ffff) as u32;
        input.extend_from_slice(&checksum.to_le_bytes());
        input.push(0);
        let plan = parse_frame_plan(&input, Limits::default()).unwrap();
        let mut output = Vec::new();

        let written = decode_plan(&input, &plan, &mut output, Limits::default()).unwrap();

        assert_eq!(written, 3);
        assert_eq!(output, [7, 8, 9]);
    }

    #[cfg(feature = "checksum")]
    #[test]
    fn rejects_compressed_checksum_mismatch() {
        let mut input = Vec::new();
        input.extend_from_slice(&magic(21));
        input.push(1 << 1);
        input.push(1);
        input.push(4);
        let header_checksum = (xxhash_rust::xxh3::xxh3_64(&input) & 0xff) as u8;
        input.push(header_checksum);
        input.push(1);
        input.push(1);
        input.push(3);
        input.extend_from_slice(&[7, 8, 9]);
        input.extend_from_slice(&0u32.to_le_bytes());
        input.push(0);

        let err = parse_frame_plan(&input, Limits::default()).unwrap_err();

        assert_eq!(err.kind(), ErrorKind::ChecksumMismatch);
    }

    #[test]
    fn decodes_fse_ncount_node() {
        let distribution = [15, 8, 4, 3, 1, 1];
        let encoded =
            zrip_core::fse::table_builder::serialize_fse_table_description(&distribution, 5);
        let output = decode_fse_ncount_node(
            StreamInput {
                bytes: &encoded,
                element_width: 1,
                string_lengths: None,
            },
            &[],
            Limits::default(),
        )
        .unwrap();

        let decoded = output
            .bytes
            .chunks_exact(2)
            .map(|bytes| i16::from_le_bytes(bytes.try_into().unwrap()))
            .collect::<Vec<_>>();
        assert_eq!(output.element_width, 2);
        assert_eq!(decoded, distribution);
    }

    #[test]
    fn rejects_fse_ncount_trailing_bytes() {
        let distribution = [15, 8, 4, 3, 1, 1];
        let mut encoded =
            zrip_core::fse::table_builder::serialize_fse_table_description(&distribution, 5);
        encoded.push(0);
        let err = decode_fse_ncount_node(
            StreamInput {
                bytes: &encoded,
                element_width: 1,
                string_lengths: None,
            },
            &[],
            Limits::default(),
        )
        .unwrap_err();

        assert_eq!(err.kind(), ErrorKind::Malformed);
    }
}
