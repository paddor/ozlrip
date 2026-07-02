use alloc::{format, vec, vec::Vec};

use ozlrip_core::{Error, ErrorKind, FrameValueType, Limits, Result};

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
    limits: Limits,
    #[cfg(feature = "zstd")] zstd: &mut zrip::DecompressContext,
) -> Result<DecodedChunk<'a>> {
    let plan = build_chunk_execution_plan(chunk)?;
    let mut streams = initialize_stream_slots(input, chunk, &plan.regen_targets)?;
    let transform_headers = chunk.transform_header_range().as_slice(input)?;

    for node in plan.nodes {
        let inputs = collect_node_inputs(&streams, node.input_start, node.input_count)?;
        let header = node_header(transform_headers, node.header_start, node.header_size)?;
        let outputs = execute_standard_node(
            node.standard_id,
            &inputs,
            node.variable_inputs,
            header,
            limits,
            #[cfg(feature = "zstd")]
            zstd,
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

struct ChunkExecutionPlan {
    nodes: Vec<NodeExecutionPlan>,
    regen_targets: Vec<bool>,
}

struct NodeExecutionPlan {
    standard_id: u32,
    input_start: usize,
    input_count: usize,
    output_targets: Vec<usize>,
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
        let mut output_targets = Vec::new();
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
                Error::new(ErrorKind::InvalidGraph)
                    .with_detail("regen stream distance is out of bounds")
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
        standard::SPLITN_ID | standard::TRANSPOSE_SPLIT_ID => 0,
        standard::CONCAT_SERIAL_ID
        | standard::FLATPACK_ID
        | standard::TRANSPOSE_SPLIT2_ID
        | standard::MUX_LENGTHS_ID => 2,
        standard::TRANSPOSE_SPLIT4_ID | standard::LZ_ID => 4,
        standard::FIELD_LZ_ID => 5,
        standard::TRANSPOSE_SPLIT8_ID => 8,
        standard::LZ4_ID
        | standard::ZSTD_ID
        | standard::BITPACK_SERIAL_ID
        | standard::BITPACK_INT_ID
        | standard::CONSTANT_SERIAL_ID
        | standard::CONVERT_NUM_TO_STRUCT_LE_ID
        | standard::CONVERT_SERIAL_TO_NUM_LE_ID
        | standard::CONVERT_NUM_TO_SERIAL_LE_ID
        | standard::CONVERT_SERIAL_TO_STRUCT_ID
        | standard::CONVERT_STRUCT_TO_SERIAL_ID
        | standard::ZIGZAG_ID
        | standard::DELTA_INT_ID
        | standard::BITUNPACK_ID
        | standard::RANGE_PACK_ID => 1,
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
) -> Result<Vec<StreamInput<'a>>> {
    let input_end = input_start
        .checked_add(input_count)
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
    let input_slots = streams.get(input_start..input_end).ok_or_else(|| {
        Error::new(ErrorKind::InvalidGraph).with_detail("node input range is out of bounds")
    })?;
    let mut inputs = Vec::new();
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
    limits: Limits,
    #[cfg(feature = "zstd")] zstd: &mut zrip::DecompressContext,
) -> Result<Vec<OwnedStream>> {
    match standard_id {
        standard::CONCAT_SERIAL_ID => one_serial(decode_concat_serial_node(inputs, header, limits)),
        standard::SPLITN_ID => {
            one_serial(decode_splitn_node(inputs, variable_inputs, header, limits))
        }
        standard::FLATPACK_ID => one_serial(decode_flatpack_node(inputs, header, limits)),
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
        standard::CONVERT_NUM_TO_STRUCT_LE_ID => one_typed(decode_num_to_struct_le_chunk(
            single_stream(inputs)?,
            header,
            limits,
        )),
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
        standard::MUX_LENGTHS_ID => decode_mux_lengths_node(inputs, header, limits),
        standard::LZ_ID => one_serial(decode_lz_node(inputs, header, limits)),
        standard::FIELD_LZ_ID => one_typed(decode_field_lz_node(inputs, header, limits)),
        standard::ZIGZAG_ID => one_serial(decode_zigzag_serial8_chunk(
            single_input(inputs)?,
            header,
            limits,
        )),
        standard::DELTA_INT_ID => one_serial(decode_delta_serial8_chunk(
            single_input(inputs)?,
            header,
            limits,
        )),
        standard::BITUNPACK_ID => one_serial(decode_bitunpack_serial8_chunk(
            single_input(inputs)?,
            header,
            limits,
        )),
        standard::RANGE_PACK_ID => one_serial(decode_range_pack_serial8_chunk(
            single_input(inputs)?,
            header,
            limits,
        )),
        _ => Err(Error::new(ErrorKind::Unsupported)
            .with_detail("standard transform graph execution is not implemented yet")),
    }
}

fn one_serial(result: Result<Vec<u8>>) -> Result<Vec<OwnedStream>> {
    Ok(vec![OwnedStream::serial(result?)])
}

fn one_typed(result: Result<OwnedStream>) -> Result<Vec<OwnedStream>> {
    Ok(vec![result?])
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
            }),
            Self::Owned(stream) => Ok(StreamInput {
                bytes: &stream.bytes,
                element_width: stream.element_width,
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
}

#[derive(Debug)]
struct OwnedStream {
    bytes: Vec<u8>,
    element_width: usize,
}

impl OwnedStream {
    fn serial(bytes: Vec<u8>) -> Self {
        Self {
            bytes,
            element_width: 1,
        }
    }
}

fn decode_concat_serial_node(
    inputs: &[StreamInput<'_>],
    header: &[u8],
    limits: Limits,
) -> Result<Vec<u8>> {
    if !header.is_empty() {
        return Err(Error::new(ErrorKind::Unsupported)
            .with_detail("concat_serial transform headers are unsupported"));
    }
    let [sizes, concatenated] = inputs else {
        return Err(Error::new(ErrorKind::InvalidGraph)
            .with_detail("concat_serial input count does not match node shape"));
    };
    let sizes = sizes.bytes;
    let concatenated = concatenated.bytes;
    if sizes.len() != 4 {
        return Err(
            Error::new(ErrorKind::Malformed).with_detail("concat_serial size table is malformed")
        );
    }
    let decoded_size =
        usize::try_from(u32::from_le_bytes(sizes.try_into().map_err(|_| {
            Error::new(ErrorKind::Malformed).with_detail("invalid concat size")
        })?))
        .map_err(|_| {
            Error::new(ErrorKind::LimitExceeded).with_detail("concat size is too large")
        })?;
    if decoded_size != concatenated.len() {
        return Err(
            Error::new(ErrorKind::Malformed).with_detail("concat_serial size does not match input")
        );
    }
    if decoded_size > limits.max_decoded_bytes || decoded_size > limits.max_buffer_bytes {
        return Err(
            Error::new(ErrorKind::LimitExceeded).with_detail("decoded output limit exceeded")
        );
    }

    let mut output = Vec::new();
    output.try_reserve_exact(decoded_size).map_err(|_| {
        Error::new(ErrorKind::LimitExceeded).with_detail("concat allocation failed")
    })?;
    output.extend_from_slice(concatenated);
    Ok(output)
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
    let input_count = usize::try_from(variable_inputs)
        .map_err(|_| Error::new(ErrorKind::LimitExceeded).with_detail("too many splitn inputs"))?;
    if inputs.len() != input_count {
        return Err(Error::new(ErrorKind::InvalidGraph)
            .with_detail("splitn input count does not match node shape"));
    }
    if input_count == 0 {
        validate_splitn_empty_header(header)?;
        return Ok(Vec::new());
    }
    if !header.is_empty() {
        return Err(
            Error::new(ErrorKind::Unsupported).with_detail("splitn headers are unsupported")
        );
    }

    let mut total_len = 0usize;
    for input in inputs {
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
    Ok(output)
}

fn validate_splitn_empty_header(header: &[u8]) -> Result<()> {
    if header.is_empty() {
        return Ok(());
    }
    let mut offset = 0usize;
    let element_width = read_var_u64(header, &mut offset)?;
    if offset != header.len() {
        return Err(Error::new(ErrorKind::Malformed).with_detail("unexpected splitn header bytes"));
    }
    if element_width != 1 {
        return Err(Error::new(ErrorKind::Unsupported)
            .with_detail("only serial byte splitn output is implemented"));
    }
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
        },
        OwnedStream {
            bytes: match_lengths,
            element_width,
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
        if out_match_end > output.len() {
            return Err(
                Error::new(ErrorKind::Malformed).with_detail("lz match length exceeds output size")
            );
        }
        for index in 0..match_len {
            let value = output[out_pos + index - match_offset];
            output[out_pos + index] = value;
        }
        out_pos = out_match_end;
    }

    let remaining_literals = literals.bytes.get(lit_pos..).ok_or_else(|| {
        Error::new(ErrorKind::Malformed).with_detail("lz literal stream is too short")
    })?;
    let out_end = out_pos
        .checked_add(remaining_literals.len())
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
    if out_end != output.len() {
        return Err(
            Error::new(ErrorKind::Malformed).with_detail("lz output size does not match header")
        );
    }
    output[out_pos..].copy_from_slice(remaining_literals);
    Ok(output)
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

fn read_usize_numeric_element(bytes: &[u8], element_width: usize, index: usize) -> Result<usize> {
    usize::try_from(read_numeric_element(bytes, element_width, index)?)
        .map_err(|_| Error::new(ErrorKind::LimitExceeded).with_detail("numeric value is too large"))
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
        let token = read_numeric_element(tokens.bytes, 2, token_index)?;
        let offset_code =
            usize::try_from(token & 0x3).map_err(|_| Error::new(ErrorKind::IntegerOverflow))?;
        let literal_code = usize::try_from((token >> 2) & 0x0f)
            .map_err(|_| Error::new(ErrorKind::IntegerOverflow))?;
        let match_code = usize::try_from((token >> 6) & 0x0f)
            .map_err(|_| Error::new(ErrorKind::IntegerOverflow))?;

        let match_offset = match offset_code {
            3 => {
                let raw_offset = read_usize_numeric_element(offsets.bytes, 4, offset_pos)?;
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
                .checked_add(read_usize_numeric_element(
                    extra_literal_lengths.bytes,
                    4,
                    extra_literal_pos,
                )?)
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
                .checked_add(read_usize_numeric_element(
                    extra_match_lengths.bytes,
                    4,
                    extra_match_pos,
                )?)
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
    for index in 0..match_len {
        let value = output[start + index - match_offset];
        output[start + index] = value;
    }
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
    let mask = if bits == 128 {
        u128::MAX
    } else {
        (1u128 << bits) - 1
    };
    for (index, out) in output.chunks_exact_mut(element_width).enumerate() {
        let bit_offset = index
            .checked_mul(bits)
            .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
        let value = read_packed_value(stored, bit_offset, bits, mask)?;
        out.copy_from_slice(&value.to_le_bytes()[..element_width]);
    }
    Ok(())
}

fn read_packed_value(stored: &[u8], bit_offset: usize, bits: usize, mask: u128) -> Result<u128> {
    let byte_offset = bit_offset / 8;
    let bit_shift = bit_offset % 8;
    let lane_bytes = bit_shift
        .checked_add(bits)
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?
        .div_ceil(8);
    let mut lane = 0u128;
    for byte_index in 0..lane_bytes {
        let byte = stored.get(byte_offset + byte_index).ok_or_else(|| {
            Error::new(ErrorKind::Malformed).with_detail("bitpack input is truncated")
        })?;
        lane |= u128::from(*byte) << (byte_index * 8);
    }
    Ok((lane >> bit_shift) & mask)
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
    })
}

fn decode_zigzag_serial8_chunk(stored: &[u8], header: &[u8], limits: Limits) -> Result<Vec<u8>> {
    if !header.is_empty() {
        return Err(Error::new(ErrorKind::Unsupported)
            .with_detail("zigzag transform headers are unsupported"));
    }
    if stored.len() > limits.max_decoded_bytes || stored.len() > limits.max_buffer_bytes {
        return Err(
            Error::new(ErrorKind::LimitExceeded).with_detail("decoded output limit exceeded")
        );
    }
    let mut output = Vec::new();
    output.try_reserve_exact(stored.len()).map_err(|_| {
        Error::new(ErrorKind::LimitExceeded).with_detail("zigzag allocation failed")
    })?;
    for &encoded in stored {
        let mask = 0u8.wrapping_sub(encoded & 1);
        output.push((encoded >> 1) ^ mask);
    }
    Ok(output)
}

fn decode_delta_serial8_chunk(stored: &[u8], header: &[u8], limits: Limits) -> Result<Vec<u8>> {
    let output_len = match header.len() {
        0 if stored.is_empty() => 0,
        0 => {
            return Err(
                Error::new(ErrorKind::Malformed).with_detail("delta stream has no first value")
            );
        }
        1 => stored.len().checked_add(1).ok_or_else(|| {
            Error::new(ErrorKind::IntegerOverflow).with_detail("delta size overflowed")
        })?,
        _ => {
            return Err(
                Error::new(ErrorKind::Malformed).with_detail("delta header must contain one byte")
            );
        }
    };
    if output_len > limits.max_decoded_bytes || output_len > limits.max_buffer_bytes {
        return Err(
            Error::new(ErrorKind::LimitExceeded).with_detail("decoded output limit exceeded")
        );
    }
    let mut output = Vec::new();
    output
        .try_reserve_exact(output_len)
        .map_err(|_| Error::new(ErrorKind::LimitExceeded).with_detail("delta allocation failed"))?;
    if output_len == 0 {
        return Ok(output);
    }
    output.push(header[0]);
    for &delta in stored {
        let previous = *output
            .last()
            .ok_or_else(|| Error::new(ErrorKind::Malformed).with_detail("missing delta base"))?;
        output.push(previous.wrapping_add(delta));
    }
    Ok(output)
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
            standard::BITUNPACK_ID,
            standard::CONCAT_SERIAL_ID,
            standard::CONSTANT_SERIAL_ID,
            standard::CONVERT_NUM_TO_SERIAL_LE_ID,
            standard::CONVERT_NUM_TO_STRUCT_LE_ID,
            standard::CONVERT_SERIAL_TO_NUM_LE_ID,
            standard::CONVERT_SERIAL_TO_STRUCT_ID,
            standard::CONVERT_STRUCT_TO_SERIAL_ID,
            standard::DELTA_INT_ID,
            standard::FIELD_LZ_ID,
            standard::FLATPACK_ID,
            standard::LZ_ID,
            standard::MUX_LENGTHS_ID,
            standard::RANGE_PACK_ID,
            standard::SPLITN_ID,
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
            standard::BITUNPACK_ID,
            standard::CONCAT_SERIAL_ID,
            standard::CONSTANT_SERIAL_ID,
            standard::CONVERT_NUM_TO_SERIAL_LE_ID,
            standard::CONVERT_NUM_TO_STRUCT_LE_ID,
            standard::CONVERT_SERIAL_TO_NUM_LE_ID,
            standard::CONVERT_SERIAL_TO_STRUCT_ID,
            standard::CONVERT_STRUCT_TO_SERIAL_ID,
            standard::DELTA_INT_ID,
            standard::FIELD_LZ_ID,
            standard::FLATPACK_ID,
            standard::LZ_ID,
            standard::MUX_LENGTHS_ID,
            standard::RANGE_PACK_ID,
            standard::SPLITN_ID,
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
                },
                StreamInput {
                    bytes: &long,
                    element_width: 2,
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
                },
                StreamInput {
                    bytes: &long,
                    element_width: 2,
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
                },
                StreamInput {
                    bytes: &long,
                    element_width: 2,
                },
            ],
            &[0x24],
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
                },
                StreamInput {
                    bytes: &offsets,
                    element_width: 2,
                },
                StreamInput {
                    bytes: &literal_lengths,
                    element_width: 2,
                },
                StreamInput {
                    bytes: &match_lengths,
                    element_width: 2,
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
                },
                StreamInput {
                    bytes: &offsets,
                    element_width: 2,
                },
                StreamInput {
                    bytes: &literal_lengths,
                    element_width: 2,
                },
                StreamInput {
                    bytes: &match_lengths,
                    element_width: 2,
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
                },
                StreamInput {
                    bytes: &[],
                    element_width: 2,
                },
                StreamInput {
                    bytes: &[],
                    element_width: 4,
                },
                StreamInput {
                    bytes: &[],
                    element_width: 4,
                },
                StreamInput {
                    bytes: &[],
                    element_width: 4,
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
                },
                StreamInput {
                    bytes: &token.to_le_bytes(),
                    element_width: 2,
                },
                StreamInput {
                    bytes: &offset,
                    element_width: 4,
                },
                StreamInput {
                    bytes: &[],
                    element_width: 4,
                },
                StreamInput {
                    bytes: &[],
                    element_width: 4,
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
}
