use alloc::vec::Vec;

use ozlrip_core::{Error, ErrorKind, FrameValueType, Limits, Result};

use crate::{parse::FramePlan, standard};

#[cfg(test)]
pub(crate) fn decode_plan(
    input: &[u8],
    plan: &FramePlan,
    dst: &mut Vec<u8>,
    limits: Limits,
) -> Result<usize> {
    let mut scratch = Vec::new();
    decode_plan_with_scratch(input, plan, dst, &mut scratch, limits)
}

pub(crate) fn decode_plan_with_scratch(
    input: &[u8],
    plan: &FramePlan,
    dst: &mut Vec<u8>,
    scratch: &mut Vec<u8>,
    limits: Limits,
) -> Result<usize> {
    if plan.info.dictionary_bundle_id.is_some() {
        return Err(Error::new(ErrorKind::Unsupported)
            .with_detail("dictionary bundle materialization is not implemented"));
    }
    let decoded = collect_decoded_output(input, plan, limits)?;
    scratch.clear();
    scratch.try_reserve_exact(decoded.total_len).map_err(|_| {
        Error::new(ErrorKind::LimitExceeded).with_detail("output allocation failed")
    })?;
    for chunk in decoded.chunks {
        scratch.extend_from_slice(chunk.as_slice());
    }
    dst.try_reserve_exact(decoded.total_len).map_err(|_| {
        Error::new(ErrorKind::LimitExceeded).with_detail("output allocation failed")
    })?;
    dst.extend_from_slice(scratch);
    Ok(decoded.total_len)
}

fn collect_decoded_output<'a>(
    input: &'a [u8],
    plan: &FramePlan,
    limits: Limits,
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
            decode_simple_transform_chunk(input, chunk, limits)?
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

fn decode_simple_transform_chunk(
    input: &[u8],
    chunk: &crate::parse::ChunkPlan,
    limits: Limits,
) -> Result<DecodedChunk<'static>> {
    let Some(node) = chunk.single_node() else {
        return Err(Error::new(ErrorKind::Unsupported)
            .with_detail("only single-node transform chunks are implemented"));
    };
    if node.standard_id() == Some(standard::CONCAT_SERIAL_ID) {
        return decode_concat_serial_chunk(input, chunk, node, limits).map(DecodedChunk::Owned);
    }
    if node.standard_id() == Some(standard::SPLITN_ID) {
        return decode_splitn_chunk(input, chunk, node, limits).map(DecodedChunk::Owned);
    }
    if node.standard_id() == Some(standard::FLATPACK_ID) {
        return decode_flatpack_chunk(input, chunk, node, limits).map(DecodedChunk::Owned);
    }
    if let Some(width) = transpose_split_width(node.standard_id()) {
        return decode_transpose_split_chunk(input, chunk, node, width, limits)
            .map(DecodedChunk::Owned);
    }
    if node.variable_outputs() != 0 || node.regen_distances() != [0] {
        return Err(Error::new(ErrorKind::Unsupported)
            .with_detail("only single-input single-output transform chunks are implemented"));
    }
    if chunk.stored_stream_range(1).is_some() {
        return Err(Error::new(ErrorKind::Unsupported)
            .with_detail("transform chunk contains multiple stored streams"));
    }
    let Some(stored_range) = chunk.stored_stream_range(0) else {
        return Err(Error::new(ErrorKind::Unsupported)
            .with_detail("transform chunk does not contain one stored stream"));
    };
    let stored = stored_range.as_slice(input)?;
    let header = chunk.transform_header_range().as_slice(input)?;
    match node.standard_id() {
        Some(standard::LZ4_ID) => decode_lz4_chunk(stored, header, limits).map(DecodedChunk::Owned),
        Some(standard::ZSTD_ID) => {
            decode_zstd_chunk(stored, header, limits).map(DecodedChunk::Owned)
        }
        Some(standard::BITPACK_SERIAL_ID) => {
            decode_bitpack_serial_chunk(stored, header, limits).map(DecodedChunk::Owned)
        }
        Some(standard::CONSTANT_SERIAL_ID) => {
            decode_constant_serial_chunk(stored, header, limits).map(DecodedChunk::Owned)
        }
        Some(standard::CONVERT_SERIAL_TO_STRUCT_ID) => {
            decode_convert_serial_to_struct_chunk(stored, header, limits).map(DecodedChunk::Owned)
        }
        Some(standard::ZIGZAG_ID) => {
            decode_zigzag_serial8_chunk(stored, header, limits).map(DecodedChunk::Owned)
        }
        Some(standard::DELTA_INT_ID) => {
            decode_delta_serial8_chunk(stored, header, limits).map(DecodedChunk::Owned)
        }
        Some(standard::BITUNPACK_ID) => {
            decode_bitunpack_serial8_chunk(stored, header, limits).map(DecodedChunk::Owned)
        }
        Some(standard::RANGE_PACK_ID) => {
            decode_range_pack_serial8_chunk(stored, header, limits).map(DecodedChunk::Owned)
        }
        _ => Err(Error::new(ErrorKind::Unsupported)
            .with_detail("transform graph execution is not implemented yet")),
    }
}

fn decode_concat_serial_chunk(
    input: &[u8],
    chunk: &crate::parse::ChunkPlan,
    node: &crate::parse::NodePlan,
    limits: Limits,
) -> Result<Vec<u8>> {
    if chunk.transform_header_range().len() != 0 {
        return Err(Error::new(ErrorKind::Unsupported)
            .with_detail("concat_serial transform headers are unsupported"));
    }
    if node.regen_distances() != [0] {
        return Err(Error::new(ErrorKind::Unsupported)
            .with_detail("only single-output concat_serial chunks are implemented"));
    }
    if node.variable_outputs() != 0 {
        return Err(Error::new(ErrorKind::Unsupported)
            .with_detail("variable concat_serial outputs are unsupported"));
    }
    if chunk.stored_streams() != 2 {
        return Err(Error::new(ErrorKind::InvalidGraph)
            .with_detail("concat_serial input count does not match stored streams"));
    }

    let sizes_range = chunk
        .stored_stream_range(0)
        .ok_or_else(|| Error::new(ErrorKind::InvalidGraph).with_detail("missing concat sizes"))?;
    let concatenated_range = chunk
        .stored_stream_range(1)
        .ok_or_else(|| Error::new(ErrorKind::InvalidGraph).with_detail("missing concat input"))?;
    let sizes = sizes_range.as_slice(input)?;
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
    if decoded_size != concatenated_range.len() {
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
    output.extend_from_slice(concatenated_range.as_slice(input)?);
    Ok(output)
}

fn transpose_split_width(id: Option<u32>) -> Option<usize> {
    match id {
        Some(standard::TRANSPOSE_SPLIT2_ID) => Some(2),
        Some(standard::TRANSPOSE_SPLIT4_ID) => Some(4),
        Some(standard::TRANSPOSE_SPLIT8_ID) => Some(8),
        _ => None,
    }
}

fn decode_transpose_split_chunk(
    input: &[u8],
    chunk: &crate::parse::ChunkPlan,
    node: &crate::parse::NodePlan,
    width: usize,
    limits: Limits,
) -> Result<Vec<u8>> {
    if node.variable_outputs() != 0 || node.regen_distances() != [0] {
        return Err(Error::new(ErrorKind::Unsupported)
            .with_detail("only single-output transpose_split chunks are implemented"));
    }
    if chunk.transform_header_range().len() != 0 {
        return Err(Error::new(ErrorKind::Unsupported)
            .with_detail("transpose_split transform headers are unsupported"));
    }
    if chunk.stored_streams() != width {
        return Err(Error::new(ErrorKind::InvalidGraph)
            .with_detail("transpose_split input count does not match width"));
    }
    let first = chunk.stored_stream_range(0).ok_or_else(|| {
        Error::new(ErrorKind::InvalidGraph).with_detail("missing transpose input")
    })?;
    let lane_len = first.len();
    let output_len = lane_len.checked_mul(width).ok_or_else(|| {
        Error::new(ErrorKind::IntegerOverflow).with_detail("transpose size overflowed")
    })?;
    if output_len > limits.max_decoded_bytes || output_len > limits.max_buffer_bytes {
        return Err(
            Error::new(ErrorKind::LimitExceeded).with_detail("decoded output limit exceeded")
        );
    }
    let mut lanes = Vec::new();
    lanes
        .try_reserve_exact(width)
        .map_err(|_| Error::new(ErrorKind::LimitExceeded).with_detail("lane allocation failed"))?;
    for index in 0..width {
        let lane = chunk
            .stored_stream_range(index)
            .ok_or_else(|| {
                Error::new(ErrorKind::InvalidGraph).with_detail("missing transpose input")
            })?
            .as_slice(input)?;
        if lane.len() != lane_len {
            return Err(Error::new(ErrorKind::Malformed)
                .with_detail("transpose_split lanes have different sizes"));
        }
        lanes.push(lane);
    }
    let mut output = Vec::new();
    output.try_reserve_exact(output_len).map_err(|_| {
        Error::new(ErrorKind::LimitExceeded).with_detail("transpose allocation failed")
    })?;
    for element in 0..lane_len {
        for lane in &lanes {
            output.push(lane[element]);
        }
    }
    Ok(output)
}

fn decode_flatpack_chunk(
    input: &[u8],
    chunk: &crate::parse::ChunkPlan,
    node: &crate::parse::NodePlan,
    limits: Limits,
) -> Result<Vec<u8>> {
    if node.variable_outputs() != 0 || node.regen_distances() != [0] {
        return Err(Error::new(ErrorKind::Unsupported)
            .with_detail("only single-output flatpack chunks are implemented"));
    }
    if chunk.transform_header_range().len() != 0 {
        return Err(Error::new(ErrorKind::Unsupported)
            .with_detail("flatpack transform headers are unsupported"));
    }
    if chunk.stored_streams() != 2 {
        return Err(Error::new(ErrorKind::InvalidGraph)
            .with_detail("flatpack input count does not match stored streams"));
    }
    let alphabet = chunk
        .stored_stream_range(0)
        .ok_or_else(|| {
            Error::new(ErrorKind::InvalidGraph).with_detail("missing flatpack alphabet")
        })?
        .as_slice(input)?;
    let packed = chunk
        .stored_stream_range(1)
        .ok_or_else(|| Error::new(ErrorKind::InvalidGraph).with_detail("missing flatpack input"))?
        .as_slice(input)?;
    decode_flatpack_serial(alphabet, packed, limits)
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

fn decode_splitn_chunk(
    input: &[u8],
    chunk: &crate::parse::ChunkPlan,
    node: &crate::parse::NodePlan,
    limits: Limits,
) -> Result<Vec<u8>> {
    if node.regen_distances() != [0] {
        return Err(Error::new(ErrorKind::Unsupported)
            .with_detail("only single-output splitn chunks are implemented"));
    }
    let input_count = usize::try_from(node.variable_outputs())
        .map_err(|_| Error::new(ErrorKind::LimitExceeded).with_detail("too many splitn inputs"))?;
    if chunk.stored_streams() != input_count {
        return Err(Error::new(ErrorKind::InvalidGraph)
            .with_detail("splitn input count does not match stored streams"));
    }
    let header = chunk.transform_header_range().as_slice(input)?;
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
    for index in 0..input_count {
        let range = chunk.stored_stream_range(index).ok_or_else(|| {
            Error::new(ErrorKind::InvalidGraph).with_detail("missing splitn input")
        })?;
        total_len = total_len.checked_add(range.len()).ok_or_else(|| {
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
    for index in 0..input_count {
        let range = chunk.stored_stream_range(index).ok_or_else(|| {
            Error::new(ErrorKind::InvalidGraph).with_detail("missing splitn input")
        })?;
        output.extend_from_slice(range.as_slice(input)?);
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

fn decode_bitpack_serial_chunk(stored: &[u8], header: &[u8], limits: Limits) -> Result<Vec<u8>> {
    let parsed = parse_bitpack_serial_header(header, stored.len())?;
    if parsed.output_len > limits.max_decoded_bytes || parsed.output_len > limits.max_buffer_bytes {
        return Err(
            Error::new(ErrorKind::LimitExceeded).with_detail("decoded output limit exceeded")
        );
    }
    let mut output = Vec::new();
    output.try_reserve_exact(parsed.output_len).map_err(|_| {
        Error::new(ErrorKind::LimitExceeded).with_detail("bitpack allocation failed")
    })?;
    output.resize(parsed.output_len, 0);
    unpack_lsb_bits(stored, parsed.bits, &mut output)?;
    Ok(output)
}

struct BitpackHeader {
    bits: usize,
    output_len: usize,
}

fn parse_bitpack_serial_header(header: &[u8], packed_len: usize) -> Result<BitpackHeader> {
    if header.is_empty() || header.len() > 2 {
        return Err(Error::new(ErrorKind::Malformed).with_detail("bitpack header is malformed"));
    }
    let element_width = 1usize
        .checked_shl(u32::from((header[0] >> 6) & 0x3))
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
    if element_width != 1 {
        return Err(Error::new(ErrorKind::Unsupported)
            .with_detail("only serial byte bitpack output is implemented"));
    }
    let bits = usize::from(header[0] & 0x3f)
        .checked_add(1)
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
    if bits > 8 {
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
        bits,
        output_len: max_elements - extra,
    })
}

fn unpack_lsb_bits(stored: &[u8], bits: usize, output: &mut [u8]) -> Result<()> {
    let mask = if bits == 8 {
        u16::from(u8::MAX)
    } else {
        (1u16 << bits) - 1
    };
    for (index, out) in output.iter_mut().enumerate() {
        let bit_offset = index
            .checked_mul(bits)
            .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
        let byte_offset = bit_offset / 8;
        let bit_shift = bit_offset % 8;
        let mut lane = u16::from(*stored.get(byte_offset).ok_or_else(|| {
            Error::new(ErrorKind::Malformed).with_detail("bitpack input is truncated")
        })?);
        if bit_shift + bits > 8 {
            lane |= u16::from(*stored.get(byte_offset + 1).ok_or_else(|| {
                Error::new(ErrorKind::Malformed).with_detail("bitpack input is truncated")
            })?) << 8;
        }
        *out = u8::try_from((lane >> bit_shift) & mask)
            .map_err(|_| Error::new(ErrorKind::IntegerOverflow))?;
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

fn decode_convert_serial_to_struct_chunk(
    stored: &[u8],
    header: &[u8],
    limits: Limits,
) -> Result<Vec<u8>> {
    if !header.is_empty() {
        return Err(Error::new(ErrorKind::Unsupported)
            .with_detail("convert_serial_to_struct headers are unsupported"));
    }
    if stored.len() > limits.max_decoded_bytes || stored.len() > limits.max_buffer_bytes {
        return Err(
            Error::new(ErrorKind::LimitExceeded).with_detail("decoded output limit exceeded")
        );
    }
    let mut output = Vec::new();
    output.try_reserve_exact(stored.len()).map_err(|_| {
        Error::new(ErrorKind::LimitExceeded).with_detail("conversion allocation failed")
    })?;
    output.extend_from_slice(stored);
    Ok(output)
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
fn decode_zstd_chunk(stored: &[u8], header: &[u8], limits: Limits) -> Result<Vec<u8>> {
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
    let mut frame = Vec::new();
    frame
        .try_reserve_exact(4usize.checked_add(magicless.len()).ok_or_else(|| {
            Error::new(ErrorKind::IntegerOverflow).with_detail("zstd frame size overflowed")
        })?)
        .map_err(|_| {
            Error::new(ErrorKind::LimitExceeded).with_detail("zstd frame allocation failed")
        })?;
    frame.extend_from_slice(&0xfd2f_b528u32.to_le_bytes());
    frame.extend_from_slice(magicless);
    let output = zrip::decompress_with_limit(&frame, limits.max_decoded_bytes).map_err(|err| {
        if err == zrip::DecompressError::OutputTooSmall {
            Error::new(ErrorKind::LimitExceeded).with_detail("decoded output limit exceeded")
        } else {
            Error::new(ErrorKind::Malformed).with_detail("OpenZL zstd frame failed")
        }
    })?;
    if output.len() > limits.max_buffer_bytes {
        return Err(
            Error::new(ErrorKind::LimitExceeded).with_detail("decoded output limit exceeded")
        );
    }
    Ok(output)
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
        input.push(4);
        push_var_u64(&mut input, u64::try_from(payload.len()).unwrap());
        input.extend_from_slice(&size_stream);
        input.extend_from_slice(payload);
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
        for stream in streams {
            push_var_u64(&mut input, u64::try_from(stream.len()).unwrap());
        }
        for stream in streams {
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
        push_var_u64(&mut input, u64::try_from(alphabet.len()).unwrap());
        push_var_u64(&mut input, u64::try_from(packed.len()).unwrap());
        input.extend_from_slice(alphabet);
        input.extend_from_slice(&packed);
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
        for lane in lanes {
            push_var_u64(&mut input, u64::try_from(lane.len()).unwrap());
        }
        for lane in lanes {
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
        let bits = usize::from(bits);
        let packed_len = (values.len() * bits).div_ceil(8);
        let mut output = vec![0; packed_len];
        let mask = if bits == 8 {
            u16::from(u8::MAX)
        } else {
            (1u16 << bits) - 1
        };
        for (index, &value) in values.iter().enumerate() {
            let bit_offset = index * bits;
            let byte_offset = bit_offset / 8;
            let bit_shift = bit_offset % 8;
            let lane = (u16::from(value) & mask) << bit_shift;
            let lane_bytes = lane.to_le_bytes();
            output[byte_offset] |= lane_bytes[0];
            if bit_shift + bits > 8 {
                output[byte_offset + 1] |= lane_bytes[1];
            }
        }
        output
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
