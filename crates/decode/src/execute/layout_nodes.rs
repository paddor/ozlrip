use alloc::{vec, vec::Vec};

use crate::standard;
use ozlrip_core::{Error, ErrorKind, Limits, Result};

use super::DecodeScratch;
use super::numeric::{
    max_numeric_value, numeric_element_count, read_numeric_element, read_u32_element,
    read_usize_numeric_element, read_var_u64, validate_numeric_stream_width, write_numeric_element,
};
use super::streams::{OwnedStream, StreamInput};
use super::{fast_split_struct, fast_tokenize, fast_transpose};

pub(super) fn decode_concat_node(
    inputs: &[StreamInput<'_>],
    header: &[u8],
    expected_outputs: usize,
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
    let output_count = concat_output_count(sizes, expected_outputs)?;
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
            recyclable: false,
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

pub(super) fn concat_size_count(sizes: &StreamInput<'_>) -> Result<usize> {
    match sizes.element_width {
        1 | 4 => numeric_element_count(sizes.bytes, 4),
        _ => {
            Err(Error::new(ErrorKind::InvalidType).with_detail("concat sizes width is unsupported"))
        }
    }
}

/// Checks the size table against the graph before any per-output allocation,
/// so a large table cannot reserve outputs the graph does not have.
pub(super) fn concat_output_count(
    sizes: &StreamInput<'_>,
    expected_outputs: usize,
) -> Result<usize> {
    let output_count = concat_size_count(sizes)?;
    if output_count == 0 {
        return Err(Error::new(ErrorKind::Malformed).with_detail("concat size table is empty"));
    }
    if output_count != expected_outputs {
        return Err(Error::new(ErrorKind::InvalidGraph)
            .with_detail("node output count does not match graph"));
    }
    Ok(output_count)
}

pub(super) fn read_concat_size(sizes: &StreamInput<'_>, index: usize) -> Result<usize> {
    match sizes.element_width {
        1 | 4 => read_usize_numeric_element(sizes.bytes, 4, index),
        _ => {
            Err(Error::new(ErrorKind::InvalidType).with_detail("concat sizes width is unsupported"))
        }
    }
}

pub(super) fn is_transpose_split(id: u32) -> bool {
    id == standard::TRANSPOSE_SPLIT_ID || transpose_split_width(Some(id)).is_some()
}

pub(super) fn transpose_split_width(id: Option<u32>) -> Option<usize> {
    match id {
        Some(standard::TRANSPOSE_SPLIT2_ID) => Some(2),
        Some(standard::TRANSPOSE_SPLIT4_ID) => Some(4),
        Some(standard::TRANSPOSE_SPLIT8_ID) => Some(8),
        _ => None,
    }
}

pub(super) fn decode_transpose_node(
    source: StreamInput<'_>,
    header: &[u8],
    limits: Limits,
    scratch: &mut DecodeScratch,
) -> Result<OwnedStream> {
    if !header.is_empty() {
        return Err(Error::new(ErrorKind::Unsupported)
            .with_detail("transpose transform headers are unsupported"));
    }
    let source_width = source.element_width;
    if source_width == 0 || !source.bytes.len().is_multiple_of(source_width) {
        return Err(Error::new(ErrorKind::Malformed)
            .with_detail("transpose input size is not a multiple of width"));
    }
    let output_len = source.bytes.len();
    if output_len > limits.max_decoded_bytes || output_len > limits.max_buffer_bytes {
        return Err(
            Error::new(ErrorKind::LimitExceeded).with_detail("decoded output limit exceeded")
        );
    }

    let source_elements = source.bytes.len() / source_width;
    let output_width = if source_elements == 0 {
        source_width
    } else {
        source_elements
    };
    let mut output = scratch.take_byte_buffer(output_len, "transpose allocation failed")?;
    output.resize(output_len, 0);
    for output_element in 0..source_width {
        for output_byte in 0..source_elements {
            output[output_element * output_width + output_byte] =
                source.bytes[output_byte * source_width + output_element];
        }
    }
    Ok(OwnedStream::pooled(output, output_width))
}

pub(super) fn decode_transpose_split_node(
    inputs: &[StreamInput<'_>],
    variable_inputs: u32,
    header: &[u8],
    limits: Limits,
    scratch: &mut DecodeScratch,
) -> Result<OwnedStream> {
    if !header.is_empty() {
        return Err(Error::new(ErrorKind::Unsupported)
            .with_detail("transpose_split transform headers are unsupported"));
    }
    if variable_inputs != 0
        && usize::try_from(variable_inputs).is_ok_and(|count| count != inputs.len())
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
    let mut output = scratch.take_byte_buffer(output_len, "transpose allocation failed")?;
    fast_transpose::write_transpose_split_output(inputs, output_len, &mut output);
    Ok(OwnedStream::pooled(output, width))
}

pub(super) fn decode_flatpack_node(
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

#[derive(Clone, Copy)]
pub(super) enum FloatDeconstructType {
    Float32,
    BFloat16,
    Float16,
}

impl FloatDeconstructType {
    pub(super) const fn sign_frac_width(self) -> usize {
        match self {
            Self::Float32 => 3,
            Self::BFloat16 => 1,
            Self::Float16 => 2,
        }
    }

    pub(super) const fn output_width(self) -> usize {
        match self {
            Self::Float32 => 4,
            Self::BFloat16 | Self::Float16 => 2,
        }
    }
}

pub(super) fn decode_float_deconstruct_node(
    inputs: &[StreamInput<'_>],
    header: &[u8],
    format_version: u32,
    limits: Limits,
) -> Result<OwnedStream> {
    let [sign_frac, exponent] = inputs else {
        return Err(Error::new(ErrorKind::InvalidGraph)
            .with_detail("float_deconstruct input count does not match node shape"));
    };
    if sign_frac.string_lengths.is_some() || exponent.string_lengths.is_some() {
        return Err(Error::new(ErrorKind::InvalidType)
            .with_detail("float_deconstruct inputs must not be string streams"));
    }

    let element_type = parse_float_deconstruct_header(header, format_version)?;
    if sign_frac.element_width != element_type.sign_frac_width() {
        return Err(Error::new(ErrorKind::InvalidType)
            .with_detail("float_deconstruct signfrac width does not match element type"));
    }
    if exponent.element_width != 1 {
        return Err(Error::new(ErrorKind::InvalidType)
            .with_detail("float_deconstruct exponent width must be 1"));
    }

    let elements = numeric_element_count(exponent.bytes, exponent.element_width)?;
    if numeric_element_count(sign_frac.bytes, sign_frac.element_width)? != elements {
        return Err(Error::new(ErrorKind::Malformed)
            .with_detail("float_deconstruct streams have different element counts"));
    }
    let output_width = element_type.output_width();
    let output_len = elements
        .checked_mul(output_width)
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
    if output_len > limits.max_decoded_bytes || output_len > limits.max_buffer_bytes {
        return Err(
            Error::new(ErrorKind::LimitExceeded).with_detail("decoded output limit exceeded")
        );
    }

    let mut output = Vec::new();
    output.try_reserve_exact(output_len).map_err(|_| {
        Error::new(ErrorKind::LimitExceeded).with_detail("float_deconstruct allocation failed")
    })?;
    match element_type {
        FloatDeconstructType::Float32 => {
            decode_float32_deconstruct(sign_frac.bytes, exponent.bytes, &mut output);
        }
        FloatDeconstructType::BFloat16 => {
            decode_bfloat16_deconstruct(sign_frac.bytes, exponent.bytes, &mut output);
        }
        FloatDeconstructType::Float16 => {
            decode_float16_deconstruct(sign_frac.bytes, exponent.bytes, &mut output)?;
        }
    }

    Ok(OwnedStream::typed(output, output_width))
}

pub(super) fn parse_float_deconstruct_header(
    header: &[u8],
    format_version: u32,
) -> Result<FloatDeconstructType> {
    if format_version < 5 {
        if !header.is_empty() {
            return Err(Error::new(ErrorKind::Malformed)
                .with_detail("float_deconstruct v4 header must be empty"));
        }
        return Ok(FloatDeconstructType::Float32);
    }

    let [element_type] = header else {
        return Err(
            Error::new(ErrorKind::Malformed).with_detail("float_deconstruct header is malformed")
        );
    };
    match *element_type {
        0 => Ok(FloatDeconstructType::Float32),
        1 => Ok(FloatDeconstructType::BFloat16),
        2 => Ok(FloatDeconstructType::Float16),
        _ => Err(Error::new(ErrorKind::Malformed)
            .with_detail("float_deconstruct element type is invalid")),
    }
}

pub(super) fn decode_float32_deconstruct(sign_frac: &[u8], exponent: &[u8], output: &mut Vec<u8>) {
    for (sf, &exp) in sign_frac.as_chunks::<3>().0.iter().zip(exponent) {
        let sf = u32::from(sf[0]) | (u32::from(sf[1]) << 8) | (u32::from(sf[2]) << 16);
        let bits = (u32::from(exp) << 23) | ((sf & 1) << 31) | (sf >> 1);
        output.extend_from_slice(&bits.to_le_bytes());
    }
}

pub(super) fn decode_bfloat16_deconstruct(sign_frac: &[u8], exponent: &[u8], output: &mut Vec<u8>) {
    for (&sf, &exp) in sign_frac.iter().zip(exponent) {
        let bits = (u16::from(sf & 1) << 15) | (u16::from(exp) << 7) | u16::from(sf >> 1);
        output.extend_from_slice(&bits.to_le_bytes());
    }
}

pub(super) fn decode_float16_deconstruct(
    sign_frac: &[u8],
    exponent: &[u8],
    output: &mut Vec<u8>,
) -> Result<()> {
    for (sf, &exp) in sign_frac.as_chunks::<2>().0.iter().zip(exponent) {
        let sf = u16::from_le_bytes(*sf);
        if sf & !0x07ff != 0 || exp & !0x1f != 0 {
            return Err(Error::new(ErrorKind::Malformed)
                .with_detail("float16_deconstruct unused bits must be zero"));
        }
        let bits = ((sf & 1) << 15) | (u16::from(exp) << 10) | (sf >> 1);
        output.extend_from_slice(&bits.to_le_bytes());
    }
    Ok(())
}

pub(super) fn decode_merge_sorted_node(
    inputs: &[StreamInput<'_>],
    header: &[u8],
    limits: Limits,
) -> Result<OwnedStream> {
    let [bitset, merged] = inputs else {
        return Err(Error::new(ErrorKind::InvalidGraph)
            .with_detail("merge_sorted input count does not match node shape"));
    };
    if bitset.string_lengths.is_some() || merged.string_lengths.is_some() {
        return Err(Error::new(ErrorKind::InvalidType)
            .with_detail("merge_sorted inputs must not be string streams"));
    }
    validate_numeric_stream_width(bitset.element_width, "merge_sorted bitset")?;
    if merged.element_width != 4 {
        return Err(Error::new(ErrorKind::InvalidType)
            .with_detail("merge_sorted merged stream width must be 4"));
    }

    let merged_elements = numeric_element_count(merged.bytes, merged.element_width)?;
    if numeric_element_count(bitset.bytes, bitset.element_width)? != merged_elements {
        return Err(Error::new(ErrorKind::Malformed)
            .with_detail("merge_sorted streams have different element counts"));
    }

    let sizes = read_merge_sorted_sizes(header)?;
    let max_runs = bitset
        .element_width
        .checked_mul(8)
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
    if sizes.len() > max_runs {
        return Err(Error::new(ErrorKind::Malformed)
            .with_detail("merge_sorted has too many output runs for bitset width"));
    }

    let max_output_elements = max_runs
        .checked_mul(merged_elements)
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
    let output_elements = sizes.iter().try_fold(0usize, |sum, &size| {
        sum.checked_add(size)
            .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))
    })?;
    if output_elements > max_output_elements {
        return Err(Error::new(ErrorKind::Malformed)
            .with_detail("merge_sorted output count exceeds bitset capacity"));
    }
    let output_len = output_elements
        .checked_mul(4)
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
    if output_len > limits.max_decoded_bytes || output_len > limits.max_buffer_bytes {
        return Err(
            Error::new(ErrorKind::LimitExceeded).with_detail("decoded output limit exceeded")
        );
    }

    let mut starts = Vec::new();
    starts.try_reserve_exact(sizes.len()).map_err(|_| {
        Error::new(ErrorKind::LimitExceeded).with_detail("merge_sorted run allocation failed")
    })?;
    let mut cursor = 0usize;
    for &size in &sizes {
        starts.push(cursor);
        cursor = cursor
            .checked_add(size)
            .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
    }

    let mut output = vec![0u8; output_len];
    let mut written = Vec::new();
    written.try_reserve_exact(sizes.len()).map_err(|_| {
        Error::new(ErrorKind::LimitExceeded).with_detail("merge_sorted count allocation failed")
    })?;
    written.resize(sizes.len(), 0usize);

    for value_index in 0..merged_elements {
        let bitset_word = read_numeric_element(bitset.bytes, bitset.element_width, value_index)?;
        let value = read_u32_element(merged.bytes, value_index)?.to_le_bytes();
        for run_index in 0..sizes.len() {
            if written[run_index] == sizes[run_index] || bitset_word & (1u64 << run_index) == 0 {
                continue;
            }
            let element_index = starts[run_index]
                .checked_add(written[run_index])
                .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
            let byte_index = element_index
                .checked_mul(4)
                .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
            output[byte_index..byte_index + 4].copy_from_slice(&value);
            written[run_index] = written[run_index]
                .checked_add(1)
                .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
        }
    }

    if written != sizes {
        return Err(Error::new(ErrorKind::Malformed)
            .with_detail("merge_sorted bitsets do not fill output runs"));
    }
    Ok(OwnedStream::typed(output, 4))
}

pub(super) fn read_merge_sorted_sizes(header: &[u8]) -> Result<Vec<usize>> {
    let mut sizes = Vec::new();
    let mut offset = 0usize;
    while offset < header.len() {
        if sizes.len() == 64 {
            return Err(Error::new(ErrorKind::Malformed)
                .with_detail("merge_sorted has too many output runs"));
        }
        let size = read_var_u64(header, &mut offset)?;
        let size = usize::try_from(size).map_err(|_| {
            Error::new(ErrorKind::LimitExceeded).with_detail("merge_sorted run size is too large")
        })?;
        sizes.push(size);
    }
    Ok(sizes)
}

pub(super) fn decode_sentinel_node(
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
        recyclable: false,
    })
}

pub(super) fn decode_flatpack_serial(
    alphabet: &[u8],
    packed: &[u8],
    limits: Limits,
) -> Result<Vec<u8>> {
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

pub(super) fn flatpack_bits(alphabet_len: usize) -> usize {
    if alphabet_len <= 1 {
        alphabet_len
    } else {
        usize::BITS as usize - (alphabet_len - 1).leading_zeros() as usize
    }
}

pub(super) fn flatpack_output_len(bits: usize, packed: &[u8]) -> Result<usize> {
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

pub(super) fn decode_splitn_node(
    inputs: &[StreamInput<'_>],
    variable_inputs: u32,
    header: &[u8],
    limits: Limits,
) -> Result<Vec<u8>> {
    Ok(decode_splitn_typed_node(inputs, variable_inputs, header, limits)?.bytes)
}

pub(super) fn decode_splitn_typed_node(
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
            recyclable: false,
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
        recyclable: false,
    })
}

pub(super) fn splitn_empty_element_width(header: &[u8]) -> Result<usize> {
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

pub(super) fn decode_split_by_struct_node(
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
    let output_len = split_by_struct_output_len(inputs)?;
    if output_len > limits.max_decoded_bytes || output_len > limits.max_buffer_bytes {
        return Err(
            Error::new(ErrorKind::LimitExceeded).with_detail("decoded output limit exceeded")
        );
    }
    let mut output = Vec::new();
    output.try_reserve_exact(output_len).map_err(|_| {
        Error::new(ErrorKind::LimitExceeded).with_detail("split_by_struct allocation failed")
    })?;
    append_split_by_struct_output(inputs, limits, &mut output)?;
    Ok(OwnedStream {
        bytes: output,
        element_width: 1,
        string_lengths: None,
        recyclable: false,
    })
}

pub(super) fn split_by_struct_output_len(inputs: &[StreamInput<'_>]) -> Result<usize> {
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
    Ok(output_len)
}

pub(super) fn append_split_by_struct_output(
    inputs: &[StreamInput<'_>],
    limits: Limits,
    output: &mut Vec<u8>,
) -> Result<()> {
    let output_len = split_by_struct_output_len(inputs)?;
    if output_len > limits.max_decoded_bytes || output_len > limits.max_buffer_bytes {
        return Err(
            Error::new(ErrorKind::LimitExceeded).with_detail("decoded output limit exceeded")
        );
    }
    let required_capacity = output
        .len()
        .checked_add(output_len)
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
    if output.capacity() < required_capacity {
        output
            .try_reserve_exact(required_capacity - output.len())
            .map_err(|_| {
                Error::new(ErrorKind::LimitExceeded)
                    .with_detail("split_by_struct allocation failed")
            })?;
    }
    fast_split_struct::append_split_by_struct_output(inputs, output);
    Ok(())
}

pub(super) fn decode_mux_lengths_node(
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

    if element_width == 2 {
        return decode_mux_lengths_u16(
            muxed_lengths.bytes,
            long_lengths.bytes,
            split_point,
            ll_mask,
            match_length_bias,
            ml_max,
            output_len,
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
            recyclable: false,
        },
        OwnedStream {
            bytes: match_lengths,
            element_width,
            string_lengths: None,
            recyclable: false,
        },
    ])
}

#[expect(
    clippy::cast_possible_truncation,
    reason = "validated mux length streams fit the u16 output width"
)]
pub(super) fn decode_mux_lengths_u16(
    muxed_lengths: &[u8],
    long_lengths: &[u8],
    split_point: usize,
    ll_mask: u64,
    match_length_bias: u64,
    ml_max: u64,
    output_len: usize,
) -> Result<Vec<OwnedStream>> {
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

    let mut long_lengths = long_lengths.as_chunks::<2>().0.iter();
    for ((literal_out, match_out), &mux) in literal_lengths
        .as_chunks_mut::<2>()
        .0
        .iter_mut()
        .zip(match_lengths.as_chunks_mut::<2>().0)
        .zip(muxed_lengths)
    {
        let mux = u64::from(mux);
        let mut literal = mux & ll_mask;
        let mut matched = match_length_bias + (mux >> split_point);

        if literal == ll_mask {
            literal = literal.wrapping_add(read_next_u16_long_length(&mut long_lengths)?);
        }
        if matched == ml_max {
            matched = matched.wrapping_add(read_next_u16_long_length(&mut long_lengths)?);
        }

        literal_out.copy_from_slice(&(literal as u16).to_le_bytes());
        match_out.copy_from_slice(&(matched as u16).to_le_bytes());
    }
    if long_lengths.next().is_some() {
        return Err(Error::new(ErrorKind::Malformed)
            .with_detail("mux_lengths long-length stream was not fully consumed"));
    }

    Ok(vec![
        OwnedStream {
            bytes: literal_lengths,
            element_width: 2,
            string_lengths: None,
            recyclable: false,
        },
        OwnedStream {
            bytes: match_lengths,
            element_width: 2,
            string_lengths: None,
            recyclable: false,
        },
    ])
}

#[inline]
pub(super) fn read_next_u16_long_length(
    long_lengths: &mut core::slice::Iter<'_, [u8; 2]>,
) -> Result<u64> {
    let bytes = long_lengths.next().ok_or_else(|| {
        Error::new(ErrorKind::Malformed).with_detail("mux_lengths long-length stream is exhausted")
    })?;
    Ok(u64::from(u16::from_le_bytes(*bytes)))
}

pub(super) fn checked_next_long_pos(long_pos: usize, long_count: usize) -> Result<usize> {
    if long_pos >= long_count {
        return Err(Error::new(ErrorKind::Malformed)
            .with_detail("mux_lengths long-length stream is exhausted"));
    }
    long_pos
        .checked_add(1)
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))
}

pub(super) fn decode_bitsplit_node(
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
    if usize::try_from(variable_inputs).is_ok_and(|count| count != inputs.len()) {
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

    Ok(OwnedStream::typed(output, output_width))
}

pub(super) fn bitsplit_element_width(bit_width: usize) -> Result<usize> {
    match bit_width {
        1..=8 => Ok(1),
        9..=16 => Ok(2),
        17..=32 => Ok(4),
        33..=64 => Ok(8),
        _ => Err(Error::new(ErrorKind::Malformed).with_detail("bitsplit bit width is unsupported")),
    }
}

pub(super) fn decode_tokenize_fixed_node(
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
    fast_tokenize::decode_tokenize_indices(
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
        recyclable: false,
    })
}
