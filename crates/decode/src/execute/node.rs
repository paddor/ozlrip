use alloc::{format, vec::Vec};

use crate::{dict::DictionaryStore, standard};
use ozlrip_core::{Error, ErrorKind, Limits, Result};
use smallvec::{SmallVec, smallvec};

use super::layout_nodes::{
    decode_bitsplit_node, decode_concat_node, decode_flatpack_node, decode_float_deconstruct_node,
    decode_merge_sorted_node, decode_mux_lengths_node, decode_sentinel_node,
    decode_split_by_struct_node, decode_splitn_node, decode_splitn_typed_node,
    decode_tokenize_fixed_node, decode_transpose_node, decode_transpose_split_node,
    is_transpose_split,
};
use super::lz4::decode_lz4_chunk;
use super::numeric::{checked_sum_u32, read_var_u64};
use super::plan::NodeExecutionPlan;
use super::streams::{
    LiveBytes, OwnedStream, StreamInput, StreamSlot, move_stream_to_single_output,
    single_execution_input,
};
use super::string_nodes::{
    decode_concat_string_node, decode_interleave_string_node, decode_prefix_node,
    decode_separate_string_components_node, decode_string_to_serial_node,
    decode_tokenize_string_node,
};
use super::{
    DecodeScratch, QUANTIZE_LENGTHS, QUANTIZE_OFFSETS, decode_bitpack_int_chunk,
    decode_bitpack_serial_chunk, decode_bitunpack_serial8_chunk,
    decode_byte_preserving_conversion_chunk, decode_constant_fixed_chunk,
    decode_constant_serial_chunk, decode_delta_node, decode_dispatch_n_by_tag_node,
    decode_dispatch_string_node, decode_divide_by_node, decode_fastlz_deprecated_node,
    decode_field_lz_node, decode_fse_deprecated_node, decode_fse_ncount_node, decode_fse_v2_node,
    decode_huffman_deprecated_node, decode_huffman_fixed_deprecated_node,
    decode_huffman_struct_v2_node, decode_huffman_v2_node, decode_lz_node,
    decode_num_to_struct_le_chunk, decode_numeric_to_serial_le_chunk, decode_partition_node,
    decode_quantize_node, decode_range_pack_serial8_chunk, decode_rolz_deprecated_node,
    decode_serial_to_num_be_chunk, decode_serial_to_numeric_le_chunk,
    decode_serial_to_struct_chunk, decode_struct_to_num_be_chunk, decode_zigzag_numeric_chunk,
    decode_zstd_chunk, parse_int, pivco_huffman,
};

pub(super) fn try_execute_single_input_splitn_node(
    streams: &mut [StreamSlot<'_>],
    node: &NodeExecutionPlan,
    header: &[u8],
    limits: Limits,
    live: &mut LiveBytes,
) -> Result<bool> {
    if !matches!(
        node.standard_id,
        standard::SPLITN_ID | standard::SPLITN_STRUCT_ID | standard::SPLITN_NUM_ID
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
    move_stream_to_single_output(streams, node, output_width, live)
}

pub(super) fn try_execute_byte_preserving_conversion_node(
    streams: &mut [StreamSlot<'_>],
    node: &NodeExecutionPlan,
    header: &[u8],
    limits: Limits,
    live: &mut LiveBytes,
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
    move_stream_to_single_output(streams, node, output_width, live)
}

pub(super) fn is_byte_preserving_conversion(standard_id: u32) -> bool {
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

pub(super) fn byte_preserving_conversion_output_width(
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
            let int_size = read_conversion_int_size(header, "convert_num_to_serial_le")?;
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

pub(super) fn read_single_conversion_width(header: &[u8]) -> Result<usize> {
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

pub(super) fn read_conversion_int_size(header: &[u8], transform: &'static str) -> Result<usize> {
    let [int_log] = header else {
        return Err(Error::new(ErrorKind::Malformed)
            .with_detail(format!("{transform} header is malformed")));
    };
    if *int_log > 3 {
        return Err(Error::new(ErrorKind::Malformed)
            .with_detail(format!("{transform} integer width is invalid")));
    }
    1usize
        .checked_shl(u32::from(*int_log))
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))
}

pub(super) fn validate_conversion_numeric_width(element_width: usize) -> Result<()> {
    match element_width {
        1 | 2 | 4 | 8 => Ok(()),
        _ => Err(Error::new(ErrorKind::InvalidType)
            .with_detail("conversion numeric width is unsupported")),
    }
}

pub(super) fn node_header(headers: &[u8], start: usize, len: usize) -> Result<&[u8]> {
    let end = start
        .checked_add(len)
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
    headers.get(start..end).ok_or_else(|| {
        Error::new(ErrorKind::InvalidGraph).with_detail("node header is out of bounds")
    })
}

pub(super) struct StandardNodeContext<'a> {
    pub(super) format_version: u32,
    pub(super) limits: Limits,
    pub(super) scratch: &'a mut DecodeScratch,
    #[cfg_attr(not(feature = "zstd"), allow(dead_code))]
    pub(super) dictionary_bundle_id: Option<&'a [u8]>,
    #[cfg_attr(not(feature = "zstd"), allow(dead_code))]
    pub(super) dict_store: &'a mut DictionaryStore,
    #[cfg(feature = "zstd")]
    pub(super) zstd: &'a mut zrip_decode::context::DecompressContext,
}

pub(super) fn execute_standard_node(
    standard_id: u32,
    inputs: &[StreamInput<'_>],
    variable_inputs: u32,
    output_count: usize,
    dict_index: Option<u32>,
    header: &[u8],
    ctx: &mut StandardNodeContext<'_>,
) -> Result<SmallVec<[OwnedStream; 2]>> {
    match standard_id {
        standard::CONCAT_SERIAL_ID | standard::CONCAT_NUM_ID | standard::CONCAT_STRUCT_ID => {
            decode_concat_node(inputs, header, output_count, ctx.limits).map(SmallVec::from_vec)
        }
        standard::CONCAT_STRING_ID => {
            decode_concat_string_node(inputs, header, output_count, ctx.limits)
                .map(SmallVec::from_vec)
        }
        standard::INTERLEAVE_STRING_ID => {
            decode_interleave_string_node(single_stream(inputs)?, header, ctx.limits)
                .map(SmallVec::from_vec)
        }
        standard::SPLITN_ID => one_serial(decode_splitn_node(
            inputs,
            variable_inputs,
            header,
            ctx.limits,
        )),
        standard::SPLITN_STRUCT_ID | standard::SPLITN_NUM_ID => one_typed(
            decode_splitn_typed_node(inputs, variable_inputs, header, ctx.limits),
        ),
        standard::SPLIT_BY_STRUCT_ID => one_typed(decode_split_by_struct_node(
            inputs,
            variable_inputs,
            header,
            ctx.limits,
        )),
        standard::FLATPACK_ID => one_serial(decode_flatpack_node(inputs, header, ctx.limits)),
        standard::FLOAT_DECONSTRUCT_ID => one_typed(decode_float_deconstruct_node(
            inputs,
            header,
            ctx.format_version,
            ctx.limits,
        )),
        standard::MERGE_SORTED_ID => {
            one_typed(decode_merge_sorted_node(inputs, header, ctx.limits))
        }
        standard::SEPARATE_STRING_COMPONENTS_ID => one_typed(
            decode_separate_string_components_node(inputs, header, ctx.limits),
        ),
        standard::CONVERT_STRING_TO_SERIAL_ID => one_serial(decode_string_to_serial_node(
            single_stream(inputs)?,
            header,
            ctx.limits,
        )),
        standard::DISPATCH_STRING_ID => one_typed(decode_dispatch_string_node(
            inputs,
            variable_inputs,
            header,
            ctx.format_version,
            ctx.limits,
        )),
        standard::DISPATCH_N_BY_TAG_ID => one_serial(decode_dispatch_n_by_tag_node(
            inputs,
            variable_inputs,
            header,
            ctx.format_version,
            ctx.limits,
        )),
        standard::PREFIX_ID => one_typed(decode_prefix_node(inputs, header, ctx.limits)),
        standard::SENTINEL_ID => one_typed(decode_sentinel_node(inputs, header, ctx.limits)),
        standard::TRANSPOSE_ID => one_typed(decode_transpose_node(
            single_stream(inputs)?,
            header,
            ctx.limits,
            ctx.scratch,
        )),
        id if is_transpose_split(id) => one_typed(decode_transpose_split_node(
            inputs,
            variable_inputs,
            header,
            ctx.limits,
            ctx.scratch,
        )),
        standard::FSE_DEPRECATED_ID => one_serial(decode_fse_deprecated_node(
            single_stream(inputs)?,
            header,
            ctx.limits,
        )),
        standard::HUFFMAN_DEPRECATED_ID => one_serial(decode_huffman_deprecated_node(
            single_stream(inputs)?,
            header,
            ctx.limits,
        )),
        standard::HUFFMAN_FIXED_DEPRECATED_ID => one_typed(decode_huffman_fixed_deprecated_node(
            single_stream(inputs)?,
            header,
            ctx.format_version,
            ctx.limits,
        )),
        standard::ROLZ_DEPRECATED_ID => one_serial(decode_rolz_deprecated_node(
            single_stream(inputs)?,
            header,
            ctx.limits,
        )),
        standard::FASTLZ_DEPRECATED_ID => one_serial(decode_fastlz_deprecated_node(
            single_stream(inputs)?,
            header,
            ctx.limits,
        )),
        standard::LZ4_ID => one_serial(decode_lz4_chunk(single_input(inputs)?, header, ctx.limits)),
        standard::ZSTD_ID | standard::ZSTD_FIXED_ID => one_typed(
            decode_zstd_chunk(single_input(inputs)?, header, dict_index, ctx)
                .map(|bytes| OwnedStream::pooled(bytes, 1)),
        ),
        standard::BITPACK_SERIAL_ID => one_serial(decode_bitpack_serial_chunk(
            single_input(inputs)?,
            header,
            ctx.limits,
            ctx.scratch,
        )),
        standard::BITPACK_INT_ID => one_typed(decode_bitpack_int_chunk(
            single_input(inputs)?,
            header,
            ctx.limits,
            ctx.scratch,
        )),
        standard::CONSTANT_SERIAL_ID => one_typed(decode_constant_serial_chunk(
            single_input(inputs)?,
            header,
            ctx.limits,
            ctx.scratch,
        )),
        standard::CONSTANT_FIXED_ID => one_typed(decode_constant_fixed_chunk(
            single_stream(inputs)?,
            header,
            ctx.limits,
            ctx.scratch,
        )),
        standard::CONVERT_SERIAL_TO_STRUCT_ID => one_typed(
            decode_byte_preserving_conversion_chunk(single_stream(inputs)?, header, ctx.limits),
        ),
        standard::CONVERT_STRUCT_TO_SERIAL_ID => one_typed(decode_serial_to_struct_chunk(
            single_stream(inputs)?,
            header,
            ctx.limits,
        )),
        standard::CONVERT_STRUCT_TO_NUM_LE_ID | standard::CONVERT_NUM_TO_STRUCT_LE_ID => one_typed(
            decode_num_to_struct_le_chunk(single_stream(inputs)?, header, ctx.limits),
        ),
        standard::CONVERT_STRUCT_TO_NUM_BE_ID => one_typed(decode_struct_to_num_be_chunk(
            single_stream(inputs)?,
            header,
            ctx.limits,
        )),
        standard::CONVERT_SERIAL_TO_NUM_BE_ID => one_typed(decode_serial_to_num_be_chunk(
            single_stream(inputs)?,
            header,
            ctx.limits,
        )),
        standard::CONVERT_SERIAL_TO_NUM_LE_ID => one_serial(decode_numeric_to_serial_le_chunk(
            single_stream(inputs)?,
            header,
            ctx.limits,
        )),
        standard::CONVERT_NUM_TO_SERIAL_LE_ID => one_typed(decode_serial_to_numeric_le_chunk(
            single_stream(inputs)?,
            header,
            ctx.limits,
        )),
        standard::MUX_LENGTHS_ID => {
            decode_mux_lengths_node(inputs, header, ctx.limits).map(SmallVec::from_vec)
        }
        standard::LZ_ID => one_serial(decode_lz_node(inputs, header, ctx.limits)),
        standard::FIELD_LZ_ID => one_typed(decode_field_lz_node(
            inputs,
            header,
            ctx.limits,
            ctx.scratch,
        )),
        standard::ZIGZAG_ID => one_typed(decode_zigzag_numeric_chunk(
            single_stream(inputs)?,
            header,
            ctx.limits,
        )),
        standard::DELTA_INT_ID => one_typed(decode_delta_node(
            single_stream(inputs)?,
            header,
            ctx.limits,
            ctx.scratch,
        )),
        standard::DIVIDE_BY_ID => one_typed(decode_divide_by_node(
            single_stream(inputs)?,
            header,
            ctx.limits,
        )),
        standard::BITUNPACK_ID => one_serial(decode_bitunpack_serial8_chunk(
            single_input(inputs)?,
            header,
            ctx.limits,
        )),
        standard::BIT_SPLIT_ID => one_typed(decode_bitsplit_node(
            inputs,
            variable_inputs,
            header,
            ctx.limits,
        )),
        standard::RANGE_PACK_ID => one_serial(decode_range_pack_serial8_chunk(
            single_input(inputs)?,
            header,
            ctx.limits,
        )),
        standard::PARSE_INT_ID => one_typed(parse_int::decode_node(
            single_stream(inputs)?,
            header,
            ctx.limits,
        )),
        standard::FSE_NCOUNT_ID => one_typed(decode_fse_ncount_node(
            single_stream(inputs)?,
            header,
            ctx.limits,
        )),
        standard::FSE_V2_ID => one_serial(decode_fse_v2_node(inputs, header, ctx.limits)),
        standard::HUFFMAN_V2_ID => one_serial(decode_huffman_v2_node(inputs, header, ctx.limits)),
        standard::HUFFMAN_STRUCT_V2_ID => {
            one_typed(decode_huffman_struct_v2_node(inputs, header, ctx.limits))
        }
        standard::PIVCO_HUFFMAN_ID => {
            one_serial(pivco_huffman::decode_node(inputs, header, ctx.limits))
        }
        standard::QUANTIZE_OFFSETS_ID => one_typed(decode_quantize_node(
            inputs,
            header,
            ctx.limits,
            &QUANTIZE_OFFSETS,
        )),
        standard::QUANTIZE_LENGTHS_ID => one_typed(decode_quantize_node(
            inputs,
            header,
            ctx.limits,
            &QUANTIZE_LENGTHS,
        )),
        standard::PARTITION_ID => one_typed(decode_partition_node(inputs, header, ctx.limits)),
        standard::TOKENIZE_FIXED_ID | standard::TOKENIZE_NUMERIC_ID => {
            one_typed(decode_tokenize_fixed_node(inputs, header, ctx.limits))
        }
        standard::TOKENIZE_STRING_ID => {
            one_typed(decode_tokenize_string_node(inputs, header, ctx.limits))
        }
        _ => Err(Error::new(ErrorKind::Unsupported)
            .with_detail("standard transform graph execution is not implemented yet")),
    }
}

pub(super) fn one_serial(result: Result<Vec<u8>>) -> Result<SmallVec<[OwnedStream; 2]>> {
    Ok(smallvec![OwnedStream::serial(result?)])
}

pub(super) fn one_typed(result: Result<OwnedStream>) -> Result<SmallVec<[OwnedStream; 2]>> {
    Ok(smallvec![result?])
}

pub(super) fn single_input<'a>(inputs: &[StreamInput<'a>]) -> Result<&'a [u8]> {
    Ok(single_stream(inputs)?.bytes)
}

pub(super) fn single_stream<'a>(inputs: &[StreamInput<'a>]) -> Result<StreamInput<'a>> {
    match inputs {
        [input] => Ok(*input),
        _ => Err(Error::new(ErrorKind::InvalidGraph)
            .with_detail("single-input transform received the wrong input count")),
    }
}
