use alloc::vec::Vec;

use crate::standard;
use ozlrip_core::{Error, ErrorKind, Result};

use smallvec::{SmallVec, smallvec};

use super::layout_nodes::{
    decode_bitsplit_node, decode_concat_node, decode_flatpack_node, decode_float_deconstruct_node,
    decode_merge_sorted_node, decode_mux_lengths_node, decode_sentinel_node,
    decode_split_by_struct_node, decode_splitn_node, decode_splitn_typed_node,
    decode_tokenize_fixed_node, decode_transpose_node, decode_transpose_split_node,
    is_transpose_split,
};
use super::lz4::decode_lz4_chunk;
use super::streams::{OwnedStream, StreamInput};
use super::string_nodes::{
    decode_concat_string_node, decode_interleave_string_node, decode_prefix_node,
    decode_separate_string_components_node, decode_tokenize_string_node,
};
use super::{
    dispatch::{decode_dispatch_n_by_tag_node, decode_dispatch_string_node},
    entropy::{
        decode_fse_deprecated_node, decode_fse_ncount_node, decode_fse_v2_node,
        decode_huffman_deprecated_node, decode_huffman_fixed_deprecated_node,
        decode_huffman_struct_v2_node, decode_huffman_v2_node,
    },
    lz_nodes::{
        decode_fastlz_deprecated_node, decode_field_lz_node, decode_lz_node,
        decode_rolz_deprecated_node,
    },
    numeric_nodes::{
        decode_bitpack_int_chunk, decode_bitpack_serial_chunk, decode_bitunpack_node,
        decode_constant_fixed_chunk, decode_constant_serial_chunk, decode_delta_node,
        decode_divide_by_node, decode_range_pack_node, decode_serial_to_num_be_chunk,
        decode_struct_to_num_be_chunk, decode_zigzag_numeric_chunk,
    },
    parse_int,
    partition::{QUANTIZE_LENGTHS, QUANTIZE_OFFSETS, decode_partition_node, decode_quantize_node},
    pivco_huffman,
    runtime::StandardNodeContext,
    zstd::decode_zstd_chunk,
};

pub(super) fn node_header(headers: &[u8], start: usize, len: usize) -> Result<&[u8]> {
    let end = start
        .checked_add(len)
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
    headers.get(start..end).ok_or_else(|| {
        Error::new(ErrorKind::InvalidGraph).with_detail("node header is out of bounds")
    })
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
        standard::ZSTD_ID | standard::ZSTD_FIXED_ID => one_typed(decode_zstd_chunk(
            single_input(inputs)?,
            header,
            dict_index,
            standard_id == standard::ZSTD_FIXED_ID,
            ctx,
        )),
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
            ctx.format_version,
            ctx.limits,
            ctx.scratch,
        )),
        standard::DIVIDE_BY_ID => one_typed(decode_divide_by_node(
            single_stream(inputs)?,
            header,
            ctx.limits,
        )),
        standard::BITUNPACK_ID => one_serial(decode_bitunpack_node(
            single_stream(inputs)?,
            header,
            ctx.limits,
        )),
        standard::BIT_SPLIT_ID => one_typed(decode_bitsplit_node(
            inputs,
            variable_inputs,
            header,
            ctx.limits,
        )),
        standard::RANGE_PACK_ID => one_typed(decode_range_pack_node(
            single_stream(inputs)?,
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
        // Byte-preserving conversions never get here: `execute_node` moves
        // their input to the output slot.
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
