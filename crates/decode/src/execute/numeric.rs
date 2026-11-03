//! Numeric nodes: bit packing, arithmetic transforms, repeats, conversions,
//! `parse_int`, `sparse_num`, `quantize` and `partition`.

mod arithmetic;
mod bit_reader;
mod bitpack;
mod convert;
#[cfg(test)]
mod convert_corpus;
mod fast_bitpack;
mod fast_delta;
mod fast_partition;
mod fast_zigzag;
mod parse_int;
#[cfg(test)]
mod parse_int_corpus;
mod partition;
mod repeat;
mod sparse_num;
#[cfg(test)]
mod sparse_num_corpus;

pub(super) use arithmetic::{
    decode_delta_node, decode_divide_by_node, decode_range_pack_node, decode_zigzag_numeric_chunk,
};
pub(super) use bitpack::{
    decode_bitpack_int_chunk, decode_bitpack_serial_chunk, decode_bitunpack_node,
};
pub(super) use convert::{
    byte_preserving_conversion_output_width, decode_serial_to_num_be_chunk,
    decode_struct_to_num_be_chunk, is_byte_preserving_conversion,
};
pub(super) use parse_int::decode_parse_int_node;
pub(super) use partition::{
    QUANTIZE_LENGTHS, QUANTIZE_OFFSETS, decode_partition_node, decode_quantize_node,
};
pub(super) use repeat::{
    decode_constant_fixed_chunk, decode_constant_serial_chunk, decode_dedup_num_node,
};
pub(super) use sparse_num::decode_sparse_num_node;
