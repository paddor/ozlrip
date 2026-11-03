//! LZ-family nodes: `lz`, `field_lz`, and the deprecated `fastlz` and
//! `rolz`.

mod fastlz;
mod field_lz;
mod legacy_literals;
mod rolz;
mod rolz_decoder;
mod sequences;

pub(super) use fastlz::decode_fastlz_deprecated_node;
pub(super) use field_lz::{decode_field_lz_node, decode_field_lz_node_to_output};
pub(super) use rolz::decode_rolz_deprecated_node;
pub(super) use sequences::{decode_lz_node, decode_lz_node_to_output};
