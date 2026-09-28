//! Entropy-coding nodes: FSE, Huffman, PivCo Huffman, and the deprecated
//! nodes of the legacy entropy container.

mod fse;
mod huffman;
mod legacy;
mod legacy_huffman;
mod pivco_huffman;

pub(super) use fse::{decode_fse_ncount_node, decode_fse_symbols, decode_fse_v2_node};
pub(super) use huffman::{decode_huffman_struct_v2_node, decode_huffman_v2_node};
pub(super) use legacy::{
    LEGACY_ENTROPY_MAX_DEPTH, decode_fse_deprecated_node, decode_huffman_deprecated_node,
    decode_huffman_fixed_deprecated_node, read_legacy_compressed_entropy_header,
    read_legacy_entropy_header, unpack_legacy_bits,
};
pub(super) use legacy_huffman::decode_legacy_huffman_block;
pub(super) use pivco_huffman::decode_pivco_huffman_node;
