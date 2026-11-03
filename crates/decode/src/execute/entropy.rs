//! Entropy-coding nodes: FSE, Huffman, PivCo Huffman, and the deprecated
//! nodes of the legacy entropy container.

mod fse;
mod huffman;
mod legacy;
mod legacy_huffman;
mod pivco_huffman;

#[cfg(test)]
pub(super) use fse::decode_fse_symbols;
pub(super) use fse::{decode_fse_ncount_node, decode_fse_v2_node};
pub(super) use huffman::{decode_huffman_struct_v2_node, decode_huffman_v2_node};
pub(super) use legacy::{
    LegacyLimit, LegacyParams, LegacyPayload, decode_fse_deprecated_node,
    decode_huffman_deprecated_node, decode_huffman_fixed_deprecated_node, parse_legacy_payload,
};
pub(super) use pivco_huffman::decode_pivco_huffman_node;
