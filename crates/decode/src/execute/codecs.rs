//! External codec nodes: zstd through `zrip-decode` and lz4 through
//! `lz4rip-decode`, plus the whole-frame zstd fast path.

mod lz4;
mod zstd;

pub(super) use lz4::decode_lz4_chunk;
#[cfg(feature = "zstd")]
pub(crate) use zstd::{decode_single_zstd_frame_with_context, zstd_context};
pub(super) use zstd::{
    decode_zstd_chunk, decode_zstd_chunk_to_output, try_decode_single_zstd_into_dst,
};
