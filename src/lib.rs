//! Memory-safe Rust decoder for OpenZL standard-codec frames.
//!
//! - [`decode`] and [`decode_into`] decode a frame with one serial output.
//! - [`decode_outputs`] decodes every output of a frame with its type:
//!   bytes, fixed-width records, integers or strings.
//! - [`Decoder`] keeps buffers, codec state and dictionary bundles between
//!   frames. [`Decoder::decode_chunks`] decodes a large frame one chunk at a
//!   time.
//! - [`inspect`], [`inspect_header`] and [`frame_size`] read frame metadata
//!   without decoding.
//!
//! The `*_with_options` variants and [`Decoder::with_options`] take
//! [`Options`]: the [`Limits`] that bound work on untrusted input, and
//! whether to verify checksums.
//!
//! ```
//! let frame = [
//!     0xd5, 0xa5, 0xb1, 0xd7, 0, 1, 4, 1, 1, 3, 7, 8, 9, 0,
//! ];
//!
//! let decoded = ozlrip::decode(&frame).unwrap();
//! assert_eq!(decoded, [7, 8, 9]);
//! ```
//!
//! # Features
//!
//! - `std` (default): SIMD dispatch and `std` support in the codecs.
//!   Without it the crate is `no_std` and needs `alloc`.
//! - `alloc` (default): required.
//! - `zstd` (default): zstd nodes, decoded by `zrip`.
//! - `lz4` (default): lz4 nodes, decoded by `lz4rip`.
//! - `paranoid`: keeps any future `unsafe` out; no effect today. Every
//!   crate is `#![forbid(unsafe_code)]`.
#![cfg_attr(not(feature = "std"), no_std)]
#![warn(missing_docs)]
#![forbid(unsafe_code)]

extern crate alloc;

pub use ozlrip_core::{Error, ErrorKind, Limits, Result};
pub use ozlrip_decode::{
    Decoder, DictionaryProvider, FrameHeaderInfo, FrameInfo, FrameValueType, Options, Output,
    decode, decode_into, decode_into_with_options, decode_outputs, decode_outputs_into,
    decode_outputs_into_with_options, decode_outputs_with_options, decode_with_options, frame_size,
    frame_size_with_options, inspect, inspect_header, inspect_header_with_options,
    inspect_with_options,
};
