//! Memory-safe Rust decoder for OpenZL standard-codec frames.
//!
//! Use [`decode`] for the common owned-output case, [`decode_into`] to append
//! into an existing buffer, and [`inspect`] to parse metadata without executing
//! the frame graph. Use the `*_with_options` variants or [`Decoder::with_options`]
//! when the default decoder options are not appropriate.
//!
//! ```
//! let frame = [
//!     0xd5, 0xa5, 0xb1, 0xd7, 0, 1, 4, 1, 1, 3, 7, 8, 9, 0,
//! ];
//!
//! let decoded = ozlrip::decode(&frame).unwrap();
//! assert_eq!(decoded, [7, 8, 9]);
//! ```
#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(feature = "paranoid", forbid(unsafe_code))]

extern crate alloc;

pub use ozlrip_core::{Error, ErrorKind, FrameInfo, Limits, Result};
pub use ozlrip_decode::{
    Decoder, Options, decode, decode_into, decode_into_with_options, decode_with_options, inspect,
    inspect_with_options,
};
