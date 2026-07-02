#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(feature = "paranoid", forbid(unsafe_code))]

extern crate alloc;

pub use ozlrip_core::{Error, ErrorKind, FrameInfo, Limits, Result};
pub use ozlrip_decode::{Decoder, decode, decode_into, inspect};
