#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(feature = "paranoid", forbid(unsafe_code))]

extern crate alloc;

use alloc::vec::Vec;
use ozlrip_core::{FrameInfo, Limits, Result};

mod execute;
mod parse;
mod standard;

pub struct Decoder {
    limits: Limits,
    scratch: Vec<u8>,
}

impl Decoder {
    pub fn new(limits: Limits) -> Self {
        Self {
            limits,
            scratch: Vec::new(),
        }
    }

    pub fn limits(&self) -> Limits {
        self.limits
    }

    pub fn decode_into(&mut self, input: &[u8], dst: &mut Vec<u8>) -> Result<usize> {
        let plan = parse::parse_frame_plan(input, self.limits)?;
        self.scratch.clear();
        execute::decode_plan(input, &plan, dst, self.limits)
    }

    pub fn inspect(&self, input: &[u8]) -> Result<FrameInfo> {
        parse::inspect_frame(input, self.limits)
    }
}

impl Default for Decoder {
    fn default() -> Self {
        Self::new(Limits::default())
    }
}

pub fn decode(input: &[u8]) -> Result<Vec<u8>> {
    let mut output = Vec::new();
    decode_into(input, &mut output, Limits::default())?;
    Ok(output)
}

pub fn decode_into(input: &[u8], dst: &mut Vec<u8>, limits: Limits) -> Result<usize> {
    Decoder::new(limits).decode_into(input, dst)
}

pub fn inspect(input: &[u8]) -> Result<FrameInfo> {
    Decoder::default().inspect(input)
}
