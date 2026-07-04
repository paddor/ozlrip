#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(feature = "paranoid", forbid(unsafe_code))]

extern crate alloc;

use alloc::vec::Vec;
use ozlrip_core::{FrameInfo, Limits, Result};

mod execute;
mod parse;
mod standard;

const PLAN_CACHE_MAX_FRAME_BYTES: usize = 4096;

pub struct Decoder {
    limits: Limits,
    scratch: execute::DecodeScratch,
    plan_cache: Option<CachedFramePlan>,
    #[cfg(feature = "zstd")]
    zstd: zrip::DecompressContext,
}

struct CachedFramePlan {
    frame: Vec<u8>,
    plan: parse::FramePlan,
    direct_append_plans: Option<execute::DirectAppendChunkPlans>,
}

impl Decoder {
    pub fn new(limits: Limits) -> Self {
        Self {
            limits,
            scratch: execute::DecodeScratch::new(),
            plan_cache: None,
            #[cfg(feature = "zstd")]
            zstd: zrip::DecompressContext::new(),
        }
    }

    pub fn limits(&self) -> Limits {
        self.limits
    }

    pub fn decode_into(&mut self, input: &[u8], dst: &mut Vec<u8>) -> Result<usize> {
        #[cfg(feature = "zstd")]
        if let Some(frame) = parse::parse_single_zstd_frame(input, self.limits)? {
            return execute::decode_single_zstd_frame_with_context(
                input,
                frame,
                dst,
                self.limits,
                &mut self.zstd,
            );
        }
        if let Some(cached) = self.plan_cache.as_ref()
            && cached.frame == input
        {
            if let Some(direct_append_plans) = cached.direct_append_plans.as_ref() {
                return execute::decode_plan_with_cached_direct_append_plans(
                    input,
                    &cached.plan,
                    direct_append_plans,
                    dst,
                    self.limits,
                    &mut self.scratch,
                    #[cfg(feature = "zstd")]
                    &mut self.zstd,
                );
            }
            return execute::decode_plan_with_context(
                input,
                &cached.plan,
                dst,
                self.limits,
                &mut self.scratch,
                #[cfg(feature = "zstd")]
                &mut self.zstd,
            );
        }

        let plan = parse::parse_frame_plan(input, self.limits)?;
        self.remember_frame_plan(input, &plan);
        execute::decode_plan_with_context(
            input,
            &plan,
            dst,
            self.limits,
            &mut self.scratch,
            #[cfg(feature = "zstd")]
            &mut self.zstd,
        )
    }

    fn remember_frame_plan(&mut self, input: &[u8], plan: &parse::FramePlan) {
        if input.len() > PLAN_CACHE_MAX_FRAME_BYTES {
            self.plan_cache = None;
            return;
        }

        let mut frame = Vec::new();
        if frame.try_reserve_exact(input.len()).is_err() {
            self.plan_cache = None;
            return;
        }
        frame.extend_from_slice(input);
        let direct_append_plans = execute::prepare_direct_append_chunk_plans(plan)
            .ok()
            .flatten();
        self.plan_cache = Some(CachedFramePlan {
            frame,
            plan: plan.clone(),
            direct_append_plans,
        });
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
