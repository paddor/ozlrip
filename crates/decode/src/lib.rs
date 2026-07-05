#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(feature = "paranoid", forbid(unsafe_code))]

extern crate alloc;

use alloc::vec::Vec;
use ozlrip_core::{FrameInfo, Limits, Result};

mod execute;
mod parse;
mod standard;

pub const DEFAULT_PLAN_CACHE_MAX_FRAME_BYTES: usize = 4096;

/// Decoder configuration.
///
/// New options should be added here instead of creating new public function
/// variants.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Options {
    /// Defensive parser, graph, allocation, and expansion limits.
    pub limits: Limits,
    /// Maximum frame size eligible for reusable decoder plan caching.
    ///
    /// Set to `0` to disable plan caching.
    pub plan_cache_max_frame_bytes: usize,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            limits: Limits::default(),
            plan_cache_max_frame_bytes: DEFAULT_PLAN_CACHE_MAX_FRAME_BYTES,
        }
    }
}

/// Reusable OpenZL decoder with scratch buffers and codec state.
pub struct Decoder {
    options: Options,
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
    /// Creates a decoder with [`Options::default`].
    pub fn new() -> Self {
        Self::with_options(Options::default())
    }

    /// Creates a decoder with explicit options.
    pub fn with_options(options: Options) -> Self {
        Self {
            options,
            scratch: execute::DecodeScratch::new(),
            plan_cache: None,
            #[cfg(feature = "zstd")]
            zstd: zrip::DecompressContext::new(),
        }
    }

    pub fn options(&self) -> Options {
        self.options
    }

    pub fn limits(&self) -> Limits {
        self.options.limits
    }

    /// Decodes one OpenZL frame and appends the decoded bytes to `dst`.
    ///
    /// Returns the number of bytes appended. On error, `dst` is restored to its
    /// original length.
    pub fn decode_into(&mut self, input: &[u8], dst: &mut Vec<u8>) -> Result<usize> {
        #[cfg(feature = "zstd")]
        if let Some(frame) = parse::parse_single_zstd_frame(input, self.options.limits)? {
            return execute::decode_single_zstd_frame_with_context(
                input,
                frame,
                dst,
                self.options.limits,
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
                    self.options.limits,
                    &mut self.scratch,
                    #[cfg(feature = "zstd")]
                    &mut self.zstd,
                );
            }
            return execute::decode_plan_with_context(
                input,
                &cached.plan,
                dst,
                self.options.limits,
                &mut self.scratch,
                #[cfg(feature = "zstd")]
                &mut self.zstd,
            );
        }

        let plan = parse::parse_frame_plan(input, self.options.limits)?;
        self.remember_frame_plan(input, &plan);
        execute::decode_plan_with_context(
            input,
            &plan,
            dst,
            self.options.limits,
            &mut self.scratch,
            #[cfg(feature = "zstd")]
            &mut self.zstd,
        )
    }

    fn remember_frame_plan(&mut self, input: &[u8], plan: &parse::FramePlan) {
        if self.options.plan_cache_max_frame_bytes == 0
            || input.len() > self.options.plan_cache_max_frame_bytes
        {
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

    /// Decodes one OpenZL frame into a new `Vec`.
    pub fn decode(&mut self, input: &[u8]) -> Result<Vec<u8>> {
        let mut output = Vec::new();
        self.decode_into(input, &mut output)?;
        Ok(output)
    }

    /// Parses and validates frame metadata without executing decode nodes.
    pub fn inspect(&self, input: &[u8]) -> Result<FrameInfo> {
        parse::inspect_frame(input, self.options.limits)
    }
}

impl Default for Decoder {
    fn default() -> Self {
        Self::new()
    }
}

/// Decodes one OpenZL frame into a new `Vec` using [`Options::default`].
pub fn decode(input: &[u8]) -> Result<Vec<u8>> {
    Decoder::new().decode(input)
}

/// Decodes one OpenZL frame into a new `Vec` using explicit options.
pub fn decode_with_options(input: &[u8], options: Options) -> Result<Vec<u8>> {
    Decoder::with_options(options).decode(input)
}

/// Decodes one OpenZL frame and appends the decoded bytes to `dst`.
///
/// Returns the number of bytes appended. On error, `dst` is restored to its
/// original length.
pub fn decode_into(input: &[u8], dst: &mut Vec<u8>) -> Result<usize> {
    Decoder::new().decode_into(input, dst)
}

/// Decodes one OpenZL frame into `dst` using explicit options.
pub fn decode_into_with_options(
    input: &[u8],
    dst: &mut Vec<u8>,
    options: Options,
) -> Result<usize> {
    Decoder::with_options(options).decode_into(input, dst)
}

/// Parses and validates frame metadata using [`Options::default`].
pub fn inspect(input: &[u8]) -> Result<FrameInfo> {
    Decoder::default().inspect(input)
}

/// Parses and validates frame metadata using explicit options.
pub fn inspect_with_options(input: &[u8], options: Options) -> Result<FrameInfo> {
    Decoder::with_options(options).inspect(input)
}
