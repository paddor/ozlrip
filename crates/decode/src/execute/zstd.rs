use alloc::vec::Vec;

use ozlrip_core::{Error, ErrorKind, Limits, Result};

#[cfg(feature = "zstd")]
use crate::info::FrameValueType;

use crate::parse::FramePlan;
#[cfg(feature = "zstd")]
use crate::{parse::SingleZstdFrame, standard};

#[cfg(feature = "zstd")]
use super::output::{OutputBudget, size_mismatch, verify_decoded_checksum};
use super::{node::StandardNodeContext, streams::OwnedStream};
#[cfg(feature = "zstd")]
use super::{numeric::read_var_u64, runtime::DecodeScratch};

/// The zstd context in `slot`, created on first use.
#[cfg(feature = "zstd")]
pub(crate) fn zstd_context(
    slot: &mut Option<zrip_decode::context::DecompressContext>,
) -> &mut zrip_decode::context::DecompressContext {
    slot.get_or_insert_with(zrip_decode::context::DecompressContext::new)
}

#[cfg(feature = "zstd")]
pub(crate) fn decode_single_zstd_frame_with_context(
    input: &[u8],
    frame: SingleZstdFrame,
    dst: &mut Vec<u8>,
    limits: Limits,
    verify_content: bool,
    zstd: &mut zrip_decode::context::DecompressContext,
) -> Result<usize> {
    let stored = frame.stored.as_slice(input)?;
    let mut offset = 0usize;
    let element_width = read_var_u64(stored, &mut offset)?;
    if element_width != 1 {
        return Err(Error::new(ErrorKind::Unsupported)
            .with_detail("zstd serial streams with non-byte elements are unsupported"));
    }
    let magicless = stored
        .get(offset..)
        .ok_or_else(|| Error::at(ErrorKind::Malformed, offset))?;
    let declared = frame.decoded_bytes.ok_or_else(|| {
        Error::new(ErrorKind::Unsupported)
            .with_detail("unknown OpenZL output sizes are unsupported")
    })?;
    let mut budget = OutputBudget::new(declared, frame.frame_bytes, limits)?;
    let start = dst.len();
    let written = match zstd.decompress_after_magic_into(magicless, dst, budget.remaining()) {
        Ok(written) => written,
        Err(err) => {
            dst.truncate(start);
            return Err(map_budget_zstd_error(&err));
        }
    };
    if let Err(err) = budget.consume(written).and_then(|()| budget.finish()) {
        dst.truncate(start);
        return Err(err);
    }
    if verify_content
        && let Err(err) = verify_decoded_checksum(&dst[start..], frame.decoded_checksum)
    {
        dst.truncate(start);
        return Err(err);
    }
    Ok(written)
}

#[cfg(feature = "zstd")]
pub(super) fn try_decode_single_zstd_into_dst(
    input: &[u8],
    plan: &FramePlan,
    dst: &mut Vec<u8>,
    limits: Limits,
    verify_content: bool,
    zstd: &mut Option<zrip_decode::context::DecompressContext>,
) -> Result<Option<usize>> {
    if plan.info.output_types.as_slice() != [FrameValueType::Serial] || plan.chunks.len() != 1 {
        return Ok(None);
    }
    let chunk = &plan.chunks[0];
    let [node] = chunk.nodes() else {
        return Ok(None);
    };
    if node.standard_id() != Some(standard::ZSTD_ID)
        || node.variable_outputs() != 0
        || node.regen_distances() != [0]
        || node.dict_index().is_some()
        || node.transform_header_size() != 0
        || node.transform_header_start() != 0
        || chunk.stored_streams() != 1
    {
        return Ok(None);
    }

    let stored = chunk
        .stored_stream_range(0)
        .ok_or_else(|| {
            Error::new(ErrorKind::InvalidGraph).with_detail("zstd input stream is missing")
        })?
        .as_slice(input)?;
    let mut offset = 0usize;
    let element_width = read_var_u64(stored, &mut offset)?;
    if element_width == 0 || element_width != 1 {
        return Ok(None);
    }
    let magicless = zstd_frame_after_magic(stored, offset, plan.info.format_version)?;
    let mut budget = OutputBudget::for_output(plan, 0, input.len(), limits)?;
    let start = dst.len();
    let written =
        match zstd_context(zstd).decompress_after_magic_into(magicless, dst, budget.remaining()) {
            Ok(written) => written,
            Err(err) => {
                dst.truncate(start);
                return Err(map_budget_zstd_error(&err));
            }
        };
    if let Err(err) = budget.consume(written).and_then(|()| budget.finish()) {
        dst.truncate(start);
        return Err(err);
    }
    if verify_content
        && let Err(err) = verify_decoded_checksum(&dst[start..], chunk.decoded_checksum)
    {
        dst.truncate(start);
        return Err(err);
    }
    Ok(Some(written))
}

#[cfg(not(feature = "zstd"))]
#[expect(
    clippy::unnecessary_wraps,
    reason = "the zstd-disabled shim keeps the same fallible signature as the zstd implementation"
)]
pub(super) fn try_decode_single_zstd_into_dst(
    _input: &[u8],
    _plan: &FramePlan,
    _dst: &mut Vec<u8>,
    _limits: Limits,
    _verify_content: bool,
) -> Result<Option<usize>> {
    Ok(None)
}

#[cfg(feature = "zstd")]
/// Decodes a zstd node. The deprecated `zstd_fixed` node outputs records of
/// the width its input states; `zstd` outputs bytes.
pub(super) fn decode_zstd_chunk(
    stored: &[u8],
    header: &[u8],
    dict_index: Option<u32>,
    fixed: bool,
    ctx: &mut StandardNodeContext<'_>,
) -> Result<OwnedStream> {
    if !header.is_empty() {
        return Err(Error::new(ErrorKind::Unsupported)
            .with_detail("zstd transform headers are unsupported"));
    }
    let mut offset = 0usize;
    let element_width = read_var_u64(stored, &mut offset)?;
    if element_width == 0 {
        return Err(Error::new(ErrorKind::Malformed).with_detail("zstd element width is zero"));
    }
    if element_width != 1 && !fixed {
        return Err(Error::new(ErrorKind::Unsupported)
            .with_detail("only serial byte zstd output is implemented"));
    }
    let element_width = usize::try_from(element_width).map_err(|_| {
        Error::new(ErrorKind::LimitExceeded).with_detail("zstd element width is too large")
    })?;
    let magicless = zstd_frame_after_magic(stored, offset, ctx.format_version)?;
    let bytes = if let Some(dict_index) = dict_index {
        let bundle_id = ctx.dictionary_bundle_id.ok_or_else(|| {
            Error::new(ErrorKind::Malformed).with_detail("dictionary-backed node has no bundle ID")
        })?;
        let dict_zstd = ctx.dict_store.zstd_context(bundle_id, dict_index)?;
        decode_zstd_magicless_with_context(magicless, ctx.limits, ctx.scratch, dict_zstd)?
    } else {
        decode_zstd_magicless_with_context(
            magicless,
            ctx.limits,
            ctx.scratch,
            zstd_context(ctx.zstd),
        )?
    };
    if !bytes.len().is_multiple_of(element_width) {
        ctx.scratch.recycle_byte_buffer(bytes);
        return Err(Error::new(ErrorKind::Malformed)
            .with_detail("zstd content size is not a multiple of its element width"));
    }
    Ok(OwnedStream::pooled(bytes, element_width))
}

#[cfg(feature = "zstd")]
pub(super) fn decode_zstd_chunk_to_output(
    stored: &[u8],
    header: &[u8],
    dict_index: Option<u32>,
    ctx: &mut StandardNodeContext<'_>,
    max_output: usize,
    dst: &mut Vec<u8>,
) -> Result<()> {
    if !header.is_empty() {
        return Err(Error::new(ErrorKind::Unsupported)
            .with_detail("zstd transform headers are unsupported"));
    }
    let mut offset = 0usize;
    let element_width = read_var_u64(stored, &mut offset)?;
    if element_width == 0 || element_width != 1 {
        return Err(Error::new(ErrorKind::Unsupported)
            .with_detail("only serial byte zstd output is implemented"));
    }
    let magicless = zstd_frame_after_magic(stored, offset, ctx.format_version)?;
    let start = dst.len();
    let written = if let Some(dict_index) = dict_index {
        let bundle_id = ctx.dictionary_bundle_id.ok_or_else(|| {
            Error::new(ErrorKind::Malformed).with_detail("dictionary-backed node has no bundle ID")
        })?;
        let zstd = ctx.dict_store.zstd_context(bundle_id, dict_index)?;
        zstd.decompress_after_magic_into(magicless, dst, max_output)
    } else {
        zstd_context(ctx.zstd).decompress_after_magic_into(magicless, dst, max_output)
    };
    let written = match written {
        Ok(written) => written,
        Err(err) => {
            dst.truncate(start);
            return Err(map_budget_zstd_error(&err));
        }
    };
    debug_assert_eq!(written, dst.len() - start);
    if written > ctx.limits.max_buffer_bytes {
        dst.truncate(start);
        return Err(
            Error::new(ErrorKind::LimitExceeded).with_detail("decoded output limit exceeded")
        );
    }
    Ok(())
}

#[cfg(feature = "zstd")]
fn decode_zstd_magicless_with_context(
    magicless: &[u8],
    limits: Limits,
    scratch: &mut DecodeScratch,
    zstd: &mut zrip_decode::context::DecompressContext,
) -> Result<Vec<u8>> {
    if !magicless.is_empty() {
        // Take a pooled buffer that fits the frame's content size. zrip caps
        // the output at that size and reserves it, plus 64 bytes of slack
        // for its block writer, up to its largest window.
        let content_size =
            zstd_content_size(magicless).filter(|&size| size <= limits.max_decoded_bytes);
        let capacity = content_size.map_or(0, |size| {
            let upfront = usize::try_from(zrip_core::frame::MAX_WINDOW_SIZE).unwrap_or(usize::MAX);
            size.min(upfront) + ZSTD_OUTPUT_SLACK
        });
        let mut output = scratch.take_byte_buffer(capacity, "zstd allocation failed")?;
        let written = match zstd.decompress_after_magic_into(
            magicless,
            &mut output,
            limits.max_decoded_bytes,
        ) {
            Ok(written) => written,
            Err(err) => {
                scratch.recycle_byte_buffer(output);
                return Err(map_zstd_error(&err));
            }
        };
        debug_assert_eq!(written, output.len());
        if output.len() > limits.max_buffer_bytes {
            scratch.recycle_byte_buffer(output);
            return Err(
                Error::new(ErrorKind::LimitExceeded).with_detail("decoded output limit exceeded")
            );
        }
        return Ok(output);
    }
    let output = zstd
        .decompress_after_magic_with_limit(magicless, limits.max_decoded_bytes)
        .map_err(|err| map_zstd_error(&err))?;
    let output = output.into_owned();
    if output.len() > limits.max_buffer_bytes {
        return Err(
            Error::new(ErrorKind::LimitExceeded).with_detail("decoded output limit exceeded")
        );
    }
    Ok(output)
}

/// First format version whose zstd nodes omit the zstd magic number.
#[cfg(feature = "zstd")]
const ZSTD_MAGICLESS_VERSION_MIN: u32 = 9;

/// The zstd magic number, little-endian.
#[cfg(feature = "zstd")]
const ZSTD_MAGIC: [u8; 4] = 0xfd2f_b528_u32.to_le_bytes();

/// The zstd frame in a zstd node's input, which starts at `offset` after the
/// element width, without its magic number. Upstream writes the magic
/// before format v9.
#[cfg(feature = "zstd")]
fn zstd_frame_after_magic(stored: &[u8], offset: usize, format_version: u32) -> Result<&[u8]> {
    let frame = stored
        .get(offset..)
        .ok_or_else(|| Error::at(ErrorKind::Malformed, offset))?;
    if format_version >= ZSTD_MAGICLESS_VERSION_MIN {
        return Ok(frame);
    }
    frame
        .strip_prefix(&ZSTD_MAGIC)
        .ok_or_else(|| Error::new(ErrorKind::Malformed).with_detail("zstd magic number is missing"))
}

/// Spare bytes zrip's block writer keeps past the end of its output.
#[cfg(feature = "zstd")]
const ZSTD_OUTPUT_SLACK: usize = 64;

#[cfg(feature = "zstd")]
fn zstd_content_size(magicless: &[u8]) -> Option<usize> {
    let header = zrip_core::frame::header::parse_frame_header_after_magic(magicless, 0).ok()?;
    usize::try_from(header.frame_content_size?).ok()
}

/// Maps an error from zstd output capped at the frame's remaining declared
/// size: running out of room means the output overran the declaration.
#[cfg(feature = "zstd")]
fn map_budget_zstd_error(err: &zrip_core::DecompressError) -> Error {
    if *err == zrip_core::DecompressError::OutputTooSmall {
        size_mismatch()
    } else {
        map_zstd_error(err)
    }
}

#[cfg(feature = "zstd")]
fn map_zstd_error(err: &zrip_core::DecompressError) -> Error {
    if *err == zrip_core::DecompressError::OutputTooSmall {
        Error::new(ErrorKind::LimitExceeded).with_detail("decoded output limit exceeded")
    } else {
        Error::new(ErrorKind::Malformed).with_detail("OpenZL zstd frame failed")
    }
}

#[cfg(not(feature = "zstd"))]
pub(super) fn decode_zstd_chunk(
    _stored: &[u8],
    _header: &[u8],
    _dict_index: Option<u32>,
    _fixed: bool,
    _ctx: &mut StandardNodeContext<'_>,
) -> Result<OwnedStream> {
    Err(Error::new(ErrorKind::Unsupported).with_detail("zstd support is disabled"))
}

#[cfg(not(feature = "zstd"))]
pub(super) fn decode_zstd_chunk_to_output(
    _stored: &[u8],
    _header: &[u8],
    _dict_index: Option<u32>,
    _ctx: &mut StandardNodeContext<'_>,
    _max_output: usize,
    _dst: &mut Vec<u8>,
) -> Result<()> {
    Err(Error::new(ErrorKind::Unsupported).with_detail("zstd support is disabled"))
}
