use alloc::vec::Vec;

use ozlrip_core::{Error, ErrorKind, Limits, Result};

#[cfg(feature = "zstd")]
use ozlrip_core::FrameValueType;

use crate::parse::FramePlan;
#[cfg(feature = "zstd")]
use crate::{parse::SingleZstdFrame, standard};

use super::StandardNodeContext;
#[cfg(feature = "checksum")]
use super::verify_decoded_checksum;
#[cfg(feature = "zstd")]
use super::{DecodeScratch, check_output_size, read_var_u64};

#[cfg(feature = "zstd")]
pub(crate) fn decode_single_zstd_frame_with_context(
    input: &[u8],
    frame: SingleZstdFrame,
    dst: &mut Vec<u8>,
    limits: Limits,
    zstd: &mut zrip::DecompressContext,
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
        .ok_or_else(|| Error::at(ErrorKind::Truncated, offset))?;
    let start = dst.len();
    let written = match zstd.decompress_after_magic_into(magicless, dst, limits.max_decoded_bytes) {
        Ok(written) => written,
        Err(err) => {
            dst.truncate(start);
            return Err(map_zstd_error(&err));
        }
    };
    if written > limits.max_buffer_bytes {
        dst.truncate(start);
        return Err(
            Error::new(ErrorKind::LimitExceeded).with_detail("decoded output limit exceeded")
        );
    }
    if let Some(expected) = frame.decoded_bytes
        && expected != written
    {
        dst.truncate(start);
        return Err(Error::new(ErrorKind::Malformed).with_detail("decoded output size mismatch"));
    }
    if frame.frame_bytes > 0 && written / frame.frame_bytes > limits.max_expansion_ratio {
        dst.truncate(start);
        return Err(Error::new(ErrorKind::LimitExceeded).with_detail("expansion ratio exceeded"));
    }
    #[cfg(feature = "checksum")]
    if let Err(err) = verify_decoded_checksum(&dst[start..], frame.decoded_checksum) {
        dst.truncate(start);
        return Err(err);
    }
    #[cfg(not(feature = "checksum"))]
    let _ = frame.decoded_checksum;
    Ok(written)
}

#[cfg(feature = "zstd")]
pub(super) fn try_decode_single_zstd_into_dst(
    input: &[u8],
    plan: &FramePlan,
    dst: &mut Vec<u8>,
    limits: Limits,
    zstd: &mut zrip::DecompressContext,
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
    let magicless = stored
        .get(offset..)
        .ok_or_else(|| Error::at(ErrorKind::Truncated, offset))?;
    let start = dst.len();
    let written = match zstd.decompress_after_magic_into(magicless, dst, limits.max_decoded_bytes) {
        Ok(written) => written,
        Err(err) => {
            dst.truncate(start);
            return Err(map_zstd_error(&err));
        }
    };
    if written > limits.max_buffer_bytes {
        dst.truncate(start);
        return Err(
            Error::new(ErrorKind::LimitExceeded).with_detail("decoded output limit exceeded")
        );
    }
    if let Err(err) = check_output_size(written, input.len(), plan, limits) {
        dst.truncate(start);
        return Err(err);
    }
    #[cfg(feature = "checksum")]
    if let Err(err) = verify_decoded_checksum(&dst[start..], chunk.decoded_checksum) {
        dst.truncate(start);
        return Err(err);
    }
    #[cfg(not(feature = "checksum"))]
    let _ = chunk.decoded_checksum;
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
) -> Result<Option<usize>> {
    Ok(None)
}

#[cfg(feature = "zstd")]
pub(super) fn decode_zstd_chunk(
    stored: &[u8],
    header: &[u8],
    dict_index: Option<u32>,
    ctx: &mut StandardNodeContext<'_>,
) -> Result<Vec<u8>> {
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
    let magicless = stored
        .get(offset..)
        .ok_or_else(|| Error::at(ErrorKind::Truncated, offset))?;
    if let Some(dict_index) = dict_index {
        let bundle_id = ctx.dictionary_bundle_id.ok_or_else(|| {
            Error::new(ErrorKind::Malformed).with_detail("dictionary-backed node has no bundle ID")
        })?;
        let dict_zstd = ctx.dict_store.zstd_context(bundle_id, dict_index)?;
        return decode_zstd_magicless_with_context(magicless, ctx.limits, ctx.scratch, dict_zstd);
    }
    decode_zstd_magicless_with_context(magicless, ctx.limits, ctx.scratch, ctx.zstd)
}

#[cfg(feature = "zstd")]
fn decode_zstd_magicless_with_context(
    magicless: &[u8],
    limits: Limits,
    scratch: &mut DecodeScratch,
    zstd: &mut zrip::DecompressContext,
) -> Result<Vec<u8>> {
    if !magicless.is_empty() {
        let mut output = scratch.take_byte_buffer(0, "zstd allocation failed")?;
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

#[cfg(feature = "zstd")]
fn map_zstd_error(err: &zrip::DecompressError) -> Error {
    if *err == zrip::DecompressError::OutputTooSmall {
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
    _ctx: &mut StandardNodeContext<'_>,
) -> Result<Vec<u8>> {
    Err(Error::new(ErrorKind::Unsupported).with_detail("zstd support is disabled"))
}
