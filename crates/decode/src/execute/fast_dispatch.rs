#![cfg_attr(feature = "paranoid", forbid(unsafe_code))]

use alloc::{vec, vec::Vec};

use ozlrip_core::{Error, ErrorKind, Result};

use super::{StreamInput, read_usize_numeric_element};

pub(super) fn decode_dispatch_n_by_tag_to_output(
    tags: &StreamInput<'_>,
    segment_sizes: &StreamInput<'_>,
    segment_inputs: &[StreamInput<'_>],
    segment_count: usize,
    total_output: usize,
    output: &mut Vec<u8>,
) -> Result<()> {
    output.try_reserve_exact(total_output).map_err(|_| {
        Error::new(ErrorKind::LimitExceeded).with_detail("dispatchN_byTag output allocation failed")
    })?;

    #[cfg(not(feature = "paranoid"))]
    {
        decode_dispatch_n_by_tag_to_output_fast(
            tags,
            segment_sizes,
            segment_inputs,
            segment_count,
            total_output,
            output,
        )
    }
    #[cfg(feature = "paranoid")]
    {
        decode_dispatch_n_by_tag_to_output_safe(
            tags,
            segment_sizes,
            segment_inputs,
            segment_count,
            total_output,
            output,
        )
    }
}

#[cfg(not(feature = "paranoid"))]
fn decode_dispatch_n_by_tag_to_output_fast(
    tags: &StreamInput<'_>,
    segment_sizes: &StreamInput<'_>,
    segment_inputs: &[StreamInput<'_>],
    segment_count: usize,
    total_output: usize,
    output: &mut Vec<u8>,
) -> Result<()> {
    let mut source_positions = vec![0usize; segment_inputs.len()];
    let start_len = output.len();
    debug_assert!(output.capacity() >= start_len + total_output);
    let mut written = 0usize;

    unsafe {
        let dst_start = output.as_mut_ptr().add(start_len);
        for segment in 0..segment_count {
            let tag = read_usize_numeric_element(tags.bytes, tags.element_width, segment)?;
            let size = read_usize_numeric_element(
                segment_sizes.bytes,
                segment_sizes.element_width,
                segment,
            )?;
            let input = segment_inputs.get(tag).ok_or_else(|| {
                Error::new(ErrorKind::Malformed).with_detail("dispatchN_byTag tag is out of range")
            })?;
            let position = source_positions.get_mut(tag).ok_or_else(|| {
                Error::new(ErrorKind::Malformed).with_detail("dispatchN_byTag tag is out of range")
            })?;
            let end = position
                .checked_add(size)
                .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
            let segment_bytes = input.bytes.get(*position..end).ok_or_else(|| {
                Error::new(ErrorKind::Malformed)
                    .with_detail("dispatchN_byTag source stream is truncated")
            })?;
            let next_written = written
                .checked_add(size)
                .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
            if next_written > total_output {
                return Err(Error::new(ErrorKind::Malformed)
                    .with_detail("dispatchN_byTag output size mismatch"));
            }
            core::ptr::copy_nonoverlapping(
                segment_bytes.as_ptr(),
                dst_start.add(written),
                segment_bytes.len(),
            );
            written = next_written;
            *position = end;
        }
        output.set_len(start_len + written);
    }
    Ok(())
}

#[cfg(feature = "paranoid")]
fn decode_dispatch_n_by_tag_to_output_safe(
    tags: &StreamInput<'_>,
    segment_sizes: &StreamInput<'_>,
    segment_inputs: &[StreamInput<'_>],
    segment_count: usize,
    total_output: usize,
    output: &mut Vec<u8>,
) -> Result<()> {
    let mut source_positions = vec![0usize; segment_inputs.len()];
    for segment in 0..segment_count {
        let tag = read_usize_numeric_element(tags.bytes, tags.element_width, segment)?;
        let size =
            read_usize_numeric_element(segment_sizes.bytes, segment_sizes.element_width, segment)?;
        let input = segment_inputs.get(tag).ok_or_else(|| {
            Error::new(ErrorKind::Malformed).with_detail("dispatchN_byTag tag is out of range")
        })?;
        let position = source_positions.get_mut(tag).ok_or_else(|| {
            Error::new(ErrorKind::Malformed).with_detail("dispatchN_byTag tag is out of range")
        })?;
        let end = position
            .checked_add(size)
            .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
        let segment_bytes = input.bytes.get(*position..end).ok_or_else(|| {
            Error::new(ErrorKind::Malformed)
                .with_detail("dispatchN_byTag source stream is truncated")
        })?;
        output.extend_from_slice(segment_bytes);
        *position = end;
    }
    if output.len() != total_output {
        return Err(
            Error::new(ErrorKind::Malformed).with_detail("dispatchN_byTag output size mismatch")
        );
    }
    Ok(())
}
