use alloc::vec::Vec;

use ozlrip_core::{Error, ErrorKind, Result};

/// Lengths summed per step: their sum stays below 2^24, so it fits `usize`
/// on every target, and only the running total needs an overflow check.
const SUM_CHUNK: usize = 1 << 16;

/// Appends each byte of `sizes` to the empty `output` as a `u32` and sets
/// `total` to their sum.
#[inline]
pub(super) fn decode_u8_lengths(
    sizes: &[u8],
    output: &mut Vec<u32>,
    total: &mut usize,
) -> Result<()> {
    debug_assert_eq!(output.as_slice(), []);
    *total = sizes
        .chunks(SUM_CHUNK)
        .try_fold(0usize, |total, chunk| {
            total.checked_add(chunk.iter().map(|&size| usize::from(size)).sum())
        })
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
    output.extend(sizes.iter().map(|&size| u32::from(size)));
    Ok(())
}
