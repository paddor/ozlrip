use alloc::vec::Vec;

use ozlrip_core::{Error, ErrorKind, Result};

/// Appends each byte of `sizes` to the empty `output` as a `u32` and sets
/// `total` to their sum.
#[inline]
pub(super) fn decode_u8_lengths(
    sizes: &[u8],
    output: &mut Vec<u32>,
    total: &mut usize,
) -> Result<()> {
    debug_assert_eq!(output.as_slice(), []);
    for &size in sizes {
        *total = total
            .checked_add(usize::from(size))
            .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
        output.push(u32::from(size));
    }
    Ok(())
}
