#![cfg_attr(feature = "paranoid", forbid(unsafe_code))]

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
    #[cfg(not(feature = "paranoid"))]
    {
        output.reserve(sizes.len());
        let start = output.len();
        let dst = output.as_mut_ptr();
        let mut sum = 0usize;
        for (index, &size) in sizes.iter().enumerate() {
            sum = sum
                .checked_add(usize::from(size))
                .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
            // SAFETY: `reserve` made room for `sizes.len()` elements after
            // `start`, and `index < sizes.len()`.
            unsafe {
                dst.add(start + index).write(u32::from(size));
            }
        }
        // SAFETY: the loop wrote the `sizes.len()` elements after `start`.
        unsafe {
            output.set_len(start + sizes.len());
        }
        *total = sum;
    }
    #[cfg(feature = "paranoid")]
    {
        for &size in sizes {
            *total = total
                .checked_add(usize::from(size))
                .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
            output.push(u32::from(size));
        }
    }
    Ok(())
}
