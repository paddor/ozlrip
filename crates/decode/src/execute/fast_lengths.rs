#![cfg_attr(feature = "paranoid", forbid(unsafe_code))]

use alloc::vec::Vec;

use ozlrip_core::{Error, ErrorKind, Result};

#[inline]
pub(super) fn decode_u8_lengths(
    sizes: &[u8],
    output: &mut Vec<u32>,
    total: &mut usize,
) -> Result<()> {
    debug_assert!(output.is_empty());
    debug_assert!(output.capacity() >= sizes.len());
    #[cfg(not(feature = "paranoid"))]
    {
        unsafe {
            let dst = output.as_mut_ptr();
            let mut sum = 0usize;
            for (index, &size) in sizes.iter().enumerate() {
                sum = sum
                    .checked_add(usize::from(size))
                    .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
                dst.add(index).write(u32::from(size));
            }
            output.set_len(sizes.len());
            *total = sum;
        }
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
