//! Checked `usize` arithmetic that reports overflow as `IntegerOverflow`.

use ozlrip_core::{Error, ErrorKind, Result};

pub(crate) fn checked_add(lhs: usize, rhs: usize) -> Result<usize> {
    lhs.checked_add(rhs)
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))
}

pub(crate) fn checked_mul(lhs: usize, rhs: usize) -> Result<usize> {
    lhs.checked_mul(rhs)
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))
}
