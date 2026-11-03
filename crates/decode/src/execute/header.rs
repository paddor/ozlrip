//! Checks on node headers.

use ozlrip_core::{Error, ErrorKind, Result};

/// Fails with `Unsupported` and `detail` unless `header` is empty, for
/// nodes whose header upstream never writes.
#[inline]
pub(super) fn require_empty_header(header: &[u8], detail: &'static str) -> Result<()> {
    if header.is_empty() {
        Ok(())
    } else {
        Err(Error::new(ErrorKind::Unsupported).with_detail(detail))
    }
}
