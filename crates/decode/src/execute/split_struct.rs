//! The split_by_struct shape check, shared by the node decoder and its
//! fast path.

use ozlrip_core::{Error, ErrorKind, Result};

use super::streams::StreamInput;

/// Output size of a split_by_struct node, after checking that every input
/// has whole elements of a nonzero width and the same element count.
pub(super) fn split_by_struct_output_len(inputs: &[StreamInput<'_>]) -> Result<usize> {
    let Some(first) = inputs.first() else {
        return Err(Error::new(ErrorKind::Malformed).with_detail("split_by_struct requires inputs"));
    };
    if first.element_width == 0 {
        return Err(
            Error::new(ErrorKind::InvalidType).with_detail("split_by_struct field width is zero")
        );
    }
    if !first.bytes.len().is_multiple_of(first.element_width) {
        return Err(Error::new(ErrorKind::Malformed)
            .with_detail("split_by_struct input has partial element"));
    }

    let element_count = first.bytes.len() / first.element_width;
    let mut struct_width = 0usize;
    for input in inputs {
        if input.element_width == 0 {
            return Err(Error::new(ErrorKind::InvalidType)
                .with_detail("split_by_struct field width is zero"));
        }
        if !input.bytes.len().is_multiple_of(input.element_width) {
            return Err(Error::new(ErrorKind::Malformed)
                .with_detail("split_by_struct input has partial element"));
        }
        if input.bytes.len() / input.element_width != element_count {
            return Err(Error::new(ErrorKind::Malformed)
                .with_detail("split_by_struct inputs have mismatched element counts"));
        }
        struct_width = struct_width
            .checked_add(input.element_width)
            .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
    }
    let output_len = element_count
        .checked_mul(struct_width)
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
    Ok(output_len)
}
