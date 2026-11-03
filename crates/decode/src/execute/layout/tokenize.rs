//! The `tokenize` node for fixed-width and numeric tokens: an alphabet and
//! indexes into it.

use ozlrip_core::{Error, ErrorKind, Limits, Result};

use super::fast_tokenize;
use crate::execute::elements::{numeric_element_count, validate_numeric_stream_width};
use crate::execute::header::require_empty_header;
use crate::execute::output::check_output_len;
use crate::execute::runtime::DecodeScratch;
use crate::execute::streams::{OwnedStream, StreamInput};

pub(in crate::execute) fn decode_tokenize_fixed_node(
    inputs: &[StreamInput<'_>],
    header: &[u8],
    limits: Limits,
    scratch: &mut DecodeScratch,
) -> Result<OwnedStream> {
    require_empty_header(header, "tokenize_fixed headers are unsupported")?;
    let [alphabet, indices] = inputs else {
        return Err(Error::new(ErrorKind::InvalidGraph)
            .with_detail("tokenize_fixed input count does not match node shape"));
    };
    let element_width = alphabet.element_width;
    if element_width == 0 || !alphabet.bytes.len().is_multiple_of(element_width) {
        return Err(Error::new(ErrorKind::Malformed)
            .with_detail("tokenize_fixed alphabet has partial element"));
    }
    validate_numeric_stream_width(indices.element_width, "tokenize_fixed indices")?;
    let alphabet_size = alphabet.bytes.len() / element_width;
    let output_elements = numeric_element_count(indices.bytes, indices.element_width)?;
    let output_len = output_elements
        .checked_mul(element_width)
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
    check_output_len(output_len, limits)?;
    if alphabet_size == 0 && output_elements != 0 {
        return Err(
            Error::new(ErrorKind::Malformed).with_detail("tokenize_fixed alphabet is empty")
        );
    }

    let mut output = scratch.take_byte_buffer(output_len, "tokenize allocation failed")?;
    fast_tokenize::decode_tokenize_indices(
        alphabet.bytes,
        alphabet_size,
        element_width,
        indices.bytes,
        indices.element_width,
        &mut output,
    )?;
    Ok(OwnedStream::pooled(output, element_width))
}
