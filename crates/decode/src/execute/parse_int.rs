use alloc::{string::ToString, vec::Vec};

use ozlrip_core::{Error, ErrorKind, Limits, Result};

use super::{OwnedStream, StreamInput, numeric_element_count};

pub(super) fn decode_node(
    input: StreamInput<'_>,
    header: &[u8],
    limits: Limits,
) -> Result<OwnedStream> {
    if !header.is_empty() {
        return Err(Error::new(ErrorKind::Malformed)
            .with_detail("parse_int transform header must be empty"));
    }
    if input.element_width != 8 {
        return Err(Error::new(ErrorKind::InvalidType)
            .with_detail("parse_int input must be width-8 numeric values"));
    }
    if input.string_lengths.is_some() {
        return Err(Error::new(ErrorKind::InvalidType)
            .with_detail("parse_int input must be numeric, not string"));
    }

    let count = numeric_element_count(input.bytes, input.element_width)?;
    let mut lengths = Vec::new();
    lengths.try_reserve_exact(count).map_err(|_| {
        Error::new(ErrorKind::LimitExceeded).with_detail("parse_int length allocation failed")
    })?;

    let mut output = Vec::new();
    for raw in input.bytes.chunks_exact(8) {
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(raw);
        let text = i64::from_le_bytes(bytes).to_string();
        let len = u32::try_from(text.len()).map_err(|_| Error::new(ErrorKind::IntegerOverflow))?;
        let new_len = output
            .len()
            .checked_add(text.len())
            .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
        if new_len > limits.max_decoded_bytes || new_len > limits.max_buffer_bytes {
            return Err(
                Error::new(ErrorKind::LimitExceeded).with_detail("decoded output limit exceeded")
            );
        }
        lengths.push(len);
        output.try_reserve_exact(text.len()).map_err(|_| {
            Error::new(ErrorKind::LimitExceeded).with_detail("parse_int output allocation failed")
        })?;
        output.extend_from_slice(text.as_bytes());
    }

    Ok(OwnedStream {
        bytes: output,
        element_width: 1,
        string_lengths: Some(lengths),
        recyclable: false,
    })
}
