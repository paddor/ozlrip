use alloc::vec::Vec;

use ozlrip_core::{Error, ErrorKind, Limits, Result};

use super::output::alloc_output;
use super::{
    elements::push_numeric_element,
    elements::{numeric_element_count, read_usize_numeric_element},
    streams::{OwnedStream, StreamInput},
};

#[inline(never)]
#[cold]
pub(super) fn decode_node(
    inputs: &[StreamInput<'_>],
    header: &[u8],
    limits: Limits,
) -> Result<OwnedStream> {
    let [distances, values] = inputs else {
        return Err(Error::new(ErrorKind::InvalidGraph)
            .with_detail("sparse_num input count does not match node shape"));
    };
    if !matches!(distances.element_width, 1 | 2 | 4) {
        return Err(Error::new(ErrorKind::InvalidType)
            .with_detail("sparse_num distance width is unsupported"));
    }
    if !matches!(values.element_width, 1 | 2 | 4 | 8) {
        return Err(
            Error::new(ErrorKind::InvalidType).with_detail("sparse_num value width is unsupported")
        );
    }
    if header.len() > values.element_width {
        return Err(
            Error::new(ErrorKind::Malformed).with_detail("sparse_num header exceeds value width")
        );
    }

    let distance_count = numeric_element_count(distances.bytes, distances.element_width)?;
    let value_count = numeric_element_count(values.bytes, values.element_width)?;
    if distance_count != value_count && distance_count != value_count.saturating_add(1) {
        return Err(Error::new(ErrorKind::Malformed)
            .with_detail("sparse_num distance count does not match literal count"));
    }

    let dominant = read_dominant(header);
    let mut output_elements = value_count;
    for index in 0..distance_count {
        output_elements = output_elements
            .checked_add(read_usize_numeric_element(
                distances.bytes,
                distances.element_width,
                index,
            )?)
            .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
    }
    let output_len = output_elements
        .checked_mul(values.element_width)
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
    let mut output = alloc_output(output_len, limits, "sparse_num allocation failed")?;
    for index in 0..value_count {
        let distance = read_usize_numeric_element(distances.bytes, distances.element_width, index)?;
        append_run(&mut output, dominant, distance, values.element_width)?;
        let start = index
            .checked_mul(values.element_width)
            .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
        let end = start
            .checked_add(values.element_width)
            .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
        let value = values.bytes.get(start..end).ok_or_else(|| {
            Error::new(ErrorKind::Malformed).with_detail("sparse_num value stream is truncated")
        })?;
        output.extend_from_slice(value);
    }
    if distance_count == value_count + 1 {
        let distance =
            read_usize_numeric_element(distances.bytes, distances.element_width, value_count)?;
        append_run(&mut output, dominant, distance, values.element_width)?;
    }
    debug_assert_eq!(output.len(), output_len);
    Ok(OwnedStream::typed(output, values.element_width))
}

#[inline(never)]
#[cold]
fn read_dominant(header: &[u8]) -> u64 {
    let mut bytes = [0u8; 8];
    bytes[..header.len()].copy_from_slice(header);
    u64::from_le_bytes(bytes)
}

#[inline(never)]
#[cold]
fn append_run(
    output: &mut Vec<u8>,
    dominant: u64,
    distance: usize,
    value_width: usize,
) -> Result<()> {
    let run_len = distance
        .checked_mul(value_width)
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
    if dominant == 0 {
        output.resize(output.len() + run_len, 0);
        return Ok(());
    }
    for _ in 0..distance {
        push_numeric_element(output, value_width, dominant);
    }
    Ok(())
}
