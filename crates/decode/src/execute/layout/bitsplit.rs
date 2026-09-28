//! The `bitsplit` node: elements rebuilt from streams of bit fields.

use alloc::vec::Vec;

use ozlrip_core::{Error, ErrorKind, Limits, Result};

use crate::execute::elements::{
    numeric_element_count, read_numeric_element, validate_numeric_stream_width,
    write_numeric_element,
};
use crate::execute::output::alloc_output;
use crate::execute::streams::{OwnedStream, StreamInput};

pub(in crate::execute) fn decode_bitsplit_node(
    inputs: &[StreamInput<'_>],
    variable_inputs: u32,
    header: &[u8],
    limits: Limits,
) -> Result<OwnedStream> {
    let (&output_width, stored_widths) = header.split_first().ok_or_else(|| {
        Error::new(ErrorKind::Malformed).with_detail("bitsplit header is missing output width")
    })?;
    let output_width = usize::from(output_width);
    validate_numeric_stream_width(output_width, "bitsplit output")?;

    let bit_widths = parse_bitsplit_widths(stored_widths, output_width, inputs.len())?;
    if usize::try_from(variable_inputs).is_ok_and(|count| count != inputs.len()) {
        return Err(Error::new(ErrorKind::InvalidGraph)
            .with_detail("bitsplit variable input count does not match inputs"));
    }
    let element_count = bitsplit_element_count(inputs, &bit_widths)?;

    let output_len = element_count
        .checked_mul(output_width)
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
    let mut output = alloc_output(output_len, limits, "bitsplit allocation failed")?;
    output.resize(output_len, 0);

    for element in 0..element_count {
        let mut value = 0u64;
        let mut bit_pos = 0usize;
        for (input, &bit_width) in inputs.iter().zip(bit_widths.iter()) {
            let part = read_numeric_element(input.bytes, input.element_width, element)?;
            value |= part << bit_pos;
            bit_pos = bit_pos
                .checked_add(bit_width)
                .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
        }
        let output_offset = element
            .checked_mul(output_width)
            .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
        write_numeric_element(&mut output[output_offset..], output_width, value);
    }

    Ok(OwnedStream::typed(output, output_width))
}

/// Bit width of each bitsplit input: the stored widths, plus the rest of
/// the output width when the node has one more input than stored widths.
fn parse_bitsplit_widths(
    stored_widths: &[u8],
    output_width: usize,
    input_count: usize,
) -> Result<Vec<usize>> {
    let mut bit_widths = Vec::new();
    bit_widths.try_reserve_exact(input_count).map_err(|_| {
        Error::new(ErrorKind::AllocationFailed).with_detail("bitsplit width allocation failed")
    })?;
    let mut stored_sum = 0usize;
    for &width in stored_widths {
        if width == 0 {
            return Err(Error::new(ErrorKind::Malformed).with_detail("bitsplit width is zero"));
        }
        let width = usize::from(width);
        stored_sum = stored_sum
            .checked_add(width)
            .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
        bit_widths.push(width);
    }

    let output_bits = output_width
        .checked_mul(8)
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
    if stored_sum > output_bits {
        return Err(
            Error::new(ErrorKind::Malformed).with_detail("bitsplit widths exceed output width")
        );
    }
    if input_count == stored_widths.len() + 1 {
        let last_width = output_bits
            .checked_sub(stored_sum)
            .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
        if last_width == 0 {
            return Err(
                Error::new(ErrorKind::Malformed).with_detail("bitsplit inferred width is zero")
            );
        }
        bit_widths.push(last_width);
    } else if input_count != stored_widths.len() {
        return Err(Error::new(ErrorKind::InvalidGraph)
            .with_detail("bitsplit input count does not match header"));
    }
    if bit_widths.is_empty() {
        return Err(Error::new(ErrorKind::Malformed).with_detail("bitsplit has no bit widths"));
    }
    Ok(bit_widths)
}

/// Element count shared by all bitsplit inputs, after checking each input's
/// width against its bit width.
fn bitsplit_element_count(inputs: &[StreamInput<'_>], bit_widths: &[usize]) -> Result<usize> {
    let first = inputs
        .first()
        .ok_or_else(|| Error::new(ErrorKind::InvalidGraph).with_detail("bitsplit has no inputs"))?;
    let element_count = numeric_element_count(first.bytes, first.element_width)?;
    for (input, &bit_width) in inputs.iter().zip(bit_widths.iter()) {
        validate_numeric_stream_width(input.element_width, "bitsplit input")?;
        if numeric_element_count(input.bytes, input.element_width)? != element_count {
            return Err(
                Error::new(ErrorKind::Malformed).with_detail("bitsplit input counts do not match")
            );
        }
        if bit_width > input.element_width * 8 {
            return Err(
                Error::new(ErrorKind::Malformed).with_detail("bitsplit width exceeds input width")
            );
        }
        if input.element_width != bitsplit_element_width(bit_width)? {
            return Err(Error::new(ErrorKind::InvalidType)
                .with_detail("bitsplit input width does not match bit width"));
        }
    }
    Ok(element_count)
}

fn bitsplit_element_width(bit_width: usize) -> Result<usize> {
    match bit_width {
        1..=8 => Ok(1),
        9..=16 => Ok(2),
        17..=32 => Ok(4),
        33..=64 => Ok(8),
        _ => Err(Error::new(ErrorKind::Malformed).with_detail("bitsplit bit width is unsupported")),
    }
}
