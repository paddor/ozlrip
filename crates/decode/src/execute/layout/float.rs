//! The `float_deconstruct` node: floats rebuilt from a sign-and-fraction
//! stream and an exponent stream.

use alloc::vec::Vec;

use ozlrip_core::{Error, ErrorKind, Limits, Result};

use crate::execute::elements::numeric_element_count;
use crate::execute::header::require_empty_header;
use crate::execute::output::alloc_output;
use crate::execute::streams::{OwnedStream, StreamInput};

#[derive(Clone, Copy)]
enum FloatDeconstructType {
    Float32,
    BFloat16,
    Float16,
}

impl FloatDeconstructType {
    pub(super) const fn sign_frac_width(self) -> usize {
        match self {
            Self::Float32 => 3,
            Self::BFloat16 => 1,
            Self::Float16 => 2,
        }
    }

    pub(super) const fn output_width(self) -> usize {
        match self {
            Self::Float32 => 4,
            Self::BFloat16 | Self::Float16 => 2,
        }
    }
}

pub(in crate::execute) fn decode_float_deconstruct_node(
    inputs: &[StreamInput<'_>],
    header: &[u8],
    format_version: u32,
    limits: Limits,
) -> Result<OwnedStream> {
    let [sign_frac, exponent] = inputs else {
        return Err(Error::new(ErrorKind::InvalidGraph)
            .with_detail("float_deconstruct input count does not match node shape"));
    };
    if sign_frac.string_lengths.is_some() || exponent.string_lengths.is_some() {
        return Err(Error::new(ErrorKind::InvalidType)
            .with_detail("float_deconstruct inputs must not be string streams"));
    }

    let element_type = parse_float_deconstruct_header(header, format_version)?;
    if sign_frac.element_width != element_type.sign_frac_width() {
        return Err(Error::new(ErrorKind::InvalidType)
            .with_detail("float_deconstruct signfrac width does not match element type"));
    }
    if exponent.element_width != 1 {
        return Err(Error::new(ErrorKind::InvalidType)
            .with_detail("float_deconstruct exponent width must be 1"));
    }

    let elements = numeric_element_count(exponent.bytes, exponent.element_width)?;
    if numeric_element_count(sign_frac.bytes, sign_frac.element_width)? != elements {
        return Err(Error::new(ErrorKind::Malformed)
            .with_detail("float_deconstruct streams have different element counts"));
    }
    let output_width = element_type.output_width();
    let output_len = elements
        .checked_mul(output_width)
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
    let mut output = alloc_output(output_len, limits, "float_deconstruct allocation failed")?;
    match element_type {
        FloatDeconstructType::Float32 => {
            decode_float32_deconstruct(sign_frac.bytes, exponent.bytes, &mut output);
        }
        FloatDeconstructType::BFloat16 => {
            decode_bfloat16_deconstruct(sign_frac.bytes, exponent.bytes, &mut output);
        }
        FloatDeconstructType::Float16 => {
            decode_float16_deconstruct(sign_frac.bytes, exponent.bytes, &mut output)?;
        }
    }

    Ok(OwnedStream::typed(output, output_width))
}

fn parse_float_deconstruct_header(
    header: &[u8],
    format_version: u32,
) -> Result<FloatDeconstructType> {
    if format_version < 5 {
        require_empty_header(
            header,
            "float_deconstruct headers before format v5 are unsupported",
        )?;
        return Ok(FloatDeconstructType::Float32);
    }

    let [element_type] = header else {
        return Err(
            Error::new(ErrorKind::Malformed).with_detail("float_deconstruct header is malformed")
        );
    };
    match *element_type {
        0 => Ok(FloatDeconstructType::Float32),
        1 => Ok(FloatDeconstructType::BFloat16),
        2 => Ok(FloatDeconstructType::Float16),
        _ => Err(Error::new(ErrorKind::Malformed)
            .with_detail("float_deconstruct element type is invalid")),
    }
}

fn decode_float32_deconstruct(sign_frac: &[u8], exponent: &[u8], output: &mut Vec<u8>) {
    for (sf, &exp) in sign_frac.as_chunks::<3>().0.iter().zip(exponent) {
        let sf = u32::from(sf[0]) | (u32::from(sf[1]) << 8) | (u32::from(sf[2]) << 16);
        let bits = (u32::from(exp) << 23) | ((sf & 1) << 31) | (sf >> 1);
        output.extend_from_slice(&bits.to_le_bytes());
    }
}

fn decode_bfloat16_deconstruct(sign_frac: &[u8], exponent: &[u8], output: &mut Vec<u8>) {
    for (&sf, &exp) in sign_frac.iter().zip(exponent) {
        let bits = (u16::from(sf & 1) << 15) | (u16::from(exp) << 7) | u16::from(sf >> 1);
        output.extend_from_slice(&bits.to_le_bytes());
    }
}

fn decode_float16_deconstruct(
    sign_frac: &[u8],
    exponent: &[u8],
    output: &mut Vec<u8>,
) -> Result<()> {
    for (sf, &exp) in sign_frac.as_chunks::<2>().0.iter().zip(exponent) {
        let sf = u16::from_le_bytes(*sf);
        if sf & !0x07ff != 0 || exp & !0x1f != 0 {
            return Err(Error::new(ErrorKind::Malformed)
                .with_detail("float16_deconstruct unused bits must be zero"));
        }
        let bits = ((sf & 1) << 15) | (u16::from(exp) << 10) | (sf >> 1);
        output.extend_from_slice(&bits.to_le_bytes());
    }
    Ok(())
}
