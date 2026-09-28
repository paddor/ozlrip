//! The `mux_lengths` node: lengths muxed into one byte stream, with long
//! lengths in a second stream.

use alloc::vec;
use alloc::vec::Vec;

use ozlrip_core::{Error, ErrorKind, Limits, Result};

use crate::execute::elements::{read_numeric_element, write_numeric_element};
use crate::execute::output::{check_output_len, zeroed_output};
use crate::execute::streams::{OwnedStream, StreamInput};

pub(in crate::execute) fn decode_mux_lengths_node(
    inputs: &[StreamInput<'_>],
    header: &[u8],
    limits: Limits,
) -> Result<Vec<OwnedStream>> {
    let [muxed_lengths, long_lengths] = inputs else {
        return Err(Error::new(ErrorKind::InvalidGraph)
            .with_detail("mux_lengths input count does not match node shape"));
    };
    let [header_byte] = header else {
        return Err(Error::new(ErrorKind::Malformed).with_detail("mux_lengths header is malformed"));
    };
    if muxed_lengths.element_width != 1 {
        return Err(Error::new(ErrorKind::InvalidType)
            .with_detail("mux_lengths muxed input must be serial bytes"));
    }
    let element_width = long_lengths.element_width;
    if !matches!(element_width, 1 | 2 | 4 | 8) {
        return Err(Error::new(ErrorKind::InvalidType)
            .with_detail("mux_lengths long-length width is unsupported"));
    }
    if !long_lengths.bytes.len().is_multiple_of(element_width) {
        return Err(Error::new(ErrorKind::Malformed)
            .with_detail("mux_lengths long-length stream has partial element"));
    }
    let params = MuxLengthsParams::parse(*header_byte)?;
    let output_len = muxed_lengths
        .bytes
        .len()
        .checked_mul(element_width)
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
    check_output_len(output_len, limits)?;

    if element_width == 2 {
        return decode_mux_lengths_u16(muxed_lengths.bytes, long_lengths.bytes, params, output_len);
    }
    decode_mux_lengths_any_width(
        muxed_lengths.bytes,
        long_lengths.bytes,
        element_width,
        params,
        output_len,
    )
}

/// The split point and match length bias a mux_lengths header packs into
/// one byte, and the masks derived from them.
#[derive(Clone, Copy)]
struct MuxLengthsParams {
    split_point: usize,
    ll_mask: u64,
    match_length_bias: u64,
    ml_max: u64,
}

impl MuxLengthsParams {
    fn parse(header_byte: u8) -> Result<Self> {
        let split_point = usize::from(header_byte & 0x0f);
        if split_point > 8 {
            return Err(
                Error::new(ErrorKind::Malformed).with_detail("mux_lengths split point is invalid")
            );
        }
        let match_length_bias = u64::from(header_byte >> 4);
        let ll_mask = if split_point == 64 {
            u64::MAX
        } else {
            (1u64 << split_point) - 1
        };
        let ml_mask = (1u64 << (8 - split_point)) - 1;
        let ml_max = match_length_bias
            .checked_add(ml_mask)
            .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
        Ok(Self {
            split_point,
            ll_mask,
            match_length_bias,
            ml_max,
        })
    }
}

fn decode_mux_lengths_any_width(
    muxed_lengths: &[u8],
    long_lengths: &[u8],
    element_width: usize,
    params: MuxLengthsParams,
    output_len: usize,
) -> Result<Vec<OwnedStream>> {
    let MuxLengthsParams {
        split_point,
        ll_mask,
        match_length_bias,
        ml_max,
    } = params;
    let mut literal_lengths = zeroed_output(output_len, "mux_lengths allocation failed")?;
    let mut match_lengths = zeroed_output(output_len, "mux_lengths allocation failed")?;

    let mut long_pos = 0usize;
    let long_count = long_lengths.len() / element_width;
    for (index, &mux) in muxed_lengths.iter().enumerate() {
        let mux = u64::from(mux);
        let mut literal = mux & ll_mask;
        let mut matched = match_length_bias + (mux >> split_point);

        if literal == ll_mask {
            literal =
                literal.wrapping_add(read_numeric_element(long_lengths, element_width, long_pos)?);
            long_pos = checked_next_long_pos(long_pos, long_count)?;
        }
        if matched == ml_max {
            matched =
                matched.wrapping_add(read_numeric_element(long_lengths, element_width, long_pos)?);
            long_pos = checked_next_long_pos(long_pos, long_count)?;
        }

        let offset = index
            .checked_mul(element_width)
            .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
        write_numeric_element(&mut literal_lengths[offset..], element_width, literal);
        write_numeric_element(&mut match_lengths[offset..], element_width, matched);
    }
    if long_pos != long_count {
        return Err(Error::new(ErrorKind::Malformed)
            .with_detail("mux_lengths long-length stream was not fully consumed"));
    }
    Ok(vec![
        OwnedStream::typed(literal_lengths, element_width),
        OwnedStream::typed(match_lengths, element_width),
    ])
}

#[expect(
    clippy::cast_possible_truncation,
    reason = "validated mux length streams fit the u16 output width"
)]
fn decode_mux_lengths_u16(
    muxed_lengths: &[u8],
    long_lengths: &[u8],
    params: MuxLengthsParams,
    output_len: usize,
) -> Result<Vec<OwnedStream>> {
    let MuxLengthsParams {
        split_point,
        ll_mask,
        match_length_bias,
        ml_max,
    } = params;
    let mut literal_lengths = zeroed_output(output_len, "mux_lengths allocation failed")?;
    let mut match_lengths = zeroed_output(output_len, "mux_lengths allocation failed")?;

    let mut long_lengths = long_lengths.as_chunks::<2>().0.iter();
    for ((literal_out, match_out), &mux) in literal_lengths
        .as_chunks_mut::<2>()
        .0
        .iter_mut()
        .zip(match_lengths.as_chunks_mut::<2>().0)
        .zip(muxed_lengths)
    {
        let mux = u64::from(mux);
        let mut literal = mux & ll_mask;
        let mut matched = match_length_bias + (mux >> split_point);

        if literal == ll_mask {
            literal = literal.wrapping_add(read_next_u16_long_length(&mut long_lengths)?);
        }
        if matched == ml_max {
            matched = matched.wrapping_add(read_next_u16_long_length(&mut long_lengths)?);
        }

        literal_out.copy_from_slice(&(literal as u16).to_le_bytes());
        match_out.copy_from_slice(&(matched as u16).to_le_bytes());
    }
    if long_lengths.next().is_some() {
        return Err(Error::new(ErrorKind::Malformed)
            .with_detail("mux_lengths long-length stream was not fully consumed"));
    }
    Ok(vec![
        OwnedStream::typed(literal_lengths, 2),
        OwnedStream::typed(match_lengths, 2),
    ])
}

#[inline]
fn read_next_u16_long_length(long_lengths: &mut core::slice::Iter<'_, [u8; 2]>) -> Result<u64> {
    let bytes = long_lengths.next().ok_or_else(|| {
        Error::new(ErrorKind::Malformed).with_detail("mux_lengths long-length stream is exhausted")
    })?;
    Ok(u64::from(u16::from_le_bytes(*bytes)))
}

fn checked_next_long_pos(long_pos: usize, long_count: usize) -> Result<usize> {
    if long_pos >= long_count {
        return Err(Error::new(ErrorKind::Malformed)
            .with_detail("mux_lengths long-length stream is exhausted"));
    }
    long_pos
        .checked_add(1)
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))
}
