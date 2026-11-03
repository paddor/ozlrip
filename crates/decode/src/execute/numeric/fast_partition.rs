use alloc::vec::Vec;

use ozlrip_core::{Error, ErrorKind, Result};

use super::bit_reader::ForwardBitReader;
use crate::execute::streams::OwnedStream;

pub(super) fn decode_u32_node(
    buckets: &[u8],
    offset_bits: &[u8],
    bases: &[u64],
    bits: &[u8],
    output_len: usize,
) -> Result<OwnedStream> {
    if buckets.len().checked_mul(4) != Some(output_len) {
        return Err(Error::new(ErrorKind::InvalidGraph)
            .with_detail("partition output size does not match its buckets"));
    }
    let mut reader = ForwardBitReader::new(offset_bits);
    let mut output = Vec::new();
    output.try_reserve_exact(output_len).map_err(|_| {
        Error::new(ErrorKind::AllocationFailed).with_detail("partition allocation failed")
    })?;
    output.resize(output_len, 0);

    let mut base_table = [0u64; 256];
    let mut bit_table = [u8::MAX; 256];
    for (bucket, (&base, &bit_width)) in bases.iter().zip(bits).enumerate() {
        base_table[bucket] = base;
        bit_table[bucket] = bit_width;
    }

    for (out, &bucket) in output.as_chunks_mut::<4>().0.iter_mut().zip(buckets) {
        let bucket = usize::from(bucket);
        let bit_width = bit_table[bucket];
        if bit_width == u8::MAX {
            return Err(
                Error::new(ErrorKind::Malformed).with_detail("partition bucket is out of range")
            );
        }
        let base = base_table[bucket];
        let offset = reader.read_u64(usize::from(bit_width))?;
        let value = base
            .checked_add(offset)
            .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
        let value = u32::try_from(value).map_err(|_| {
            Error::new(ErrorKind::Malformed)
                .with_detail("partition value exceeds output element width")
        })?;
        *out = value.to_le_bytes();
    }

    Ok(OwnedStream {
        bytes: output,
        element_width: 4,
        string_lengths: None,
        recyclable: false,
    })
}
