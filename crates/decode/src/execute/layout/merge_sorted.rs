//! The `merge_sorted` node, from its bitset and merged streams.

use alloc::vec;
use alloc::vec::Vec;

use ozlrip_core::{Error, ErrorKind, Limits, Result};

use crate::execute::elements::{
    numeric_element_count, read_numeric_element, read_u32_element, read_var_u64,
    validate_numeric_stream_width,
};
use crate::execute::output::check_output_len;
use crate::execute::streams::{OwnedStream, StreamInput};

pub(in crate::execute) fn decode_merge_sorted_node(
    inputs: &[StreamInput<'_>],
    header: &[u8],
    limits: Limits,
) -> Result<OwnedStream> {
    let [bitset, merged] = inputs else {
        return Err(Error::new(ErrorKind::InvalidGraph)
            .with_detail("merge_sorted input count does not match node shape"));
    };
    if bitset.string_lengths.is_some() || merged.string_lengths.is_some() {
        return Err(Error::new(ErrorKind::InvalidType)
            .with_detail("merge_sorted inputs must not be string streams"));
    }
    validate_numeric_stream_width(bitset.element_width, "merge_sorted bitset")?;
    if merged.element_width != 4 {
        return Err(Error::new(ErrorKind::InvalidType)
            .with_detail("merge_sorted merged stream width must be 4"));
    }

    let merged_elements = numeric_element_count(merged.bytes, merged.element_width)?;
    if numeric_element_count(bitset.bytes, bitset.element_width)? != merged_elements {
        return Err(Error::new(ErrorKind::Malformed)
            .with_detail("merge_sorted streams have different element counts"));
    }

    let sizes = read_merge_sorted_sizes(header)?;
    let output_len =
        merge_sorted_output_len(bitset.element_width, merged_elements, &sizes, limits)?;
    let starts = merge_sorted_run_starts(&sizes)?;

    let mut output = vec![0u8; output_len];
    let mut written = Vec::new();
    written.try_reserve_exact(sizes.len()).map_err(|_| {
        Error::new(ErrorKind::AllocationFailed).with_detail("merge_sorted count allocation failed")
    })?;
    written.resize(sizes.len(), 0usize);

    for value_index in 0..merged_elements {
        let bitset_word = read_numeric_element(bitset.bytes, bitset.element_width, value_index)?;
        let value = read_u32_element(merged.bytes, value_index)?.to_le_bytes();
        for run_index in 0..sizes.len() {
            if written[run_index] == sizes[run_index] || bitset_word & (1u64 << run_index) == 0 {
                continue;
            }
            let element_index = starts[run_index]
                .checked_add(written[run_index])
                .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
            let byte_index = element_index
                .checked_mul(4)
                .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
            output[byte_index..byte_index + 4].copy_from_slice(&value);
            written[run_index] = written[run_index]
                .checked_add(1)
                .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
        }
    }

    if written != sizes {
        return Err(Error::new(ErrorKind::Malformed)
            .with_detail("merge_sorted bitsets do not fill output runs"));
    }
    Ok(OwnedStream::typed(output, 4))
}

/// Output size of a merge_sorted node, after checking that the runs fit
/// the bitset width and the merged element count.
fn merge_sorted_output_len(
    bitset_width: usize,
    merged_elements: usize,
    sizes: &[usize],
    limits: Limits,
) -> Result<usize> {
    let max_runs = bitset_width
        .checked_mul(8)
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
    if sizes.len() > max_runs {
        return Err(Error::new(ErrorKind::Malformed)
            .with_detail("merge_sorted has too many output runs for bitset width"));
    }
    let max_output_elements = max_runs
        .checked_mul(merged_elements)
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
    let output_elements = sizes.iter().try_fold(0usize, |sum, &size| {
        sum.checked_add(size)
            .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))
    })?;
    if output_elements > max_output_elements {
        return Err(Error::new(ErrorKind::Malformed)
            .with_detail("merge_sorted output count exceeds bitset capacity"));
    }
    let output_len = output_elements
        .checked_mul(4)
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
    check_output_len(output_len, limits)?;
    Ok(output_len)
}

/// First output element of each merge_sorted run.
fn merge_sorted_run_starts(sizes: &[usize]) -> Result<Vec<usize>> {
    let mut starts = Vec::new();
    starts.try_reserve_exact(sizes.len()).map_err(|_| {
        Error::new(ErrorKind::AllocationFailed).with_detail("merge_sorted run allocation failed")
    })?;
    let mut cursor = 0usize;
    for &size in sizes {
        starts.push(cursor);
        cursor = cursor
            .checked_add(size)
            .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
    }
    Ok(starts)
}

fn read_merge_sorted_sizes(header: &[u8]) -> Result<Vec<usize>> {
    let mut sizes = Vec::new();
    let mut offset = 0usize;
    while offset < header.len() {
        if sizes.len() == 64 {
            return Err(Error::new(ErrorKind::Malformed)
                .with_detail("merge_sorted has too many output runs"));
        }
        let size = read_var_u64(header, &mut offset)?;
        let size = usize::try_from(size).map_err(|_| {
            Error::new(ErrorKind::LimitExceeded).with_detail("merge_sorted run size is too large")
        })?;
        sizes.push(size);
    }
    Ok(sizes)
}
