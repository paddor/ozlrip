use alloc::vec::Vec;

use ozlrip_core::{Error, ErrorKind, FrameValueType, Limits, Result};

use crate::parse::FramePlan;

pub(crate) fn decode_plan(
    input: &[u8],
    plan: &FramePlan,
    dst: &mut Vec<u8>,
    limits: Limits,
) -> Result<usize> {
    if plan.info.dictionary_bundle_id.is_some() {
        return Err(Error::new(ErrorKind::Unsupported)
            .with_detail("dictionary bundle materialization is not implemented"));
    }
    let stored = collect_stored_output(input, plan, limits)?;
    dst.try_reserve_exact(stored.total_len).map_err(|_| {
        Error::new(ErrorKind::LimitExceeded).with_detail("output allocation failed")
    })?;
    for stream in stored.streams {
        dst.extend_from_slice(stream);
    }
    Ok(stored.total_len)
}

fn collect_stored_output<'a>(
    input: &'a [u8],
    plan: &FramePlan,
    limits: Limits,
) -> Result<StoredOutput<'a>> {
    if plan.info.output_types.as_slice() != [FrameValueType::Serial] {
        return Err(Error::new(ErrorKind::Unsupported)
            .with_detail("only single serial stored-output frames are implemented"));
    }

    let mut streams = Vec::new();
    streams.try_reserve_exact(plan.chunks.len()).map_err(|_| {
        Error::new(ErrorKind::LimitExceeded).with_detail("stored output list allocation failed")
    })?;
    let mut total_len = 0usize;
    for chunk in &plan.chunks {
        if chunk.has_nodes() {
            return Err(Error::new(ErrorKind::Unsupported)
                .with_detail("transform graph execution is not implemented yet"));
        }
        let Some(range) = chunk.stored_stream_range(0) else {
            return Err(Error::new(ErrorKind::Unsupported)
                .with_detail("stored-output chunk does not contain one stored stream"));
        };
        if chunk.stored_stream_range(1).is_some() {
            return Err(Error::new(ErrorKind::Unsupported)
                .with_detail("stored-output chunk contains multiple stored streams"));
        }
        let stored = range.as_slice(input)?;
        total_len = total_len
            .checked_add(stored.len())
            .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
        #[cfg(not(feature = "checksum"))]
        let _ = chunk.decoded_checksum;
        #[cfg(feature = "checksum")]
        verify_decoded_checksum(stored, chunk.decoded_checksum)?;
        streams.push(stored);
    }
    check_output_size(total_len, input.len(), plan, limits)?;
    Ok(StoredOutput { streams, total_len })
}

struct StoredOutput<'a> {
    streams: Vec<&'a [u8]>,
    total_len: usize,
}

fn check_output_size(
    size: usize,
    encoded_size: usize,
    plan: &FramePlan,
    limits: Limits,
) -> Result<()> {
    if size > limits.max_decoded_bytes || size > limits.max_buffer_bytes {
        return Err(
            Error::new(ErrorKind::LimitExceeded).with_detail("decoded output limit exceeded")
        );
    }
    let max_expanded = encoded_size
        .checked_mul(limits.max_expansion_ratio)
        .ok_or_else(|| {
            Error::new(ErrorKind::IntegerOverflow)
                .with_detail("encoded size expansion limit overflowed")
        })?;
    if size > max_expanded {
        return Err(
            Error::new(ErrorKind::LimitExceeded).with_detail("decoded expansion ratio exceeded")
        );
    }
    if let Some(expected) = plan.info.output_sizes.first().and_then(|size| *size) {
        let expected = usize::try_from(expected).map_err(|_| {
            Error::new(ErrorKind::LimitExceeded).with_detail("decoded output size is too large")
        })?;
        if expected != size {
            return Err(Error::new(ErrorKind::Malformed)
                .with_detail("stored output size does not match frame header"));
        }
    }
    Ok(())
}

#[cfg(feature = "checksum")]
fn verify_decoded_checksum(output: &[u8], expected: Option<u32>) -> Result<()> {
    if let Some(expected) = expected {
        let actual = (xxhash_rust::xxh3::xxh3_64(output) & 0xffff_ffff) as u32;
        if actual != expected {
            return Err(Error::new(ErrorKind::ChecksumMismatch)
                .with_detail("OpenZL decoded checksum mismatch"));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse::parse_frame_plan;
    use alloc::vec;

    const MAGIC_BASE: u32 = 0xd7b1_a5c0;

    fn magic(version: u32) -> [u8; 4] {
        (MAGIC_BASE + version).to_le_bytes()
    }

    #[test]
    fn decodes_v21_stored_serial_output() {
        let mut input = Vec::new();
        input.extend_from_slice(&magic(21));
        input.push(0);
        input.push(1);
        input.push(4);
        input.push(1);
        input.push(1);
        input.push(3);
        input.extend_from_slice(&[7, 8, 9]);
        input.push(0);
        let plan = parse_frame_plan(&input, Limits::default()).unwrap();
        let mut output = Vec::new();

        let written = decode_plan(&input, &plan, &mut output, Limits::default()).unwrap();

        assert_eq!(written, 3);
        assert_eq!(output, [7, 8, 9]);
    }

    #[test]
    fn decodes_empty_v21_stored_serial_output() {
        let mut input = Vec::new();
        input.extend_from_slice(&magic(21));
        input.push(0);
        input.push(1);
        input.push(1);
        input.push(0);
        let plan = parse_frame_plan(&input, Limits::default()).unwrap();
        let mut output = vec![1, 2];

        let written = decode_plan(&input, &plan, &mut output, Limits::default()).unwrap();

        assert_eq!(written, 0);
        assert_eq!(output, [1, 2]);
    }

    #[test]
    fn decodes_v21_stored_serial_chunks() {
        let mut input = Vec::new();
        input.extend_from_slice(&magic(21));
        input.push(0);
        input.push(1);
        input.push(8);
        input.push(1);
        input.push(1);
        input.push(3);
        input.extend_from_slice(&[7, 8, 9]);
        input.push(1);
        input.push(1);
        input.push(4);
        input.extend_from_slice(&[10, 11, 12, 13]);
        input.push(0);
        let plan = parse_frame_plan(&input, Limits::default()).unwrap();
        let mut output = Vec::new();

        let written = decode_plan(&input, &plan, &mut output, Limits::default()).unwrap();

        assert_eq!(written, 7);
        assert_eq!(output, [7, 8, 9, 10, 11, 12, 13]);
    }

    #[test]
    fn rejects_size_mismatch_without_mutating_destination() {
        let mut input = Vec::new();
        input.extend_from_slice(&magic(21));
        input.push(0);
        input.push(1);
        input.push(5);
        input.push(1);
        input.push(1);
        input.push(3);
        input.extend_from_slice(&[7, 8, 9]);
        input.push(0);
        let plan = parse_frame_plan(&input, Limits::default()).unwrap();
        let mut output = vec![1, 2];

        let err = decode_plan(&input, &plan, &mut output, Limits::default()).unwrap_err();

        assert_eq!(err.kind(), ErrorKind::Malformed);
        assert_eq!(output, [1, 2]);
    }

    #[test]
    fn enforces_expansion_ratio_without_mutating_destination() {
        let mut input = Vec::new();
        input.extend_from_slice(&magic(21));
        input.push(0);
        input.push(1);
        input.push(4);
        input.push(1);
        input.push(1);
        input.push(3);
        input.extend_from_slice(&[7, 8, 9]);
        input.push(0);
        let plan = parse_frame_plan(&input, Limits::default()).unwrap();
        let mut output = vec![1, 2];
        let limits = Limits {
            max_expansion_ratio: 0,
            ..Limits::default()
        };

        let err = decode_plan(&input, &plan, &mut output, limits).unwrap_err();

        assert_eq!(err.kind(), ErrorKind::LimitExceeded);
        assert_eq!(output, [1, 2]);
    }

    #[cfg(feature = "checksum")]
    #[test]
    fn verifies_decoded_checksum() {
        let mut input = Vec::new();
        input.extend_from_slice(&magic(21));
        input.push(1);
        input.push(1);
        input.push(4);
        input.push(1);
        input.push(1);
        input.push(3);
        input.extend_from_slice(&[7, 8, 9]);
        let checksum = (xxhash_rust::xxh3::xxh3_64(&[7, 8, 9]) & 0xffff_ffff) as u32;
        input.extend_from_slice(&checksum.to_le_bytes());
        input.push(0);
        let plan = parse_frame_plan(&input, Limits::default()).unwrap();
        let mut output = Vec::new();

        let written = decode_plan(&input, &plan, &mut output, Limits::default()).unwrap();

        assert_eq!(written, 3);
        assert_eq!(output, [7, 8, 9]);
    }

    #[cfg(feature = "checksum")]
    #[test]
    fn rejects_decoded_checksum_mismatch_without_mutating_destination() {
        let mut input = Vec::new();
        input.extend_from_slice(&magic(21));
        input.push(1);
        input.push(1);
        input.push(4);
        input.push(1);
        input.push(1);
        input.push(3);
        input.extend_from_slice(&[7, 8, 9]);
        input.extend_from_slice(&0u32.to_le_bytes());
        input.push(0);
        let plan = parse_frame_plan(&input, Limits::default()).unwrap();
        let mut output = vec![1, 2];

        let err = decode_plan(&input, &plan, &mut output, Limits::default()).unwrap_err();

        assert_eq!(err.kind(), ErrorKind::ChecksumMismatch);
        assert_eq!(output, [1, 2]);
    }

    #[cfg(feature = "checksum")]
    #[test]
    fn verifies_compressed_checksum() {
        let mut input = Vec::new();
        input.extend_from_slice(&magic(21));
        input.push(1 << 1);
        input.push(1);
        input.push(4);
        let header_checksum = (xxhash_rust::xxh3::xxh3_64(&input) & 0xff) as u8;
        input.push(header_checksum);
        let chunk_start = input.len();
        input.push(1);
        input.push(1);
        input.push(3);
        input.extend_from_slice(&[7, 8, 9]);
        let checksum = (xxhash_rust::xxh3::xxh3_64(&input[chunk_start..]) & 0xffff_ffff) as u32;
        input.extend_from_slice(&checksum.to_le_bytes());
        input.push(0);
        let plan = parse_frame_plan(&input, Limits::default()).unwrap();
        let mut output = Vec::new();

        let written = decode_plan(&input, &plan, &mut output, Limits::default()).unwrap();

        assert_eq!(written, 3);
        assert_eq!(output, [7, 8, 9]);
    }

    #[cfg(feature = "checksum")]
    #[test]
    fn rejects_compressed_checksum_mismatch() {
        let mut input = Vec::new();
        input.extend_from_slice(&magic(21));
        input.push(1 << 1);
        input.push(1);
        input.push(4);
        let header_checksum = (xxhash_rust::xxh3::xxh3_64(&input) & 0xff) as u8;
        input.push(header_checksum);
        input.push(1);
        input.push(1);
        input.push(3);
        input.extend_from_slice(&[7, 8, 9]);
        input.extend_from_slice(&0u32.to_le_bytes());
        input.push(0);

        let err = parse_frame_plan(&input, Limits::default()).unwrap_err();

        assert_eq!(err.kind(), ErrorKind::ChecksumMismatch);
    }
}
