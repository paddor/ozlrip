use crate::standard;
use ozlrip_core::{Error, ErrorKind, Limits, Result};

#[cfg(feature = "checksum")]
use super::chunk::verify_compressed_checksum;
use super::chunk::{read_count, read_transform_count, standard_transform_id_bits};
#[cfg(feature = "checksum")]
use super::header::verify_header_checksum;
use super::header::{FrameFlags, format_version_from_magic, runtime_input_limit};
use super::reader::{Reader, bits_needed, check_limit, read_single_low_bits_u32};
use super::{ByteRange, CHUNK_VERSION_MIN};

pub(crate) fn parse_single_zstd_frame(
    input: &[u8],
    limits: Limits,
) -> Result<Option<SingleZstdFrame>> {
    check_limit(
        input.len(),
        limits.max_frame_bytes,
        ErrorKind::LimitExceeded,
    )?;

    let mut reader = Reader::new(input);
    let magic = reader.read_u32_le()?;
    let format_version = format_version_from_magic(magic)?;
    if format_version < CHUNK_VERSION_MIN {
        return Ok(None);
    }

    let flags = FrameFlags::from_byte(reader.read_byte()?, format_version);
    if flags.has_bundle_id() || flags.has_comment() {
        return Ok(None);
    }

    let output_token = reader.read_byte()?;
    let outputs = usize::from(output_token & 0x0f);
    if outputs != 1 || ((output_token >> 4) & 3) != 0 {
        return Ok(None);
    }
    check_limit(
        outputs,
        runtime_input_limit(format_version),
        ErrorKind::Malformed,
    )?;
    check_limit(outputs, limits.max_streams, ErrorKind::LimitExceeded)?;
    let first_size = reader.peek_byte()?;
    let decoded_bytes = if first_size == 0 {
        return Err(Error::at(ErrorKind::Unsupported, reader.offset())
            .with_detail("unknown OpenZL output sizes are unsupported"));
    } else {
        let encoded = reader.read_var_u64()?;
        let size = encoded
            .checked_sub(1)
            .ok_or_else(|| Error::at(ErrorKind::IntegerOverflow, reader.offset()))?;
        let size_usize = usize::try_from(size)
            .map_err(|_| Error::at(ErrorKind::LimitExceeded, reader.offset()))?;
        check_limit(
            size_usize,
            limits.max_buffer_bytes,
            ErrorKind::LimitExceeded,
        )?;
        check_limit(
            size_usize,
            limits.max_decoded_bytes,
            ErrorKind::LimitExceeded,
        )?;
        Some(size_usize)
    };

    if flags.has_encoded_checksum() {
        let checksum_offset = reader.offset();
        let expected = reader.read_byte()?;
        #[cfg(not(feature = "checksum"))]
        let _ = (checksum_offset, expected);
        #[cfg(feature = "checksum")]
        verify_header_checksum(&input[..checksum_offset], expected, checksum_offset)?;
    }

    if reader.peek_byte()? == 0 {
        return Ok(None);
    }
    let chunk_start = reader.offset();
    let transforms = read_transform_count(&mut reader, format_version)?;
    let stored_streams_u64 = read_count(&mut reader, format_version)?;
    let stored_streams = usize::try_from(stored_streams_u64)
        .map_err(|_| Error::at(ErrorKind::LimitExceeded, reader.offset()))?;
    if transforms != 1 || stored_streams != 1 {
        return Ok(None);
    }
    check_limit(transforms, limits.max_nodes, ErrorKind::LimitExceeded)?;
    check_limit(stored_streams, limits.max_streams, ErrorKind::LimitExceeded)?;
    check_limit(1, limits.max_chunks, ErrorKind::LimitExceeded)?;
    check_limit(1, limits.max_graph_depth, ErrorKind::LimitExceeded)?;

    if read_single_low_bits_u32(&mut reader, 1)? != 0 {
        return Ok(None);
    }
    let transform_id =
        read_single_low_bits_u32(&mut reader, standard_transform_id_bits(format_version))?;
    if transform_id != standard::ZSTD_ID {
        return Ok(None);
    }
    standard::validate_transform_id(transform_id, format_version)?;
    if read_single_low_bits_u32(&mut reader, 1)? != 0
        || read_single_low_bits_u32(&mut reader, 1)? != 0
    {
        return Ok(None);
    }
    if format_version >= 16 && read_single_low_bits_u32(&mut reader, 1)? != 0 {
        return Ok(None);
    }
    let distance_bits = bits_needed(2);
    if read_single_low_bits_u32(&mut reader, distance_bits)? != 0 {
        return Ok(None);
    }
    let stored_stream_size = reader.read_var_u64()?;
    let stored_stream_size = usize::try_from(stored_stream_size)
        .map_err(|_| Error::at(ErrorKind::LimitExceeded, reader.offset()))?;
    check_limit(
        stored_stream_size,
        limits.max_buffer_bytes,
        ErrorKind::LimitExceeded,
    )?;
    check_limit(
        stored_stream_size,
        limits.max_stored_stream_bytes,
        ErrorKind::LimitExceeded,
    )?;
    let payload_start = reader.offset();
    let stored = ByteRange {
        start: payload_start,
        len: stored_stream_size,
    };
    let _ = reader.read_slice(stored_stream_size)?;

    let decoded_checksum = if flags.has_decoded_checksum() {
        Some(reader.read_u32_le()?)
    } else {
        None
    };
    if flags.has_encoded_checksum() {
        let checksum_offset = reader.offset();
        let encoded_checksum = Some(reader.read_u32_le()?);
        #[cfg(not(feature = "checksum"))]
        let _ = (chunk_start, checksum_offset, encoded_checksum);
        #[cfg(feature = "checksum")]
        verify_compressed_checksum(reader.bytes, chunk_start, checksum_offset, encoded_checksum)?;
    }
    if reader.read_byte()? != 0 || !reader.is_empty() {
        return Ok(None);
    }

    Ok(Some(SingleZstdFrame {
        stored,
        decoded_checksum,
        decoded_bytes,
        frame_bytes: input.len(),
    }))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct SingleZstdFrame {
    pub(crate) stored: ByteRange,
    pub(crate) decoded_checksum: Option<u32>,
    pub(crate) decoded_bytes: Option<usize>,
    pub(crate) frame_bytes: usize,
}
