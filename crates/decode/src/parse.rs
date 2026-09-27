use alloc::vec::Vec;

use ozlrip_core::{Error, ErrorKind, Limits, Result};

use crate::info::{FrameInfo, FrameValueType};
use smallvec::SmallVec;

mod chunk;
#[cfg(feature = "zstd")]
mod fast_zstd;
mod header;
mod reader;
mod validate;

use chunk::read_chunks;
#[cfg(feature = "zstd")]
pub(crate) use fast_zstd::{SingleZstdFrame, parse_single_zstd_frame};
#[cfg(feature = "checksum")]
use header::verify_header_checksum;
use header::{
    FrameFlags, format_version_from_magic, read_bundle_id, read_comment, read_output_header,
    read_output_sizes,
};
use reader::{Reader, check_limit, checked_add};
use validate::validate_frame_plan;

type ChunkPlans = SmallVec<[ChunkPlan; 1]>;
type NodePlans = SmallVec<[NodePlan; 2]>;
type RegenDistances = SmallVec<[u32; 1]>;
type StoredStreamSizes = SmallVec<[usize; 2]>;
type ByteRanges = SmallVec<[ByteRange; 2]>;
type OutputTypes = SmallVec<[FrameValueType; 2]>;
type OutputSizeValues = SmallVec<[Option<u64>; 2]>;

const MAGIC_BASE: u32 = 0xd7b1_a5c0;
const MIN_FORMAT_VERSION: u32 = 8;
const MAX_FORMAT_VERSION: u32 = 27;
const CHUNK_VERSION_MIN: u32 = 21;
const COMMENT_VERSION_MIN: u32 = 22;
const MATERIALIZED_DICT_VERSION_MIN: u32 = 25;
const UNIQUE_ID_BYTES: usize = 32;
const MAX_DICTS_PER_BUNDLE: u32 = 0xffff;
const MAX_HEADER_COMMENT_BYTES: u64 = 10_000;

pub(crate) fn inspect_frame(input: &[u8], limits: Limits) -> Result<FrameInfo> {
    Ok(parse_frame_plan(input, limits)?.info.into_public_info())
}

pub(crate) fn parse_frame_plan(input: &[u8], limits: Limits) -> Result<FramePlan> {
    check_limit(
        input.len(),
        limits.max_frame_bytes,
        ErrorKind::LimitExceeded,
    )?;

    let mut reader = Reader::new(input);
    let magic = reader.read_u32_le()?;
    let format_version = format_version_from_magic(magic)?;

    let mut flags = FrameFlags::default();
    if format_version >= CHUNK_VERSION_MIN {
        flags = FrameFlags::from_byte(reader.read_byte()?, format_version);
    }

    let dictionary_bundle_id = if flags.has_bundle_id() {
        Some(read_bundle_id(&mut reader)?)
    } else {
        None
    };

    let output_header = read_output_header(&mut reader, input, format_version, limits)?;
    let output_sizes = read_output_sizes(
        &mut reader,
        &output_header.output_types,
        format_version,
        limits,
    )?;

    let comment = if flags.has_comment() {
        Some(read_comment(&mut reader)?)
    } else {
        None
    };

    if format_version >= CHUNK_VERSION_MIN && flags.has_encoded_checksum() {
        let checksum_offset = reader.offset();
        let expected = reader.read_byte()?;
        #[cfg(not(feature = "checksum"))]
        let _ = (checksum_offset, expected);
        #[cfg(feature = "checksum")]
        verify_header_checksum(&input[..checksum_offset], expected, checksum_offset)?;
    }

    let header_bytes = reader.offset();
    let chunk_scan = read_chunks(
        &mut reader,
        format_version,
        flags,
        dictionary_bundle_id.is_some(),
        limits,
    )?;
    if !reader.is_empty() {
        return Err(Error::at(ErrorKind::Malformed, reader.offset())
            .with_detail("trailing bytes after OpenZL frame"));
    }

    let info = FramePlanInfo {
        format_version,
        frame_bytes: input.len(),
        header_bytes,
        decoded_bytes: output_sizes.decoded_bytes,
        chunks: chunk_scan.summary.chunks,
        outputs: output_header.outputs,
        output_types: output_header.output_types,
        output_sizes: output_sizes.sizes,
        output_elements: output_sizes.elements,
        transforms: chunk_scan.summary.transforms,
        stored_streams: chunk_scan.summary.stored_streams,
        regenerated_streams: chunk_scan.summary.regenerated_streams,
        has_decoded_checksum: chunk_scan.flags.has_decoded_checksum(),
        has_encoded_checksum: chunk_scan.flags.has_encoded_checksum(),
        has_comment: flags.has_comment(),
        comment,
        dictionary_bundle_id,
    };
    let plan = FramePlan {
        info,
        chunks: chunk_scan.chunks,
    };
    validate_frame_plan(&plan, limits)?;
    Ok(plan)
}

#[derive(Clone, Debug)]
pub(crate) struct FramePlan {
    pub(crate) info: FramePlanInfo,
    pub(crate) chunks: ChunkPlans,
}

#[derive(Clone, Debug)]
pub(crate) struct FramePlanInfo {
    pub(crate) format_version: u32,
    pub(crate) frame_bytes: usize,
    pub(crate) header_bytes: usize,
    pub(crate) decoded_bytes: Option<usize>,
    pub(crate) chunks: usize,
    pub(crate) outputs: usize,
    pub(crate) output_types: OutputTypes,
    pub(crate) output_sizes: OutputSizeValues,
    pub(crate) output_elements: OutputSizeValues,
    pub(crate) transforms: usize,
    pub(crate) stored_streams: usize,
    pub(crate) regenerated_streams: usize,
    pub(crate) has_decoded_checksum: bool,
    pub(crate) has_encoded_checksum: bool,
    pub(crate) has_comment: bool,
    pub(crate) comment: Option<Vec<u8>>,
    pub(crate) dictionary_bundle_id: Option<Vec<u8>>,
}

impl FramePlanInfo {
    fn into_public_info(self) -> FrameInfo {
        FrameInfo {
            format_version: self.format_version,
            frame_bytes: self.frame_bytes,
            header_bytes: self.header_bytes,
            decoded_bytes: self.decoded_bytes,
            chunks: self.chunks,
            outputs: self.outputs,
            output_types: self.output_types.into_vec(),
            output_sizes: self.output_sizes.into_vec(),
            output_elements: self.output_elements.into_vec(),
            transforms: self.transforms,
            stored_streams: self.stored_streams,
            regenerated_streams: self.regenerated_streams,
            has_decoded_checksum: self.has_decoded_checksum,
            has_encoded_checksum: self.has_encoded_checksum,
            has_comment: self.has_comment,
            comment: self.comment,
            dictionary_bundle_id: self.dictionary_bundle_id,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TransformType {
    Standard,
    Custom,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct NodePlan {
    transform_type: TransformType,
    transform_id: u32,
    transform_header_start: usize,
    transform_header_size: usize,
    variable_outputs: u32,
    regen_distances: RegenDistances,
    dict_index: Option<u32>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ChunkPlan {
    nodes: NodePlans,
    stored_stream_sizes: StoredStreamSizes,
    transform_header_bytes: usize,
    stored_stream_bytes: usize,
    transform_header_range: ByteRange,
    stored_stream_ranges: ByteRanges,
    pub(crate) decoded_checksum: Option<u32>,
    encoded_checksum: Option<u32>,
}

impl ChunkPlan {
    pub(crate) fn transforms(&self) -> usize {
        self.nodes.len()
    }

    pub(crate) fn has_nodes(&self) -> bool {
        !self.nodes.is_empty()
    }

    pub(crate) fn nodes(&self) -> &[NodePlan] {
        &self.nodes
    }

    pub(crate) fn stored_streams(&self) -> usize {
        self.stored_stream_sizes.len()
    }

    pub(crate) fn stored_stream_range(&self, index: usize) -> Option<ByteRange> {
        self.stored_stream_ranges.get(index).copied()
    }

    pub(crate) const fn transform_header_range(&self) -> ByteRange {
        self.transform_header_range
    }

    pub(crate) fn regenerated_streams(&self) -> usize {
        self.nodes
            .iter()
            .map(|node| node.regen_distances.len())
            .sum()
    }

    fn set_payload_start(&mut self, payload_start: usize) -> Result<()> {
        let transform_header_end = checked_add(payload_start, self.transform_header_bytes)?;
        self.transform_header_range = ByteRange {
            start: payload_start,
            len: self.transform_header_bytes,
        };

        let mut offset = transform_header_end;
        self.stored_stream_ranges.clear();
        self.stored_stream_ranges
            .try_reserve_exact(self.stored_stream_sizes.len())
            .map_err(|_| {
                Error::new(ErrorKind::LimitExceeded)
                    .with_detail("stored stream range allocation failed")
            })?;
        for &size in &self.stored_stream_sizes {
            self.stored_stream_ranges.push(ByteRange {
                start: offset,
                len: size,
            });
            offset = checked_add(offset, size)?;
        }
        Ok(())
    }
}

impl NodePlan {
    pub(crate) const fn standard_id(&self) -> Option<u32> {
        match self.transform_type {
            TransformType::Standard => Some(self.transform_id),
            TransformType::Custom => None,
        }
    }

    pub(crate) const fn variable_outputs(&self) -> u32 {
        self.variable_outputs
    }

    pub(crate) fn regen_distances(&self) -> &[u32] {
        &self.regen_distances
    }

    pub(crate) const fn transform_header_start(&self) -> usize {
        self.transform_header_start
    }

    pub(crate) const fn transform_header_size(&self) -> usize {
        self.transform_header_size
    }

    pub(crate) const fn dict_index(&self) -> Option<u32> {
        self.dict_index
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct ByteRange {
    start: usize,
    len: usize,
}

impl ByteRange {
    pub(crate) fn as_slice(self, input: &[u8]) -> Result<&[u8]> {
        let end = checked_add(self.start, self.len)?;
        input
            .get(self.start..end)
            .ok_or_else(|| Error::at(ErrorKind::Truncated, self.start))
    }
}

#[cfg(test)]
mod tests;
