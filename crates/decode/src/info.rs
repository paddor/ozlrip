use alloc::vec::Vec;

/// Frame metadata returned by [`crate::inspect`].
///
/// New fields may be added in minor releases.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct FrameInfo {
    /// OpenZL wire format version.
    pub format_version: u32,
    /// Size of the whole frame.
    pub frame_bytes: usize,
    /// Size of the frame header.
    pub header_bytes: usize,
    /// Total decoded size, when every output is serial with a known size.
    pub decoded_bytes: Option<usize>,
    /// Number of chunks.
    pub chunks: usize,
    /// Number of frame outputs.
    pub outputs: usize,
    /// Type of each output.
    pub output_types: Vec<FrameValueType>,
    /// Decoded byte size of each output, when the header states it.
    pub output_sizes: Vec<Option<u64>>,
    /// Element count of each output, when the header states it.
    pub output_elements: Vec<Option<u64>>,
    /// Transform nodes across all chunks.
    pub transforms: usize,
    /// Stored streams across all chunks.
    pub stored_streams: usize,
    /// Regenerated streams across all chunks.
    pub regenerated_streams: usize,
    /// Chunks carry a checksum of their decoded content.
    pub has_decoded_checksum: bool,
    /// The frame carries checksums of its encoded bytes.
    pub has_encoded_checksum: bool,
    /// The frame carries a comment.
    pub has_comment: bool,
    /// Comment bytes, if any.
    pub comment: Option<Vec<u8>>,
    /// Dictionary bundle the frame needs, if any.
    pub dictionary_bundle_id: Option<Vec<u8>>,
}

/// Type of a frame output.
///
/// New types may be added in minor releases.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum FrameValueType {
    /// Plain bytes.
    Serial,
    /// Fixed-width records.
    Struct,
    /// Little-endian integers of width 1, 2, 4 or 8.
    Numeric,
    /// Variable-length strings with a length per element.
    String,
}
