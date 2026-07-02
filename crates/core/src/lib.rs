#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(feature = "paranoid", forbid(unsafe_code))]

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

pub type Result<T> = core::result::Result<T, Error>;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Error {
    kind: ErrorKind,
    offset: Option<usize>,
    detail: Option<String>,
}

impl Error {
    pub const fn new(kind: ErrorKind) -> Self {
        Self {
            kind,
            offset: None,
            detail: None,
        }
    }

    pub const fn at(kind: ErrorKind, offset: usize) -> Self {
        Self {
            kind,
            offset: Some(offset),
            detail: None,
        }
    }

    #[must_use]
    pub fn with_detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = Some(detail.into());
        self
    }

    pub const fn kind(&self) -> ErrorKind {
        self.kind
    }

    pub const fn offset(&self) -> Option<usize> {
        self.offset
    }

    pub fn detail(&self) -> Option<&str> {
        self.detail.as_deref()
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self.kind)?;
        if let Some(offset) = self.offset {
            write!(f, " at byte {offset}")?;
        }
        if let Some(detail) = &self.detail {
            write!(f, ": {detail}")?;
        }
        Ok(())
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ErrorKind {
    Truncated,
    Malformed,
    Unsupported,
    LimitExceeded,
    ChecksumMismatch,
    InvalidGraph,
    InvalidType,
    IntegerOverflow,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Limits {
    pub max_frame_bytes: usize,
    pub max_decoded_bytes: usize,
    pub max_chunks: usize,
    pub max_nodes: usize,
    pub max_streams: usize,
    pub max_transform_header_bytes: usize,
    pub max_stored_stream_bytes: usize,
    pub max_buffer_bytes: usize,
    pub max_graph_depth: usize,
    pub max_expansion_ratio: usize,
}

impl Limits {
    pub const fn strict() -> Self {
        Self {
            max_frame_bytes: 64 * 1024 * 1024,
            max_decoded_bytes: 64 * 1024 * 1024,
            max_chunks: 16_384,
            max_nodes: 65_536,
            max_streams: 131_072,
            max_transform_header_bytes: 16 * 1024 * 1024,
            max_stored_stream_bytes: 64 * 1024 * 1024,
            max_buffer_bytes: 64 * 1024 * 1024,
            max_graph_depth: 1024,
            max_expansion_ratio: 256,
        }
    }

    pub const fn paranoid() -> Self {
        Self {
            max_frame_bytes: 16 * 1024 * 1024,
            max_decoded_bytes: 16 * 1024 * 1024,
            max_chunks: 4096,
            max_nodes: 16_384,
            max_streams: 32_768,
            max_transform_header_bytes: 4 * 1024 * 1024,
            max_stored_stream_bytes: 16 * 1024 * 1024,
            max_buffer_bytes: 16 * 1024 * 1024,
            max_graph_depth: 256,
            max_expansion_ratio: 64,
        }
    }
}

impl Default for Limits {
    fn default() -> Self {
        if cfg!(feature = "paranoid") {
            Self::paranoid()
        } else {
            Self::strict()
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FrameInfo {
    pub format_version: u32,
    pub frame_bytes: usize,
    pub header_bytes: usize,
    pub decoded_bytes: Option<usize>,
    pub chunks: usize,
    pub inputs: usize,
    pub output_types: Vec<FrameValueType>,
    pub output_sizes: Vec<Option<u64>>,
    pub output_elements: Vec<Option<u64>>,
    pub transforms: usize,
    pub stored_streams: usize,
    pub regenerated_streams: usize,
    pub has_decoded_checksum: bool,
    pub has_encoded_checksum: bool,
    pub has_comment: bool,
    pub dictionary_bundle_id: Option<Vec<u8>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FrameValueType {
    Serial,
    Struct,
    Numeric,
    String,
}
