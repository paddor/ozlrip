//! Shared error and limit types for `ozlrip`.
//!
//! Use the `ozlrip` crate; it re-exports everything here.
#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(feature = "paranoid", forbid(unsafe_code))]

extern crate alloc;

use alloc::borrow::Cow;
use core::fmt;

/// Result type used by every `ozlrip` API.
pub type Result<T> = core::result::Result<T, Error>;

/// A decode or inspection failure.
///
/// [`Error::kind`] classifies the failure. [`Error::offset`] and
/// [`Error::detail`] add context when known; their contents are not part of
/// the stable API.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Error {
    kind: ErrorKind,
    offset: Option<usize>,
    detail: Option<Cow<'static, str>>,
}

impl Error {
    /// Creates an error without an offset or detail.
    pub const fn new(kind: ErrorKind) -> Self {
        Self {
            kind,
            offset: None,
            detail: None,
        }
    }

    /// Creates an error at a byte offset in the input frame.
    pub const fn at(kind: ErrorKind, offset: usize) -> Self {
        Self {
            kind,
            offset: Some(offset),
            detail: None,
        }
    }

    /// Attaches a human-readable detail. Static strings do not allocate.
    #[must_use]
    pub fn with_detail(mut self, detail: impl Into<Cow<'static, str>>) -> Self {
        self.detail = Some(detail.into());
        self
    }

    /// The failure class.
    pub const fn kind(&self) -> ErrorKind {
        self.kind
    }

    /// Byte offset in the input frame, if known.
    pub const fn offset(&self) -> Option<usize> {
        self.offset
    }

    /// Human-readable detail, if any.
    pub fn detail(&self) -> Option<&str> {
        self.detail.as_deref()
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.kind)?;
        if let Some(offset) = self.offset {
            write!(f, " at byte {offset}")?;
        }
        if let Some(detail) = &self.detail {
            write!(f, ": {detail}")?;
        }
        Ok(())
    }
}

impl core::error::Error for Error {}

/// Failure classes. New kinds may be added in minor releases.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ErrorKind {
    /// The input ended before a complete frame.
    Truncated,
    /// The input violates the OpenZL format.
    Malformed,
    /// The frame uses a feature this decoder does not implement.
    Unsupported,
    /// A configured [`Limits`] bound was exceeded, or allocation failed.
    LimitExceeded,
    /// A frame checksum did not match.
    ChecksumMismatch,
    /// The transform graph is inconsistent.
    InvalidGraph,
    /// A stream has the wrong type or element width.
    InvalidType,
    /// A size or offset computation overflowed.
    IntegerOverflow,
}

impl fmt::Display for ErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Truncated => "truncated input",
            Self::Malformed => "malformed input",
            Self::Unsupported => "unsupported feature",
            Self::LimitExceeded => "limit exceeded",
            Self::ChecksumMismatch => "checksum mismatch",
            Self::InvalidGraph => "invalid graph",
            Self::InvalidType => "invalid type",
            Self::IntegerOverflow => "integer overflow",
        })
    }
}

/// Defensive bounds for parsing and decoding untrusted frames.
///
/// Start from [`Limits::strict`], [`Limits::paranoid`] or
/// [`Limits::default`] and change fields as needed:
///
/// ```
/// let mut limits = ozlrip_core::Limits::strict();
/// limits.max_decoded_bytes = 1 << 20;
/// ```
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct Limits {
    /// Largest accepted input frame.
    pub max_frame_bytes: usize,
    /// Largest total decoded output.
    pub max_decoded_bytes: usize,
    /// Most chunks per frame.
    pub max_chunks: usize,
    /// Most transform nodes per chunk.
    pub max_nodes: usize,
    /// Most streams per chunk.
    pub max_streams: usize,
    /// Largest total transform header size per chunk.
    pub max_transform_header_bytes: usize,
    /// Largest stored stream.
    pub max_stored_stream_bytes: usize,
    /// Largest single intermediate or output buffer.
    pub max_buffer_bytes: usize,
    /// Most bytes all intermediate streams of one chunk may hold at once.
    ///
    /// String-heavy graphs hold about 3.5 times their chunk output (a
    /// wide CSV sample), so keep this well above `max_buffer_bytes`.
    pub max_live_bytes: usize,
    /// Deepest transform graph.
    pub max_graph_depth: usize,
    /// Most dictionaries all loaded dictionary bundles may hold.
    pub max_dictionaries: usize,
    /// Largest total size of all loaded dictionary bundles.
    pub max_dictionary_bytes: usize,
    /// Largest ratio of decoded bytes to frame bytes.
    pub max_expansion_ratio: usize,
}

impl Limits {
    /// Bounds suitable for general use: 64 MiB frames and outputs.
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
            max_live_bytes: 512 * 1024 * 1024,
            max_graph_depth: 1024,
            max_dictionaries: 1024,
            max_dictionary_bytes: 64 * 1024 * 1024,
            max_expansion_ratio: 256,
        }
    }

    /// Tighter bounds for hostile input: 16 MiB frames and outputs.
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
            max_live_bytes: 128 * 1024 * 1024,
            max_graph_depth: 256,
            max_dictionaries: 64,
            max_dictionary_bytes: 16 * 1024 * 1024,
            max_expansion_ratio: 64,
        }
    }
}

impl Default for Limits {
    /// Same as [`Limits::strict`], regardless of enabled features.
    fn default() -> Self {
        Self::strict()
    }
}
