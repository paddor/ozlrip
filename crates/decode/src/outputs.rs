use alloc::vec::Vec;

use crate::execute::DecodedOutput;
use crate::info::FrameValueType;

/// One decoded frame output, as [`crate::Decoder::decode_outputs`] returns
/// it.
///
/// New output types may be added in minor releases.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Output {
    /// Plain bytes.
    Serial(Vec<u8>),
    /// Records of `width` bytes each.
    Struct {
        /// Record width in bytes; 0 for an output that no chunk of the frame
        /// states, which is then empty.
        width: usize,
        /// The records, back to back.
        bytes: Vec<u8>,
    },
    /// Little-endian integers of `width` bytes each: 1, 2, 4 or 8.
    Numeric {
        /// Integer width in bytes; 0 for an output that no chunk of the frame
        /// states, which is then empty.
        width: usize,
        /// The integers, back to back.
        bytes: Vec<u8>,
    },
    /// Strings: their bytes back to back, and the length of each.
    String {
        /// The strings, back to back.
        bytes: Vec<u8>,
        /// The length of each string; they sum to `bytes.len()`.
        lengths: Vec<u32>,
    },
}

impl Output {
    /// The output's type.
    pub fn value_type(&self) -> FrameValueType {
        match self {
            Self::Serial(_) => FrameValueType::Serial,
            Self::Struct { .. } => FrameValueType::Struct,
            Self::Numeric { .. } => FrameValueType::Numeric,
            Self::String { .. } => FrameValueType::String,
        }
    }

    /// The output's content bytes.
    pub fn bytes(&self) -> &[u8] {
        match self {
            Self::Serial(bytes)
            | Self::Struct { bytes, .. }
            | Self::Numeric { bytes, .. }
            | Self::String { bytes, .. } => bytes,
        }
    }

    /// Hands the output's buffers to the decoder for reuse.
    pub(crate) fn into_decoded(self) -> DecodedOutput {
        let (bytes, lengths) = match self {
            Self::Serial(bytes) | Self::Struct { bytes, .. } | Self::Numeric { bytes, .. } => {
                (bytes, Vec::new())
            }
            Self::String { bytes, lengths } => (bytes, lengths),
        };
        DecodedOutput {
            bytes,
            lengths,
            ..DecodedOutput::default()
        }
    }

    pub(crate) fn from_decoded(decoded: DecodedOutput) -> Self {
        let DecodedOutput {
            value_type,
            width,
            bytes,
            lengths,
        } = decoded;
        match value_type {
            Some(FrameValueType::Struct) => Self::Struct { width, bytes },
            Some(FrameValueType::Numeric) => Self::Numeric { width, bytes },
            Some(FrameValueType::String) => Self::String { bytes, lengths },
            Some(FrameValueType::Serial) | None => Self::Serial(bytes),
        }
    }
}
